//! Role-based authorization

use crate::error::{ShieldError, ShieldResult};
use crate::types::{AuthContext, Capability, Identity};

use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::string::String;

#[cfg(feature = "std")]
use std::sync::RwLock;

#[cfg(not(feature = "std"))]
use spin::RwLock;

/// Role-based authorizer with capability tokens
pub struct Authorizer {
    /// Identity -> Capabilities mapping
    permissions: RwLock<BTreeMap<String, BTreeSet<CapabilityEntry>>>,
    /// Role -> Capabilities mapping
    roles: BTreeMap<Role, Vec<Capability>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CapabilityEntry {
    capability: CapabilityType,
    granted_at: u64,
    expires_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CapabilityType {
    SubmitOperation,
    Vote,
    EmergencyRecovery,
    Configure,
    ReadSensitive,
    Admin,
}

impl From<Capability> for CapabilityType {
    fn from(cap: Capability) -> Self {
        match cap {
            Capability::SubmitOperation => Self::SubmitOperation,
            Capability::Vote => Self::Vote,
            Capability::EmergencyRecovery => Self::EmergencyRecovery,
            Capability::Configure => Self::Configure,
            Capability::ReadSensitive => Self::ReadSensitive,
            Capability::Admin => Self::Admin,
        }
    }
}

impl From<CapabilityType> for Capability {
    fn from(cap: CapabilityType) -> Self {
        match cap {
            CapabilityType::SubmitOperation => Self::SubmitOperation,
            CapabilityType::Vote => Self::Vote,
            CapabilityType::EmergencyRecovery => Self::EmergencyRecovery,
            CapabilityType::Configure => Self::Configure,
            CapabilityType::ReadSensitive => Self::ReadSensitive,
            CapabilityType::Admin => Self::Admin,
        }
    }
}

/// Predefined roles
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Regular user - can submit operations
    User,
    /// Validator - can vote on operations
    Validator,
    /// Operator - can configure and manage
    Operator,
    /// Admin - full access
    Admin,
}

impl Authorizer {
    /// Create a new authorizer
    pub fn new() -> Self {
        let mut roles = BTreeMap::new();
        
        // Define role permissions
        roles.insert(Role::User, vec![
            Capability::SubmitOperation,
        ]);
        
        roles.insert(Role::Validator, vec![
            Capability::SubmitOperation,
            Capability::Vote,
        ]);
        
        roles.insert(Role::Operator, vec![
            Capability::SubmitOperation,
            Capability::Vote,
            Capability::Configure,
            Capability::ReadSensitive,
        ]);
        
        roles.insert(Role::Admin, vec![
            Capability::SubmitOperation,
            Capability::Vote,
            Capability::EmergencyRecovery,
            Capability::Configure,
            Capability::ReadSensitive,
            Capability::Admin,
        ]);
        
        Self {
            permissions: RwLock::new(BTreeMap::new()),
            roles,
        }
    }
    
    /// Check if auth context has required capability
    pub fn check(
        &self,
        auth_context: &AuthContext,
        required: Capability,
    ) -> ShieldResult<()> {
        // Check capabilities from auth context
        if auth_context.capabilities.contains(&required) {
            return Ok(());
        }
        
        // Check explicit permissions
        if let Ok(permissions) = self.permissions.read() {
            if let Some(caps) = permissions.get(&auth_context.identity.id) {
                let now = current_timestamp();
                let required_type = CapabilityType::from(required.clone());
                
                for entry in caps {
                    if entry.capability == required_type {
                        // Check expiry
                        if let Some(expires) = entry.expires_at {
                            if now > expires {
                                continue; // Expired
                            }
                        }
                        return Ok(());
                    }
                }
            }
        }
        
        Err(ShieldError::AuthorizationDenied {
            required: format!("{:?}", required),
        })
    }
    
    /// Check multiple capabilities (all must be present)
    pub fn check_all(
        &self,
        auth_context: &AuthContext,
        required: &[Capability],
    ) -> ShieldResult<()> {
        for cap in required {
            self.check(auth_context, cap.clone())?;
        }
        Ok(())
    }
    
    /// Check any of the capabilities (at least one must be present)
    pub fn check_any(
        &self,
        auth_context: &AuthContext,
        required: &[Capability],
    ) -> ShieldResult<()> {
        for cap in required {
            if self.check(auth_context, cap.clone()).is_ok() {
                return Ok(());
            }
        }
        Err(ShieldError::AuthorizationDenied {
            required: format!("any of {:?}", required),
        })
    }
    
    /// Grant a capability to an identity
    pub fn grant(&self, identity: &Identity, capability: Capability) {
        self.grant_with_expiry(identity, capability, None);
    }
    
    /// Grant a capability with expiry
    pub fn grant_with_expiry(
        &self,
        identity: &Identity,
        capability: Capability,
        expires_at: Option<u64>,
    ) {
        if let Ok(mut permissions) = self.permissions.write() {
            let entry = CapabilityEntry {
                capability: CapabilityType::from(capability),
                granted_at: current_timestamp(),
                expires_at,
            };
            
            permissions
                .entry(identity.id.clone())
                .or_insert_with(BTreeSet::new)
                .insert(entry);
        }
    }
    
    /// Revoke a capability from an identity
    pub fn revoke(&self, identity: &Identity, capability: Capability) {
        if let Ok(mut permissions) = self.permissions.write() {
            if let Some(caps) = permissions.get_mut(&identity.id) {
                let cap_type = CapabilityType::from(capability);
                caps.retain(|e| e.capability != cap_type);
            }
        }
    }
    
    /// Revoke all capabilities from an identity
    pub fn revoke_all(&self, identity: &Identity) {
        if let Ok(mut permissions) = self.permissions.write() {
            permissions.remove(&identity.id);
        }
    }
    
    /// Assign a role to an identity
    pub fn assign_role(&self, identity: &Identity, role: Role) {
        if let Some(capabilities) = self.roles.get(&role) {
            for cap in capabilities {
                self.grant(identity, cap.clone());
            }
        }
    }
    
    /// List capabilities for an identity
    pub fn list_capabilities(&self, identity_id: &str) -> Vec<Capability> {
        let permissions = match self.permissions.read() {
            Ok(p) => p,
            Err(_) => return Vec::new(),
        };
        
        let now = current_timestamp();
        
        permissions
            .get(identity_id)
            .map(|caps| {
                caps.iter()
                    .filter(|e| e.expires_at.map(|exp| now <= exp).unwrap_or(true))
                    .map(|e| Capability::from(e.capability))
                    .collect()
            })
            .unwrap_or_default()
    }
    
    /// Clean up expired permissions
    pub fn cleanup_expired(&self) {
        if let Ok(mut permissions) = self.permissions.write() {
            let now = current_timestamp();
            
            for caps in permissions.values_mut() {
                caps.retain(|e| {
                    e.expires_at.map(|exp| now <= exp).unwrap_or(true)
                });
            }
            
            // Remove empty entries
            permissions.retain(|_, caps| !caps.is_empty());
        }
    }
}

impl Default for Authorizer {
    fn default() -> Self {
        Self::new()
    }
}

fn current_timestamp() -> u64 {
    #[cfg(feature = "std")]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
    
    #[cfg(not(feature = "std"))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn test_identity(id: &str) -> Identity {
        Identity {
            id: id.into(),
            public_key: None,
            chain_id: None,
        }
    }
    
    fn test_context(id: &str, caps: Vec<Capability>) -> AuthContext {
        AuthContext {
            identity: test_identity(id),
            capabilities: caps,
            expires_at: u64::MAX,
            method: crate::types::AuthMethod::ApiKey,
        }
    }
    
    #[test]
    fn test_check_context_capability() {
        let authorizer = Authorizer::new();
        
        let ctx = test_context("user1", vec![Capability::SubmitOperation]);
        
        assert!(authorizer.check(&ctx, Capability::SubmitOperation).is_ok());
        assert!(authorizer.check(&ctx, Capability::Vote).is_err());
    }
    
    #[test]
    fn test_grant_revoke() {
        let authorizer = Authorizer::new();
        let identity = test_identity("user1");
        let ctx = test_context("user1", vec![]);
        
        // Initially no Vote capability
        assert!(authorizer.check(&ctx, Capability::Vote).is_err());
        
        // Grant Vote
        authorizer.grant(&identity, Capability::Vote);
        assert!(authorizer.check(&ctx, Capability::Vote).is_ok());
        
        // Revoke Vote
        authorizer.revoke(&identity, Capability::Vote);
        assert!(authorizer.check(&ctx, Capability::Vote).is_err());
    }
    
    #[test]
    fn test_assign_role() {
        let authorizer = Authorizer::new();
        let identity = test_identity("validator1");
        let ctx = test_context("validator1", vec![]);
        
        // Assign Validator role
        authorizer.assign_role(&identity, Role::Validator);
        
        // Should have Validator capabilities
        assert!(authorizer.check(&ctx, Capability::SubmitOperation).is_ok());
        assert!(authorizer.check(&ctx, Capability::Vote).is_ok());
        
        // But not Admin capabilities
        assert!(authorizer.check(&ctx, Capability::Admin).is_err());
    }
    
    #[test]
    fn test_check_all() {
        let authorizer = Authorizer::new();
        let identity = test_identity("admin");
        
        authorizer.assign_role(&identity, Role::Admin);
        
        let ctx = test_context("admin", vec![]);
        
        assert!(authorizer.check_all(&ctx, &[
            Capability::Vote,
            Capability::Configure,
        ]).is_ok());
    }
    
    #[test]
    fn test_check_any() {
        let authorizer = Authorizer::new();
        let ctx = test_context("user1", vec![Capability::Vote]);
        
        assert!(authorizer.check_any(&ctx, &[
            Capability::Admin,
            Capability::Vote,
        ]).is_ok());
        
        assert!(authorizer.check_any(&ctx, &[
            Capability::Admin,
            Capability::Configure,
        ]).is_err());
    }
}
