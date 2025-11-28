//! Session management

use crate::types::AuthContext;

use alloc::collections::BTreeMap;
use alloc::string::String;
use core::sync::atomic::Ordering;

#[cfg(feature = "std")]
use std::sync::RwLock;

#[cfg(not(feature = "std"))]
use spin::RwLock;

/// Session manager for tracking authenticated sessions
pub struct SessionManager {
    /// Active sessions
    sessions: RwLock<BTreeMap<String, Session>>,
    /// Session timeout in seconds
    session_timeout: u64,
    /// Maximum session duration
    max_duration: u64,
}

struct Session {
    /// Authentication context
    auth_context: AuthContext,
    /// Session creation time
    created_at: u64,
    /// Last activity time
    last_activity: u64,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(session_timeout: u64, max_duration: u64) -> Self {
        Self {
            sessions: RwLock::new(BTreeMap::new()),
            session_timeout,
            max_duration,
        }
    }
    
    /// Create a new session
    pub fn create_session(&self, auth_context: &AuthContext) -> String {
        let now = current_timestamp();
        let session_id = generate_session_id();
        
        let session = Session {
            auth_context: auth_context.clone(),
            created_at: now,
            last_activity: now,
        };
        
        if let Ok(mut sessions) = self.sessions.write() {
            sessions.insert(session_id.clone(), session);
        }
        
        session_id
    }
    
    /// Get a session by ID
    pub fn get_session(&self, session_id: &str) -> Option<AuthContext> {
        let now = current_timestamp();
        
        let mut sessions = self.sessions.write().ok()?;
        
        if let Some(session) = sessions.get_mut(session_id) {
            // Check if expired
            if self.is_session_expired(session, now) {
                sessions.remove(session_id);
                return None;
            }
            
            // Update last activity
            session.last_activity = now;
            
            return Some(session.auth_context.clone());
        }
        
        None
    }
    
    /// Check if auth context is expired
    pub fn is_expired(&self, auth_context: &AuthContext) -> bool {
        let now = current_timestamp();
        now > auth_context.expires_at
    }
    
    /// Check if a session is expired
    fn is_session_expired(&self, session: &Session, now: u64) -> bool {
        // Check absolute expiry
        if now > session.auth_context.expires_at {
            return true;
        }
        
        // Check idle timeout
        if now - session.last_activity > self.session_timeout {
            return true;
        }
        
        // Check max duration
        if now - session.created_at > self.max_duration {
            return true;
        }
        
        false
    }
    
    /// Revoke a session
    pub fn revoke_session(&self, session_id: &str) {
        if let Ok(mut sessions) = self.sessions.write() {
            sessions.remove(session_id);
        }
    }
    
    /// Revoke all sessions for an identity
    pub fn revoke_identity_sessions(&self, identity_id: &str) {
        if let Ok(mut sessions) = self.sessions.write() {
            sessions.retain(|_, session| {
                session.auth_context.identity.id != identity_id
            });
        }
    }
    
    /// Clean up expired sessions
    pub fn cleanup(&self) {
        let now = current_timestamp();
        
        if let Ok(mut sessions) = self.sessions.write() {
            sessions.retain(|_, session| {
                !self.is_session_expired(session, now)
            });
        }
    }
    
    /// Get active session count
    pub fn active_count(&self) -> usize {
        self.sessions.read().map(|s| s.len()).unwrap_or(0)
    }
    
    /// Extend a session's lifetime
    pub fn extend_session(&self, session_id: &str) -> bool {
        let now = current_timestamp();
        
        if let Ok(mut sessions) = self.sessions.write() {
            if let Some(session) = sessions.get_mut(session_id) {
                session.last_activity = now;
                session.auth_context.expires_at = now + self.session_timeout;
                return true;
            }
        }
        
        false
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

fn generate_session_id() -> String {
    use crate::crypto::random_bytes;
    
    match random_bytes(32) {
        Ok(bytes) => hex::encode(bytes),
        Err(_) => {
            // Fallback: use timestamp + counter
            static COUNTER: core::sync::atomic::AtomicU64 = 
                core::sync::atomic::AtomicU64::new(0);
            
            let ts = current_timestamp();
            let count = COUNTER.fetch_add(1, Ordering::Relaxed);
            format!("session_{}_{}", ts, count)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuthMethod, Capability, Identity};
    
    fn test_auth_context() -> AuthContext {
        AuthContext {
            identity: Identity {
                id: "test_user".into(),
                public_key: None,
                chain_id: None,
            },
            capabilities: vec![Capability::SubmitOperation],
            expires_at: current_timestamp() + 3600,
            method: AuthMethod::ApiKey,
        }
    }
    
    #[test]
    fn test_create_session() {
        let manager = SessionManager::new(3600, 86400);
        let ctx = test_auth_context();
        
        let session_id = manager.create_session(&ctx);
        assert!(!session_id.is_empty());
        assert_eq!(manager.active_count(), 1);
    }
    
    #[test]
    fn test_get_session() {
        let manager = SessionManager::new(3600, 86400);
        let ctx = test_auth_context();
        
        let session_id = manager.create_session(&ctx);
        
        let retrieved = manager.get_session(&session_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().identity.id, ctx.identity.id);
    }
    
    #[test]
    fn test_revoke_session() {
        let manager = SessionManager::new(3600, 86400);
        let ctx = test_auth_context();
        
        let session_id = manager.create_session(&ctx);
        assert_eq!(manager.active_count(), 1);
        
        manager.revoke_session(&session_id);
        assert_eq!(manager.active_count(), 0);
        
        assert!(manager.get_session(&session_id).is_none());
    }
    
    #[test]
    fn test_nonexistent_session() {
        let manager = SessionManager::new(3600, 86400);
        assert!(manager.get_session("nonexistent").is_none());
    }
    
    #[test]
    fn test_extend_session() {
        let manager = SessionManager::new(3600, 86400);
        let ctx = test_auth_context();
        
        let session_id = manager.create_session(&ctx);
        
        assert!(manager.extend_session(&session_id));
        assert!(!manager.extend_session("nonexistent"));
    }
}
