use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Access token JWT claims
/// Contains user identity, permissions, and relationships for authorization
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessTokenClaims {
    /// Subject (user ID)
    pub sub: Uuid,

    /// User email
    pub email: String,

    /// Expiration time (unix timestamp)
    pub exp: i64,

    /// Issued at (unix timestamp)
    pub iat: i64,

    /// Issuer
    pub iss: String,

    /// Audience
    pub aud: String,

    /// User permissions (embedded from pleme-rbac)
    /// Format: ["admin:users:write", "product:123:read"]
    #[serde(default)]
    pub permissions: Vec<String>,

    /// User relationships (embedded from pleme-rbac)
    /// Format: {"organization": ["org-123", "org-456"], "product": ["prod-789"]}
    #[serde(default)]
    pub relationships: std::collections::HashMap<String, Vec<String>>,

    /// Product scope (for multi-product environments)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
}

impl AccessTokenClaims {
    /// Create new access token claims
    pub fn new(
        user_id: Uuid,
        email: String,
        expiration: DateTime<Utc>,
        issuer: String,
        audience: String,
    ) -> Self {
        Self {
            sub: user_id,
            email,
            exp: expiration.timestamp(),
            iat: Utc::now().timestamp(),
            iss: issuer,
            aud: audience,
            permissions: Vec::new(),
            relationships: std::collections::HashMap::new(),
            product: None,
        }
    }

    /// Add permissions to the token
    pub fn with_permissions(mut self, permissions: Vec<String>) -> Self {
        self.permissions = permissions;
        self
    }

    /// Add relationships to the token
    pub fn with_relationships(mut self, relationships: std::collections::HashMap<String, Vec<String>>) -> Self {
        self.relationships = relationships;
        self
    }

    /// Add product scope to the token
    pub fn with_product(mut self, product: String) -> Self {
        self.product = Some(product);
        self
    }
}

/// Refresh token JWT claims
/// Contains minimal information for token refresh
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RefreshTokenClaims {
    /// Subject (user ID)
    pub sub: Uuid,

    /// Token type (always "refresh")
    pub token_type: String,

    /// Expiration time (unix timestamp)
    pub exp: i64,

    /// Issued at (unix timestamp)
    pub iat: i64,

    /// Issuer
    pub iss: String,

    /// Audience
    pub aud: String,
}

impl RefreshTokenClaims {
    /// Create new refresh token claims
    pub fn new(
        user_id: Uuid,
        expiration: DateTime<Utc>,
        issuer: String,
        audience: String,
    ) -> Self {
        Self {
            sub: user_id,
            token_type: "refresh".to_string(),
            exp: expiration.timestamp(),
            iat: Utc::now().timestamp(),
            iss: issuer,
            aud: audience,
        }
    }
}
