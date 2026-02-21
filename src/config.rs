use std::time::Duration;

/// Token service configuration
#[derive(Debug, Clone)]
pub struct TokenConfig {
    /// RSA private key for signing tokens (PEM or base64-encoded DER)
    pub private_key: String,

    /// RSA public key for verifying tokens (PEM or base64-encoded DER)
    pub public_key: String,

    /// Access token expiration duration (default: 15 minutes)
    pub access_token_expiration: Duration,

    /// Refresh token expiration duration (default: 7 days)
    pub refresh_token_expiration: Duration,

    /// JWT issuer (default: "pleme-auth")
    pub issuer: String,

    /// JWT audience (default: "pleme-api")
    pub audience: String,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            private_key: String::new(),
            public_key: String::new(),
            access_token_expiration: Duration::from_secs(15 * 60), // 15 minutes
            refresh_token_expiration: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
            issuer: "pleme-auth".to_string(),
            audience: "pleme-api".to_string(),
        }
    }
}
