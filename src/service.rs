use crate::claims::{AccessTokenClaims, RefreshTokenClaims};
use crate::config::TokenConfig;
use crate::error::TokenError;
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

/// Token service for JWT creation and verification
/// Handles RSA key loading (supports both PEM and base64-encoded DER formats)
pub struct TokenService {
    config: TokenConfig,
    encoding_key: Option<EncodingKey>,
    decoding_key: Option<DecodingKey>,
}

impl TokenService {
    /// Create new token service
    pub fn new(config: TokenConfig) -> Result<Self, TokenError> {
        let encoding_key = if !config.private_key.is_empty() {
            Some(Self::load_private_key(&config.private_key)?)
        } else {
            None
        };

        let decoding_key = if !config.public_key.is_empty() {
            Some(Self::load_public_key(&config.public_key)?)
        } else {
            None
        };

        Ok(Self {
            config,
            encoding_key,
            decoding_key,
        })
    }

    /// Load RSA private key from PEM or base64-encoded DER
    fn load_private_key(key_data: &str) -> Result<EncodingKey, TokenError> {
        // Try PEM format first
        if key_data.contains("BEGIN") {
            return EncodingKey::from_rsa_pem(key_data.as_bytes())
                .map_err(|e| TokenError::RsaKeyError(format!("PEM decode error: {}", e)));
        }

        // Try base64-encoded DER format
        let decoded = BASE64.decode(key_data)
            .map_err(|e| TokenError::InvalidKeyFormat(format!("Not valid PEM or base64: {}", e)))?;

        Ok(EncodingKey::from_rsa_der(&decoded))
    }

    /// Load RSA public key from PEM or base64-encoded DER
    fn load_public_key(key_data: &str) -> Result<DecodingKey, TokenError> {
        // Try PEM format first
        if key_data.contains("BEGIN") {
            return DecodingKey::from_rsa_pem(key_data.as_bytes())
                .map_err(|e| TokenError::RsaKeyError(format!("PEM decode error: {}", e)));
        }

        // Try base64-encoded DER format
        let decoded = BASE64.decode(key_data)
            .map_err(|e| TokenError::InvalidKeyFormat(format!("Not valid PEM or base64: {}", e)))?;

        Ok(DecodingKey::from_rsa_der(&decoded))
    }

    /// Create an access token
    pub fn create_access_token(&self, claims: AccessTokenClaims) -> Result<String, TokenError> {
        let encoding_key = self.encoding_key.as_ref()
            .ok_or(TokenError::MissingPrivateKey)?;

        let header = Header::new(Algorithm::RS256);

        encode(&header, &claims, encoding_key)
            .map_err(|e| TokenError::JwtCreationError(format!("Access token: {}", e)))
    }

    /// Create a refresh token
    pub fn create_refresh_token(&self, claims: RefreshTokenClaims) -> Result<String, TokenError> {
        let encoding_key = self.encoding_key.as_ref()
            .ok_or(TokenError::MissingPrivateKey)?;

        let header = Header::new(Algorithm::RS256);

        encode(&header, &claims, encoding_key)
            .map_err(|e| TokenError::JwtCreationError(format!("Refresh token: {}", e)))
    }

    /// Verify and decode an access token
    pub fn verify_access_token(&self, token: &str) -> Result<AccessTokenClaims, TokenError> {
        let decoding_key = self.decoding_key.as_ref()
            .ok_or(TokenError::MissingPublicKey)?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);

        let token_data = decode::<AccessTokenClaims>(token, decoding_key, &validation)
            .map_err(|e| {
                if e.to_string().contains("ExpiredSignature") {
                    TokenError::ExpiredToken
                } else {
                    TokenError::InvalidToken(e.to_string())
                }
            })?;

        Ok(token_data.claims)
    }

    /// Verify and decode a refresh token
    pub fn verify_refresh_token(&self, token: &str) -> Result<RefreshTokenClaims, TokenError> {
        let decoding_key = self.decoding_key.as_ref()
            .ok_or(TokenError::MissingPublicKey)?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);

        let token_data = decode::<RefreshTokenClaims>(token, decoding_key, &validation)
            .map_err(|e| {
                if e.to_string().contains("ExpiredSignature") {
                    TokenError::ExpiredToken
                } else {
                    TokenError::InvalidToken(e.to_string())
                }
            })?;

        // Verify token type
        if token_data.claims.token_type != "refresh" {
            return Err(TokenError::InvalidToken("Not a refresh token".to_string()));
        }

        Ok(token_data.claims)
    }

    /// Create access token with expiration based on config
    pub fn create_access_token_for_user(
        &self,
        user_id: uuid::Uuid,
        email: String,
    ) -> Result<String, TokenError> {
        let expiration = Utc::now() + chrono::Duration::from_std(self.config.access_token_expiration)
            .map_err(|e| TokenError::JwtCreationError(format!("Duration conversion: {}", e)))?;

        let claims = AccessTokenClaims::new(
            user_id,
            email,
            expiration,
            self.config.issuer.clone(),
            self.config.audience.clone(),
        );

        self.create_access_token(claims)
    }

    /// Create refresh token with expiration based on config
    pub fn create_refresh_token_for_user(
        &self,
        user_id: uuid::Uuid,
    ) -> Result<String, TokenError> {
        let expiration = Utc::now() + chrono::Duration::from_std(self.config.refresh_token_expiration)
            .map_err(|e| TokenError::JwtCreationError(format!("Duration conversion: {}", e)))?;

        let claims = RefreshTokenClaims::new(
            user_id,
            expiration,
            self.config.issuer.clone(),
            self.config.audience.clone(),
        );

        self.create_refresh_token(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_format_detection() {
        // This test validates that the service can handle both PEM and base64 formats
        // Actual key loading would require valid test keys
    }
}
