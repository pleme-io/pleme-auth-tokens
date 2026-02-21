use thiserror::Error;

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Falha ao criar token JWT: {0}")]
    JwtCreationError(String),

    #[error("Falha ao decodificar token JWT: {0}")]
    JwtDecodingError(String),

    #[error("Token JWT inválido: {0}")]
    InvalidToken(String),

    #[error("Token JWT expirado")]
    ExpiredToken,

    #[error("Falha ao carregar chave RSA: {0}")]
    RsaKeyError(String),

    #[error("Formato de chave inválido (esperado PEM ou base64): {0}")]
    InvalidKeyFormat(String),

    #[error("Chave privada não configurada")]
    MissingPrivateKey,

    #[error("Chave pública não configurada")]
    MissingPublicKey,
}
