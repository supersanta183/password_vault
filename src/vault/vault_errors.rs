use std::fmt::{self, write};
use std::error::Error;

#[derive(Debug, PartialEq)]
pub enum VaultError {
    NotLoggedInError(String),
    CredentialsMissingForServiceError(String),
    FailedToLoginError(String),
    FailedToGenerateVaultError(String),
    FailedToAddPasswordError(String),
    FailedToDecryptError(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::NotLoggedInError(msg) => write!(f, "Not logged in error {}", msg),
            VaultError::CredentialsMissingForServiceError(msg) => write!(f, "No credentials for service {}", msg),
            VaultError::FailedToLoginError(msg) => write!(f, "Failed to login error {}", msg),
            VaultError::FailedToGenerateVaultError(msg) => write!(f, "Failed to generate new Vault {}", msg),
            VaultError::FailedToAddPasswordError(msg) => write!(f, "Failed to add password to vault {}", msg),
            VaultError::FailedToDecryptError(msg) => write!(f, "Failed to decrypt password {}", msg),
        }
    }
}

impl Error for VaultError {}