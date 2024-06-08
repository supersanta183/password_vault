use std::fmt::{self, write};
use std::error::Error;

#[derive(Debug, PartialEq)]
pub enum VaultError {
    NotLoggedInError,
    CredentialsMissingForServiceError(String),
    FailedToLoginError(String),
    FailedToGenerateVaultError(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::NotLoggedInError => write!(f, "Not logged in error"),
            VaultError::CredentialsMissingForServiceError(msg) => write!(f, "No credentials for service {}", msg),
            VaultError::FailedToLoginError(msg) => write!(f, "Failed to login error {}", msg),
            VaultError::FailedToGenerateVaultError(msg) => write!(f, "Failed to generate new Vault {}", msg),
        }
    }
}

impl Error for VaultError {}