use std::fmt::{self, write};
use std::error::Error;

#[derive(Debug)]
pub enum VaultError {
    NotLoggedInError(String),
    FailedToLoginError(String),
    FailedToGenerateVaultError(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::NotLoggedInError(msg) => write!(f, "Not logged in error {}", msg),
            VaultError::FailedToLoginError(msg) => write!(f, "Failed to login error {}", msg),
            VaultError::FailedToGenerateVaultError(msg) => write!(f, "Failed to generate new Vault {}", msg),
        }
    }
}

impl Error for VaultError {}