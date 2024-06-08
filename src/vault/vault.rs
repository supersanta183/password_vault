use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsa::oaep;
use rsa::{
    pkcs8::der::zeroize::{Zeroize, Zeroizing},
    RsaPublicKey,
};
use rsa_keygen;
use sha2::Sha256;
use std::collections::HashMap;

use crate::vault::vault_errors::VaultError;

pub struct Vault {
    pub_key: RsaPublicKey,
    passwords: HashMap<String, (String, Result<Vec<u8>, rsa::Error>)>,
    logged_in: bool,
}

impl Vault {
    pub fn new() -> Result<Vault, VaultError> {
        let (mut seedprase, (_, pub_key)) = rsa_keygen::generate_seedphrase_and_keypair()
            .map_err(|err| err.to_string())
            .map_err(|_e| {
                VaultError::FailedToGenerateVaultError(String::from(
                    "failed to generate seedphrase and keypair",
                ))
            })?;

        //print seedphrase
        println!("{}", seedprase.as_str());
        seedprase.zeroize();

        let passwords = HashMap::new();
        let logged_in = false;

        let vault = Vault {
            pub_key: pub_key,
            passwords: passwords,
            logged_in: logged_in,
        };
        return Ok(vault);
    }

    pub fn from_seedphrase(seedphrase: &Zeroizing<String>) -> Result<Vault, VaultError> {
        let (_, pub_key) = rsa_keygen::keypair_from_seedphrase(seedphrase).map_err(|_e| {
            VaultError::FailedToLoginError(String::from(
                "Failed to generate keypair from seedphrase",
            ))
        })?;

        let passwords = HashMap::new();
        let logged_in = false;

        let vault = Vault {
            pub_key: pub_key,
            passwords: passwords,
            logged_in: logged_in,
        };
        return Ok(vault);
    }

    pub fn login(&mut self, seedphrase: &Zeroizing<String>) -> Result<(), VaultError> {
        let (_, pub_key) = rsa_keygen::keypair_from_seedphrase(seedphrase).map_err(|_e| {
            VaultError::FailedToLoginError(String::from(
                "Failed to generate keypair from seedphrase",
            ))
        })?;

        if pub_key != self.pub_key {
            return Err(VaultError::FailedToLoginError(String::from(
                "wrong seedphrase",
            )));
        }

        println!("Logged in succesfully!");
        self.logged_in = true;

        Ok(())
    }

    pub fn logout(&mut self) {
        self.logged_in = false;
    }

    pub fn add_password(
        &mut self,
        service: String,
        username: String,
        mut password: Zeroizing<String>,
    ) -> Result<(), VaultError> {
        if !self.logged_in {
            return Err(VaultError::NotLoggedInError);
        }

        let padding = oaep::Oaep::new::<Sha256>();
        let mut rng = ChaCha20Rng::from_entropy();
        let encrypted_password = self.pub_key.encrypt(&mut rng, padding, password.as_bytes());
        password.zeroize();

        let user_info = (username, encrypted_password);
        self.passwords.insert(service, user_info);

        println!("password added successfully!");

        Ok(())
    }
}

//test module
#[cfg(test)]
mod vault_tests {
    use crate::vault;

    use super::*;

    fn create_vault() -> (Zeroizing<String>, Vault) {
        let seedphrase = Zeroizing::new(String::from(
            "shell unfold hollow cause layer limit cigar educate ensure weekend ridge help",
        ));
        let mut vault = Vault::from_seedphrase(&seedphrase).expect("failed to creat vault");

        (seedphrase, vault)
    }

    #[test]
    fn cannot_add_password_when_not_logged_in() {
        let(_, mut vault) = create_vault();

        let service = String::from("service");
        let username = String::from("Emil");
        let password = Zeroizing::new(String::from("password"));
        let add_password = vault.add_password(service, username, password);

        assert!(add_password.is_err());

        if let Err(e) = add_password {
            assert_eq!(e, VaultError::NotLoggedInError)
        }
    }

    #[test]
    fn can_add_password_when_logged_in() {
        let (seedphrase, mut vault) = create_vault();

        let res = vault.login(&seedphrase);
        assert!(!res.is_err());

        let service = String::from("service");
        let username = String::from("Emil");
        let password = Zeroizing::new(String::from("password"));
        let add_password = vault.add_password(service, username, password);

        assert!(!add_password.is_err());
    }
}
