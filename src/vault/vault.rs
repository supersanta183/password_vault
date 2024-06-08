use rand::SeedableRng;
use rsa::{pkcs8::der::zeroize::{Zeroize, Zeroizing}, RsaPublicKey};
use rsa::{self, oaep};
use rsa_keygen;
use std::collections::HashMap;
use sha2::Sha256;
use rand_chacha::ChaCha20Rng;

use crate::vault::vault_errors::VaultError;

pub struct Vault {
    pub_key: RsaPublicKey,
    passwords: HashMap<String, (String, Result<Vec<u8>, rsa::Error>)>,
    logged_in: bool
}

impl Vault {
    pub fn new() -> Result<Vault, String> {
        let (mut seedprase, (_, pub_key)) = rsa_keygen::generate_seedphrase_and_keypair().map_err(|err| err.to_string())?;

        //print seedphrase
        println!("{}", seedprase.as_str());
        seedprase.zeroize();

        let passwords = HashMap::new();
        let logged_in = false;

        let vault = Vault{pub_key: pub_key, passwords: passwords, logged_in: logged_in};
        return Ok(vault);
    }

    pub fn new_from_seedphrase(seedphrase: &Zeroizing<String>) -> Result<Vault, VaultError> {
        let (_, pub_key) = rsa_keygen::keypair_from_seedphrase(seedphrase)
        .map_err(|_e| VaultError::FailedToLoginError(String::from("Failed to generate keypair from seedphrase")))?;

        let passwords = HashMap::new();
        let logged_in = false;
        
        let vault = Vault{pub_key: pub_key, passwords: passwords, logged_in: logged_in};
        return Ok(vault);
    }

    pub fn login(&mut self, seedphrase: &Zeroizing<String>) -> Result<(), VaultError> {
        let (_, pub_key) = rsa_keygen::keypair_from_seedphrase(seedphrase)
        .map_err(|_e| VaultError::FailedToLoginError(String::from("Failed to generate keypair from seedphrase")))?;

        if pub_key != self.pub_key {
            return Err(VaultError::FailedToLoginError(String::from("wrong seedphrase")));
        }

        println!("Logged in succesfully!");
        self.logged_in = true;

        Ok(())
    }

    pub fn logout(&mut self) {
        self.logged_in = false;
    }

    pub fn add_password(&mut self, service: String, username: String, mut password: Zeroizing<String>) -> Result<(), VaultError> {
        if !self.logged_in {
            return Err(VaultError::NotLoggedInError(String::from("Trying to add password but no user was logged in")));
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