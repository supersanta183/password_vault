use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsa::oaep;
use rsa::{pkcs8::der::zeroize::Zeroizing, RsaPublicKey};
use rsa_keygen;
use secrecy::{ExposeSecret, Secret};
use sha2::Sha256;
use std::collections::HashMap;
use zeroize::Zeroize;

use crate::vault::vault_errors::VaultError;

type Credentials = (String, Vec<u8>);

pub struct Vault {
    pub_key: RsaPublicKey,
    seedphrase: Option<Secret<Vec<u8>>>,
    credentials: HashMap<String, Credentials>,
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
            seedphrase: None,
            credentials: passwords,
            logged_in: logged_in,
        };
        return Ok(vault);
    }

    pub fn from_seedphrase(mut seedphrase: Zeroizing<String>) -> Result<Vault, VaultError> {
        let (_, pub_key) = rsa_keygen::keypair_from_seedphrase(&seedphrase).map_err(|_e| {
            VaultError::FailedToLoginError(String::from(
                "Failed to generate keypair from seedphrase",
            ))
        })?;

        seedphrase.zeroize();

        let passwords = HashMap::new();
        let logged_in = false;

        let vault = Vault {
            pub_key: pub_key,
            seedphrase: None,
            credentials: passwords,
            logged_in: logged_in,
        };
        return Ok(vault);
    }

    pub fn from_password(mut password: Zeroizing<String>) -> Result<Vault, VaultError> {
        let seedphrase = rsa_keygen::seedphrase_from_password(&password).map_err(|_e| {
            VaultError::FailedToLoginError(String::from(
                "Failed to generate seedphrase from password",
            ))
        })?;

        let vault = Self::from_seedphrase(seedphrase).map_err(|_e| {
            VaultError::FailedToGenerateVaultError(String::from(
                "failed to generate vault from seedphrase",
            ))
        })?;
        password.zeroize();

        Ok(vault)
    }

    pub fn login_with_seedphrase(&mut self, seedphrase: &Zeroizing<String>) -> Result<(), VaultError> {
        
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

        let secret_seedphrase = secrecy::Secret::new((**seedphrase).clone().into_bytes());
        self.seedphrase = Some(secret_seedphrase);
        self.logged_in = true;

        println!("Logged in succesfully!");

        Ok(())
    }

    pub fn login_with_password(&mut self, mut password: Zeroizing<String>) -> Result<(), VaultError> {
        let seedphrase = rsa_keygen::seedphrase_from_password(&password).map_err(|_e| {
            VaultError::FailedToLoginError(String::from(
                "Failed to generate seedphrase from password",
            ))
        })?;
        password.zeroize();

        let res = self.login_with_seedphrase(&seedphrase);

        res
    }

    pub fn logout(&mut self) {
        self.seedphrase = None;
        self.logged_in = false;

        println!("Logged out succesfully!");
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
        let encrypted_password = self.pub_key.encrypt(&mut rng, padding, password.as_bytes()).map_err(|_e| {
            VaultError::FailedToAddPasswordError(String::from(
                "Failed to encrypt password",
            ))
        })?;
        password.zeroize();

        let user_info = (username, encrypted_password);
        self.credentials.insert(service, user_info);

        println!("password added successfully!");

        Ok(())
    }

    // returns a list of the services that you have saved a password for
    pub fn get_available_credentials(&self) -> Result<Vec<String>, VaultError> {
        if !self.logged_in {
            return Err(VaultError::NotLoggedInError);
        }
        let services = self.credentials.keys().cloned().collect();
        Ok(services)
    }

    // returns (username, password) from a specific service. Password is encrypted
    pub fn get_credentials_from_service(
        &self,
        service: String,
    ) -> Result<&Credentials, VaultError> {
        if !self.logged_in {
            return Err(VaultError::NotLoggedInError);
        }
        let credentials = match self.credentials.get(&service) {
            Some(credentials) => credentials,
            None => return Err(VaultError::CredentialsMissingForServiceError(service)),
        };
        Ok(credentials)
    }

    // decrypts the password from a specific service
    // remember to zeroize password after use!
    pub fn decrypt_password(
        &self,
        credentials: &Credentials,
    ) -> Result<Zeroizing<String>, VaultError> {
        if !self.logged_in {
            return Err(VaultError::NotLoggedInError);
        };
        let seedphrase = self.seedphrase.as_ref().expect("no seedphrase found");
        let seedphrase_bytes = seedphrase.expose_secret();
        let seedphrase_string = String::from_utf8(seedphrase_bytes.to_owned()).unwrap();

        let (sk, _) = rsa_keygen::keypair_from_seedphrase(&Zeroizing::new(seedphrase_string))
            .expect("failed to generate keypair from seedphrase");

        let pw = credentials.1.as_ref();
        let pw_decrypted = sk
            .decrypt(oaep::Oaep::new::<Sha256>(), pw)
            .expect("failed to decrypt password");
        let pw_string = Zeroizing::new(String::from_utf8(pw_decrypted).unwrap());

        Ok(pw_string)
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
        let vault = Vault::from_seedphrase(seedphrase.clone()).expect("failed to creat vault");

        (seedphrase, vault)
    }

    fn create_vault_with_password() -> (Zeroizing<String>, Vault) {
        let password = Zeroizing::new(String::from("emil er sej"));
        let vault = Vault::from_password(password.clone()).expect("failed to create vault");

        (password, vault)
    }

    #[test]
    fn cannot_add_password_when_not_logged_in() {
        let (_, mut vault) = create_vault();

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

        let res = vault.login_with_seedphrase(&seedphrase);
        assert!(!res.is_err());

        let service = String::from("service");
        let username = String::from("Emil");
        let password = Zeroizing::new(String::from("password"));
        let add_password = vault.add_password(service, username, password);

        assert!(!add_password.is_err());
    }

    #[test]
    fn can_login_with_seedphrase() {
        let (seedphrase, mut vault) = create_vault();

        let res = vault.login_with_seedphrase(&seedphrase);
        assert!(!res.is_err());
    }

    #[test]
    fn can_login_with_password() {
        let (password, mut vault) = create_vault_with_password();

        let res = vault.login_with_password(password);
        assert!(!res.is_err());
    }

    #[test]
    fn can_logout() {
        let (seedphrase, mut vault) = create_vault();

        let res = vault.login_with_seedphrase(&seedphrase);
        assert!(!res.is_err());
        assert_eq!(vault.logged_in, true);

        vault.logout();

        assert_eq!(vault.logged_in, false);
    }

    #[test]
    fn can_get_available_credentials() {
        let (seedphrase, mut vault) = create_vault();

        let res = vault.login_with_seedphrase(&seedphrase);
        assert!(!res.is_err());

        let service = String::from("service");
        let username = String::from("Emil");
        let password = Zeroizing::new(String::from("password"));
        let add_password = vault.add_password(service, username, password);

        assert!(!add_password.is_err());

        let available_credentials = vault.get_available_credentials();
        assert!(!available_credentials.is_err());
        assert_eq!(available_credentials.unwrap(), vec![String::from("service")]);
    }

    #[test]
    fn can_get_credentials_from_service() {
        let (seedphrase, mut vault) = create_vault();

        let res = vault.login_with_seedphrase(&seedphrase);
        assert!(!res.is_err());

        let service = String::from("service");
        let username = String::from("Emil");
        let password = Zeroizing::new(String::from("password"));
        let add_password = vault.add_password(service.clone(), username, password);

        assert!(!add_password.is_err());

        let credentials = vault.get_credentials_from_service(service);
        assert!(!credentials.is_err());
    }

    #[test]
    fn cannot_get_credentials_from_service_when_not_logged_in() {
        let (seedphrase, mut vault) = create_vault();

        let res = vault.login_with_seedphrase(&seedphrase);
        assert!(!res.is_err());

        let service = String::from("service");
        let username = String::from("Emil");
        let password = Zeroizing::new(String::from("password"));
        let add_password = vault.add_password(service.clone(), username, password);

        assert!(!add_password.is_err());

        vault.logout();

        let credentials = vault.get_credentials_from_service(service);
        assert!(credentials.is_err());
    }

    #[test]
    fn can_decrypt_password() {
        let (seedphrase, mut vault) = create_vault();

        let res = vault.login_with_seedphrase(&seedphrase);
        assert!(!res.is_err());

        let service = String::from("service");
        let username = String::from("Emil");
        let password = Zeroizing::new(String::from("password"));
        let add_password = vault.add_password(service.clone(), username, password);

        assert!(!add_password.is_err());

        let credentials = vault.get_credentials_from_service(service).unwrap();
        let decrypted_password = vault.decrypt_password(credentials);

        assert!(!decrypted_password.is_err());
        assert_eq!(decrypted_password.unwrap(), Zeroizing::new(String::from("password")));
    }

    #[test]
    fn decrypted_password_is_same_as_original() {
        let (seedphrase, mut vault) = create_vault();

        let res = vault.login_with_seedphrase(&seedphrase);
        assert!(!res.is_err());

        let service = String::from("service");
        let username = String::from("Emil");
        let password = Zeroizing::new(String::from("password"));
        let add_password = vault.add_password(service.clone(), username, password.clone());

        assert!(!add_password.is_err());

        let credentials = vault.get_credentials_from_service(service).unwrap();
        let decrypted_password = vault.decrypt_password(credentials).unwrap();

        assert_eq!(decrypted_password, password);
    }
}
