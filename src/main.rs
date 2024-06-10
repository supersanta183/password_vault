mod vault;
mod password_generator;

use rsa::{self, pkcs8::der::zeroize::Zeroizing};
use vault::vault::Vault;
use password_generator::password_generator::PasswordGenerator;

fn main() {
    let seedphrase = Zeroizing::new(String::from("shell unfold hollow cause layer limit cigar educate ensure weekend ridge help"));
    let password = Zeroizing::new(String::from("emil er sej"));
    let mut vault = Vault::from_password(password.clone()).expect("failed to create vault");
    let mut vault2 = Vault::from_seedphrase(seedphrase.clone()).expect("failed to creat vault");
    vault.login_with_password(password).expect("failed to login");
    vault2.login_with_seedphrase(&seedphrase).expect("failed to login");
    
    let service = String::from("service");
    let username = String::from("Emil");
    let password = Zeroizing::new(String::from("password"));
    vault.add_password(service, username, password).expect("failed to add password to vault");

    let service = String::from("youtube");
    let username = String::from("supersanta183");
    let password = Zeroizing::new(String::from("password123"));
    vault.add_password(service, username, password).expect("failed to add password to vault");

    vault.get_available_credentials();
    let x = vault.get_credentials_from_service(String::from("youtube")).unwrap();
    vault2.decrypt_password(x).unwrap();
}
