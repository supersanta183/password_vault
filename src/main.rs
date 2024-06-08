mod vault;

use rsa::{self, pkcs8::der::zeroize::Zeroizing};
use zeroize::Zeroize;
use secrecy::{Secret, ExposeSecret};
use vault::vault::Vault;

fn main() {
    let seedphrase = Zeroizing::new(String::from("shell unfold hollow cause layer limit cigar educate ensure weekend ridge help"));
    let mut vault = Vault::from_seedphrase(&seedphrase).expect("failed to creat vault");
    vault.login(&seedphrase).expect("failed to login");
    
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
    vault.decrypt_password(x).unwrap();
}
