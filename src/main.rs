mod vault;

use rsa::{self, pkcs8::der::zeroize::Zeroizing};

use vault::vault::Vault;

fn main() {
    let seedphrase = Zeroizing::new(String::from("shell unfold hollow cause layer limit cigar educate ensure weekend ridge help"));
    let mut vault = Vault::new_from_seedphrase(&seedphrase).expect("failed to creat vault");
    vault.login(&seedphrase).expect("failed to login");
    
    let service = String::from("service");
    let username = String::from("Emil");
    let password = Zeroizing::new(String::from("password"));
    vault.add_password(service, username, password).expect("failed to add password to vault");
}
