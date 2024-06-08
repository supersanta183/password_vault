mod keygen;
mod vault;

use rand::SeedableRng;
use rsa_keygen;
use rand_chacha::ChaCha20Rng;
use rsa::{self, oaep, pkcs8::der::zeroize::Zeroizing, traits::PaddingScheme};
use sha2::Sha256;

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
