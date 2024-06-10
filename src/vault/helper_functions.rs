use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsa::{self, RsaPrivateKey};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub fn sign_with_pss(sk: RsaPrivateKey, hashed_data: Vec<u8>)-> Result<Vec<u8>, String> {
    let mut rng = ChaCha20Rng::from_entropy();
    let signature = sk
        .sign_with_rng(&mut rng, rsa::Pss::new::<Sha256>(), &hashed_data).map_err(|e| e.to_string())?;

    Ok(signature)
}

pub fn verify_with_pss(pk: rsa::RsaPublicKey, hashed_data: Vec<u8>, signature: Vec<u8>) -> Result<(), String> {
    pk.verify(rsa::Pss::new::<Sha256>(), &hashed_data, &signature)
        .map_err(|e| e.to_string())
}

pub fn hash_password(password: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(password);
    let hash = hasher.finalize();
    hash.to_vec()
}
