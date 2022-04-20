use anyhow::Result;
use rsa::pkcs1::LineEnding;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::path::Path;

pub fn gen_rsa_pkcs8_key_pem() -> Result<(String, String)> {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);
    let pri_str = private_key.to_pkcs8_pem(LineEnding::CRLF)?;
    let pub_str = public_key.to_public_key_pem(LineEnding::CRLF)?;
    Ok((pri_str.to_string(), pub_str))
}

pub fn gen_rsa_pkcs8_key_pem_and_file(
    pri_path: impl AsRef<Path>,
    pub_path: impl AsRef<Path>,
) -> Result<(String, String)> {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);
    let pri_str = private_key.to_pkcs8_pem(LineEnding::CRLF)?;
    let pub_str = public_key.to_public_key_pem(LineEnding::CRLF)?;

    std::fs::write(pub_path, pub_str.as_bytes())?;
    std::fs::write(pri_path, pri_str.as_bytes())?;
    Ok((pri_str.to_string(), pub_str))
}
