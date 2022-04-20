use cert_util::gen_rsa_pkcs8_key_pem_and_file;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

fn main() {
    let mut rng = rand::thread_rng();
    //
    // let bits = 2048;
    // let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    // let public_key = RsaPublicKey::from(&private_key);
    let (pri_key, pub_key) =
        gen_rsa_pkcs8_key_pem_and_file("certs/private.key", "certs/pub.key").unwrap();
    let private_key = RsaPrivateKey::from_pkcs8_pem(pri_key.as_str()).unwrap();
    let public_key = RsaPublicKey::from_public_key_pem(pub_key.as_str()).unwrap();

    // Encrypt
    let data = b"hello world";
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let enc_data = public_key
        .encrypt(&mut rng, padding, &data[..])
        .expect("failed to encrypt");
    assert_ne!(&data[..], &enc_data[..]);

    // Decrypt
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let dec_data = private_key
        .decrypt(padding, &enc_data)
        .expect("failed to decrypt");
    assert_eq!(&data[..], &dec_data[..]);

    std::fs::write("certs/private.key", pri_key.as_bytes()).unwrap();
    std::fs::write("certs/pub.key", pub_key.as_bytes()).unwrap();
}
