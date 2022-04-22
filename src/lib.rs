use anyhow::{anyhow, bail, Context, Result};
use chrono::Datelike;
use picky::hash::HashAlgorithm;
use picky::key::{PrivateKey, PublicKey};
use picky::signature::SignatureAlgorithm;
use picky::x509::certificate::CertificateBuilder;
use picky::x509::date::UTCDate;
use picky::x509::name::DirectoryName;
use picky::x509::{Cert, Csr, KeyIdGenMethod};
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rustls::Certificate;
use rustls_pemfile::Item::X509Certificate;
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

pub fn gen_rsa_key_pem_and_file(
    pri_path: impl AsRef<Path>,
    pub_path: impl AsRef<Path>,
) -> Result<(PrivateKey, PublicKey)> {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);
    let pri_str = private_key.to_pkcs1_pem(LineEnding::CRLF)?;
    let pub_str = public_key.to_public_key_pem(LineEnding::CRLF)?;

    // let mut reader = BufReader::new(pri_str.as_bytes());
    // let key = rustls_pemfile::rsa_private_keys(&mut reader).unwrap();
    // println!("key.len = {}", key.len());
    std::fs::write(pub_path, pub_str.as_bytes())?;
    std::fs::write(pri_path, pri_str.as_bytes())?;
    Ok((
        PrivateKey::from_pem_str(pri_str.as_str())?,
        PublicKey::from_pem_str(pub_str.as_str())?,
    ))
}

pub fn gen_rsa_pkcs8_key_pem_and_file(
    pri_path: impl AsRef<Path>,
    pub_path: impl AsRef<Path>,
) -> Result<(PrivateKey, PublicKey)> {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);
    let pri_str = private_key.to_pkcs8_pem(LineEnding::CRLF)?;
    let pub_str = public_key.to_public_key_pem(LineEnding::CRLF)?;

    // println!("{:?}", pri_str);
    // println!("{:?}", pub_str);
    std::fs::write(pub_path, pub_str.as_bytes())?;
    std::fs::write(pri_path, pri_str.as_bytes())?;
    Ok((
        PrivateKey::from_pem_str(pri_str.as_str())?,
        PublicKey::from_pem_str(pub_str.as_str())?,
    ))
}

pub fn gen_root_cert(
    name: &str,
    from_date: UTCDate,
    to_date: UTCDate,
    ca_key: &picky::key::PrivateKey,
    cert_path: impl AsRef<Path>,
) -> Result<Cert> {
    let root = CertificateBuilder::new()
        .validity(from_date, to_date)
        .self_signed(DirectoryName::new_common_name(name), ca_key)
        .ca(true)
        .signature_hash_type(SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256))
        .key_id_gen_method(KeyIdGenMethod::SPKFullDER(HashAlgorithm::SHA2_256))
        .build()?;
    let root_pem = root.to_pem()?;

    // println!("{:?}", root_pem.to_string());
    std::fs::write(cert_path, root_pem.to_string()).unwrap();
    Ok(root)
}

pub fn gen_ca_cert(
    subject_name: &str,
    from_date: UTCDate,
    to_date: UTCDate,
    super_ca: &Cert,
    super_ca_key: &picky::key::PrivateKey,
    ca_key: &picky::key::PrivateKey,
    cert_path: impl AsRef<Path>,
) -> Result<Cert> {
    let intermediate = CertificateBuilder::new()
        .validity(from_date, to_date)
        .subject(
            DirectoryName::new_common_name(subject_name),
            ca_key.to_public_key(),
        )
        .issuer_cert(super_ca, super_ca_key)
        .signature_hash_type(SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256))
        .key_id_gen_method(KeyIdGenMethod::SPKFullDER(HashAlgorithm::SHA2_256))
        .ca(true)
        .pathlen(0)
        .build()?;
    let intermediate_pem = intermediate.to_pem()?;
    std::fs::write(cert_path, intermediate_pem.to_string()).unwrap();
    Ok(intermediate)
}

pub fn gen_cert_by_ca(
    csr: Csr,
    from_data: UTCDate,
    to_date: UTCDate,
    ca_cert: &Cert,
    ca_key: &picky::key::PrivateKey,
    cert_path: impl AsRef<Path>,
) -> Result<Cert> {
    let signed_leaf = CertificateBuilder::new()
        .validity(from_data, to_date)
        .subject_from_csr(csr)
        .inherit_extensions_from_csr_attributes(true)
        .issuer_cert(&ca_cert, &ca_key)
        .signature_hash_type(SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256))
        .key_id_gen_method(KeyIdGenMethod::SPKFullDER(HashAlgorithm::SHA2_256))
        .build()?;
    let leaf_pem = signed_leaf.to_pem()?;
    std::fs::write(cert_path, leaf_pem.to_string()).unwrap();
    Ok(signed_leaf)
}

pub fn gen_valid_date(valid_year: u16) -> Result<(UTCDate, UTCDate)> {
    use chrono::Utc;
    let now = Utc::now();
    let year = now.year() as u16 + valid_year;
    let from_date = UTCDate::from(now);
    let to_date = UTCDate::ymd(year, now.month() as u8, now.day() as u8)
        .ok_or(anyhow!("日期生成失败:{:?}", year))?;
    Ok((from_date, to_date))
}

pub fn load_native_certs() -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().context("could not load platform certs")? {
        roots.add(&rustls::Certificate(cert.0)).unwrap();
    }
    Ok(roots)
}

pub fn load_certs(path: impl AsRef<Path>) -> Result<Vec<Certificate>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let datas = rustls_pemfile::certs(&mut reader)?;
    let mut certs = Vec::with_capacity(datas.len());
    for data in datas.into_iter() {
        certs.push(rustls::Certificate(data));
    }
    Ok(certs)
}
pub fn load_rsa_key(path: impl AsRef<Path>) -> Result<rustls::PrivateKey> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let datas = rustls_pemfile::rsa_private_keys(&mut reader)?;
    for data in datas.into_iter() {
        return Ok(rustls::PrivateKey(data));
    }
    bail!("未找到秘钥")
}
