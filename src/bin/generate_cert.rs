use cert_util::{gen_cert_by_ca, gen_rsa_key_pem_and_file, gen_valid_date};
use log::debug;
use picky::key::{PrivateKey, PublicKey};
use picky::x509::csr::Attribute;
use picky::x509::extension::KeyUsage;
use picky::x509::name::{DirectoryName, GeneralName, NameAttr};
use picky::x509::{csr::Csr, Cert, Extension, Extensions};
use picky::{hash::HashAlgorithm, oids, signature::SignatureAlgorithm};
use std::path::PathBuf;
use tokio::fs::read_to_string;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    custom_utils::logger::logger_stdout_debug();

    let args = Args::init();

    let pri_key_path = args.private_key_path();
    let pub_key_path = args.public_key_path();
    debug!("{:?}, {:?}", pri_key_path, pub_key_path);
    let (localhost_key, _) = if pri_key_path.exists() {
        (
            PrivateKey::from_pem_str(read_to_string(pri_key_path).await?.as_str())?,
            PublicKey::from_pem_str(read_to_string(pub_key_path).await?.as_str())?,
        )
    } else {
        gen_rsa_key_pem_and_file(pri_key_path, pub_key_path)?
    };
    let root = Cert::from_pem_str(read_to_string(args.ca_path.as_str()).await?.as_str())?;
    let root_key =
        PrivateKey::from_pem_str(read_to_string(args.ca_key_path.as_str()).await?.as_str())?;

    let mut key_usage = KeyUsage::new(8);
    // key_usage.set_digital_signature(true);
    // key_usage.set_content_commitment(true);
    key_usage.set_key_encipherment(true);
    // key_usage.set_crl_sign(true);
    key_usage.set_data_encipherment(true);
    // key_usage.set_decipher_only(true);
    // key_usage.set_encipher_only(true);
    // key_usage.set_key_agreement(true);
    // key_usage.set_key_cert_sign(true);
    let extensions = Extensions(vec![
        Extension::new_basic_constraints(None, None).into_non_critical(),
        Extension::new_key_usage(key_usage).into_non_critical(),
        Extension::new_extended_key_usage(vec![
            oids::kp_client_auth(),
            oids::kp_server_auth(),
            oids::kp_code_signing(),
        ])
        .into_non_critical(),
        Extension::new_subject_alt_name(vec![
            GeneralName::new_dns_name("www.localhost.com")
                .unwrap()
                .into(),
            GeneralName::new_dns_name("localhost.com").unwrap().into(),
            GeneralName::new_dns_name("localhost").unwrap().into(),
        ])
        .into_non_critical(),
    ]);
    let attr = Attribute::new_extension_request(extensions.0);
    let mut my_name = DirectoryName::new_common_name(args.name.as_str());
    my_name.add_attr(NameAttr::StateOrProvinceName, "fujian");
    my_name.add_attr(NameAttr::CountryName, "China");
    let csr = Csr::generate_with_attributes(
        my_name,
        &localhost_key,
        SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256),
        vec![attr],
    )
    .unwrap();
    let (from_date, to_date) = gen_valid_date(3)?;

    let _signed_leaf =
        gen_cert_by_ca(csr, from_date, to_date, &root, &root_key, args.cert_path()).unwrap();
    Ok(())
}

#[derive(Debug)]
pub struct Args {
    pub file_name: String,
    pub path: PathBuf,
    pub name: String,
    pub ca_path: String,
    pub ca_key_path: String,
}

impl Args {
    pub fn private_key_path(&self) -> PathBuf {
        self.path.join(format!("{}_pri.key", self.file_name))
    }
    pub fn public_key_path(&self) -> PathBuf {
        self.path.join(format!("{}_pub.key", self.file_name))
    }
    pub fn cert_path(&self) -> PathBuf {
        self.path.join(format!("{}.crt", self.file_name))
    }
    pub fn init() -> Self {
        let path: PathBuf = custom_utils::args::arg_value("--path", "-p")
            .unwrap_or("./certs".to_string())
            .into();
        if !path.exists() {
            std::fs::create_dir_all(path.as_path()).unwrap();
        }
        let name = custom_utils::args::arg_value("--name", "-n")
            .unwrap_or("localhost.com".to_string())
            .into();
        let root_path =
            custom_utils::args::arg_value("--root", "-r").unwrap_or("./certs/root.crt".to_string());
        let root_key_path = custom_utils::args::arg_value("--root-key", "-k")
            .unwrap_or("./certs/root_pri.key".to_string());
        let file_name = custom_utils::args::arg_value("--file", "-f").unwrap_or("cert".to_string());
        Self {
            path,
            file_name,
            name,
            ca_path: root_path,
            ca_key_path: root_key_path,
        }
    }
}
