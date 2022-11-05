use cert_util::{gen_root_cert, gen_rsa_key_pem_and_file, gen_valid_date};
use picky::key::{PrivateKey, PublicKey};
use picky::x509::certificate::CertType;
use std::path::PathBuf;
use tokio::fs::read_to_string;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    custom_utils::logger::logger_stdout_debug();

    let args = Args::init();

    let pri_key_path = args.private_key_path();
    let pub_key_path = args.public_key_path();

    let (root_key, _) = if pri_key_path.exists() {
        (
            PrivateKey::from_pem_str(read_to_string(pri_key_path).await?.as_str())?,
            PublicKey::from_pem_str(read_to_string(pub_key_path).await?.as_str())?,
        )
    } else {
        gen_rsa_key_pem_and_file(pri_key_path, pub_key_path)?
    };
    let (from_date, to_date) = gen_valid_date(3)?;
    let root = gen_root_cert(
        args.name.as_str(),
        from_date,
        to_date,
        &root_key,
        args.cert_path(),
    )?;
    assert_eq!(root.ty(), CertType::Root);
    Ok(())
}
#[derive(Debug)]
pub struct Args {
    pub path: PathBuf,
    pub name: String,
}

impl Args {
    pub fn private_key_path(&self) -> PathBuf {
        self.path.join("root_pri.key".to_string())
    }
    pub fn public_key_path(&self) -> PathBuf {
        self.path.join("root_pub.key".to_string())
    }
    pub fn cert_path(&self) -> PathBuf {
        self.path.join("root.crt".to_string())
    }
    pub fn init() -> Self {
        let path: PathBuf = custom_utils::args::arg_value("--path", "-p")
            .unwrap_or("./certs".to_string())
            .into();
        if !path.exists() {
            std::fs::create_dir_all(path.as_path()).unwrap();
        }
        let name = custom_utils::args::arg_value("--name", "-n")
            .unwrap_or("RootCa".to_string())
            .into();
        Self { path, name }
    }
}
