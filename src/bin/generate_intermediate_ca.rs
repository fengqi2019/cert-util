use anyhow::anyhow;
use cert_util::{
    gen_ca_cert, gen_root_cert, gen_rsa_key_pem_and_file, gen_valid_date, load_certs, load_rsa_key,
};
use log::debug;
use picky::key::{PrivateKey, PublicKey};
use picky::x509::certificate::CertType;
use picky::x509::Cert;
use std::path::PathBuf;
use tokio::fs::read_to_string;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    custom_utils::logger::logger_stdout_debug();

    let args = Args::init();

    let pri_key_path = args.private_key_path();
    let pub_key_path = args.public_key_path();
    debug!("{:?}, {:?}", pri_key_path, pub_key_path);
    let (intermediate_pri, _) = if pri_key_path.exists() {
        (
            PrivateKey::from_pem_str(read_to_string(pri_key_path).await?.as_str())?,
            PublicKey::from_pem_str(read_to_string(pub_key_path).await?.as_str())?,
        )
    } else {
        gen_rsa_key_pem_and_file(pri_key_path, pub_key_path)?
    };
    let root = Cert::from_pem_str(read_to_string(args.root_path.as_str()).await?.as_str())?;
    let root_key =
        PrivateKey::from_pem_str(read_to_string(args.root_key_path.as_str()).await?.as_str())?;
    let (from_date, to_date) = gen_valid_date(3)?;
    let intermediate = gen_ca_cert(
        args.name.as_str(),
        from_date,
        to_date,
        &root,
        &root_key,
        &intermediate_pri,
        args.cert_path(),
    )?;
    Ok(())
}
#[derive(Debug)]
pub struct Args {
    pub path: PathBuf,
    pub name: String,
    pub root_path: String,
    pub root_key_path: String,
}

impl Args {
    pub fn private_key_path(&self) -> PathBuf {
        self.path.join("intermediate_pri.key".to_string())
    }
    pub fn public_key_path(&self) -> PathBuf {
        self.path.join("intermediate_pub.key".to_string())
    }
    pub fn cert_path(&self) -> PathBuf {
        self.path.join("intermediate.crt".to_string())
    }
    pub fn init() -> Self {
        let path: PathBuf = custom_utils::args::arg_value("--path", "-p")
            .unwrap_or("./certs".to_string())
            .into();
        if !path.exists() {
            std::fs::create_dir_all(path.as_path()).unwrap();
        }
        let name = custom_utils::args::arg_value("--name", "-n")
            .unwrap_or("IntermediateCa".to_string())
            .into();
        let root_path =
            custom_utils::args::arg_value("--root", "-r").unwrap_or("./certs/root.crt".to_string());
        let root_key_path = custom_utils::args::arg_value("--root-key", "-k")
            .unwrap_or("./certs/root_pri.key".to_string());
        Self {
            path,
            name,
            root_path,
            root_key_path,
        }
    }
}
