#![allow(unused_must_use)]
use anyhow::Result;
use cert_util::load_certs;
use rustls::client::{ServerCertVerifier, WebPkiVerifier};
use rustls::RootCertStore;
use std::time::SystemTime;

fn main() -> Result<()> {
    custom_utils::logger::logger_stdout_debug();
    assert!(verify_server("./ecdsa/ca.cert", "./ecdsa/end.fullchain", "localhost").is_ok());
    assert!(verify_server("./ecdsa/ca.cert", "./ecdsa/client.fullchain", "localhost").is_err());
    Ok(())
}

fn verify_server(ca_path: &str, server_fullchain_path: &str, server_name: &str) -> Result<()> {
    let mut root_store = RootCertStore::empty();
    // root_store.add(&load_certs("./ecdsa/inter.cert")?.remove(0))?;
    root_store.add(&load_certs(ca_path)?.remove(0))?;
    let verifier = WebPkiVerifier::new(root_store, None);
    let chain = load_certs(server_fullchain_path)?;
    let (end_entity, intermediates) = chain.split_first().unwrap();
    const SCTS: &[&[u8]] = &[];
    const OCSP_RESPONSE: &[u8] = &[];
    let _result = verifier.verify_server_cert(
        end_entity,
        intermediates,
        &server_name.try_into()?,
        &mut SCTS.iter().copied(),
        OCSP_RESPONSE,
        SystemTime::now(),
    )?;
    Ok(())
}
