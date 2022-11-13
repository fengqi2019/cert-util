use anyhow::Result;
use cert_util::{load_certs, load_pkcs8_key};
use log::LevelFilter::Trace;
use rustls::{ClientConfig, RootCertStore};

#[tokio::main]
async fn main() -> Result<()> {
    custom_utils::logger::logger_stdout(Trace);

    // Some simple CLI args requirements...
    let url = match std::env::args().nth(1) {
        Some(url) => url,
        None => {
            println!("No CLI URL provided, using default.");
            "https://localhost:8080".into()
        }
    };

    eprintln!("Fetching {:?}...", url);

    // let certs = load_certs("certs/root.crt")?;
    // let certs = load_certs("certs/root.crt")?;
    let certs = load_certs("ecdsa/ca.cert")?;
    let cert = reqwest::Certificate::from_der(certs[0].0.as_slice())?;

    let mut root_store = RootCertStore::empty();
    root_store.add(&load_certs("ecdsa/ca.cert")?.remove(0))?;
    // let certs_root = load_certs("certs/root_pri.key")?;
    // let cert_root = reqwest::Certificate::from_der(certs_root[0].0.as_slice())?;

    let client_crt = load_certs("ecdsa/client.fullchain")?;
    let client_key = load_pkcs8_key("ecdsa/client.key")?;
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_single_cert(client_crt, client_key)?;

    let client = reqwest::ClientBuilder::default()
        .add_root_certificate(cert)
        // must add this code!
        // .use_rustls_tls()
        .use_preconfigured_tls(config)
        // .add_root_certificate(cert_root)
        .build()?;

    let res = client.get(url).send().await?;
    // reqwest::get() is a convenience function.
    //
    // In most cases, you should create/build a reqwest::Client and reuse
    // it for all requests.
    // let res = reqwest::get(url).await?;

    eprintln!("Response: {:?} {}", res.version(), res.status());
    eprintln!("Headers: {:#?}\n", res.headers());

    let body = res.text().await?;

    println!("{}", body);

    Ok(())
}
