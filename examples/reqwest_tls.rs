use anyhow::Result;
use cert_util::load_certs;

#[tokio::main]
async fn main() -> Result<()> {
    // Some simple CLI args requirements...
    let url = match std::env::args().nth(1) {
        Some(url) => url,
        None => {
            println!("No CLI URL provided, using default.");
            "https://localhost.com:8080".into()
        }
    };

    eprintln!("Fetching {:?}...", url);

    // let certs = load_certs("certs/root.crt")?;
    let certs = load_certs("certs/root.crt")?;
    let cert = reqwest::Certificate::from_der(certs[0].0.as_slice())?;

    // let certs_root = load_certs("certs/root_pri.key")?;
    // let cert_root = reqwest::Certificate::from_der(certs_root[0].0.as_slice())?;

    let client = reqwest::ClientBuilder::default()
        .add_root_certificate(cert)
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
