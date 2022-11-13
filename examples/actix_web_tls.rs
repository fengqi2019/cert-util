use actix_web::{get, App, HttpServer};
use anyhow::Result;
use cert_util::{load_certs, load_pkcs8_key, load_rsa_key};
use log::LevelFilter::Trace;
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::RootCertStore;

#[get("/")]
async fn no_params() -> &'static str {
    "Hello world!\r\n"
}

#[actix_web::main]
async fn main() -> Result<()> {
    custom_utils::logger::logger_stdout(Trace);

    // let cert_chains = load_certs("certs/cert.crt")?;
    // let key = load_rsa_key("certs/cert_pri.key")?;
    let cert_chains = load_certs("ecdsa/end.fullchain")?;
    let key = load_pkcs8_key("ecdsa/end.key")?;

    let mut root_store = RootCertStore::empty();
    root_store.add(&load_certs("ecdsa/ca.cert")?.remove(0))?;
    // let cert_chains = load_certs("certs/duduwuli/www.duduwuli.cn_bundle.crt")?;
    // let key = load_rsa_key("certs/duduwuli/www.duduwuli.cn.key")?;

    let verifier = AllowAnyAuthenticatedClient::new(root_store);
    let server_conf = rustls::ServerConfig::builder()
        .with_safe_defaults()
        // .with_no_client_auth()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chains, key)?;
    HttpServer::new(|| App::new().service(no_params))
        .bind_rustls("0.0.0.0:8080", server_conf)?
        .workers(1)
        .run()
        .await?;
    Ok(())
}
