use actix_web::{get, App, HttpServer};
use anyhow::Result;
use cert_util::{load_certs, load_rsa_key};

#[get("/")]
async fn no_params() -> &'static str {
    "Hello world!\r\n"
}

#[actix_web::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let cert_chains = load_certs("certs/localhost.crt")?;
    let key = load_rsa_key("certs/localhost_pri.key")?;
    // let cert_chains = load_certs("certs/duduwuli/www.duduwuli.cn_bundle.crt")?;
    // let key = load_rsa_key("certs/duduwuli/www.duduwuli.cn.key")?;
    let server_conf = rustls::ServerConfig::builder()
        .with_safe_defaults()
        // .with_client_cert_verifier()
        .with_no_client_auth()
        .with_single_cert(cert_chains, key)?;
    HttpServer::new(|| App::new().service(no_params))
        .bind_rustls("127.0.0.1:8080", server_conf)?
        .workers(1)
        .run()
        .await?;
    Ok(())
}
