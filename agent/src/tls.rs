// agent/src/tls.rs - Configuration mTLS pour l'agent

use anyhow::{Context, Result};
use rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

/// Configure mTLS pour le client agent
pub fn configure_mtls(cert_dir: &str) -> Result<Arc<ClientConfig>> {
    // Chemins des fichiers
    let ca_cert_path = Path::new(cert_dir).join("ca-cert.pem");
    let client_cert_path = Path::new(cert_dir).join("agent-cert.pem");
    let client_key_path = Path::new(cert_dir).join("agent-key.pem");

    // Charger le certificat de la CA
    let ca_certs = load_certs(&ca_cert_path)
        .context("Failed to load CA certificate")?;

    // Créer un magasin de certificats racines avec notre CA
    let mut root_store = RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(&cert)
            .context("Failed to add CA certificate to root store")?;
    }

    // Charger le certificat et la clé du client
    let client_certs = load_certs(&client_cert_path)
        .context("Failed to load client certificate")?;
    let client_key = load_private_key(&client_key_path)
        .context("Failed to load client private key")?;

    // Configurer rustls avec mTLS
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)
        .context("Failed to configure client TLS")?;

    Ok(Arc::new(config))
}

/// Charge les certificats depuis un fichier PEM
fn load_certs(path: &Path) -> Result<Vec<Certificate>> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open certificate file: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let certs = certs(&mut reader)?
        .into_iter()
        .map(Certificate)
        .collect();
    Ok(certs)
}

/// Charge la clé privée depuis un fichier PEM
fn load_private_key(path: &Path) -> Result<PrivateKey> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open private key file: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let keys = pkcs8_private_keys(&mut reader)?;
    
    keys.into_iter()
        .next()
        .map(PrivateKey)
        .ok_or_else(|| anyhow::anyhow!("No private key found in file"))?
}

/// Récupère le CN depuis le certificat client pour l'identification
pub fn get_client_cn(cert_dir: &str) -> Result<String> {
    let client_cert_path = Path::new(cert_dir).join("agent-cert.pem");
    let certs = load_certs(&client_cert_path)?;
    
    if let Some(cert) = certs.first() {
        // TODO: Extraire le vrai CN du certificat
        // Pour l'instant, utiliser une valeur par défaut basée sur le nom du fichier
        if cert_dir.contains("agent2") {
            Ok("agent2".to_string())
        } else {
            Ok("agent1".to_string())
        }
    } else {
        Err(anyhow::anyhow!("No client certificate found"))
    }
}