// backend/src/tls.rs
use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use std::fs;
use std::path::Path;
use std::sync::Arc;

pub async fn configure_mtls(cert_dir: &str) -> Result<RustlsConfig> {
    let ca_cert_path = Path::new(cert_dir).join("ca-cert.pem");
    let server_cert_path = Path::new(cert_dir).join("server-cert.pem");
    let server_key_path = Path::new(cert_dir).join("server-key.pem");

    let ca_cert = load_certs(&ca_cert_path)
        .context("Failed to load CA certificate")?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No CA certificate found"))?;

    let server_certs =
        load_certs(&server_cert_path).context("Failed to load server certificate")?;
    let server_key =
        load_private_key(&server_key_path).context("Failed to load server private key")?;

    let client_cert_verifier = Arc::new(MtlsClientVerifier::new(ca_cert)?);

    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(server_certs, server_key)
        .context("Failed to configure TLS")?;

    Ok(RustlsConfig::from_config(Arc::new(config)))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let pem_data = fs::read(path)
        .with_context(|| format!("Failed to read certificate file: {}", path.display()))?;

    let mut reader = std::io::BufReader::new(pem_data.as_slice());

    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificates")?;

    if certs.is_empty() {
        return Err(anyhow::anyhow!(
            "No certificates found in {}",
            path.display()
        ));
    }

    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let pem_data = fs::read(path)
        .with_context(|| format!("Failed to read private key file: {}", path.display()))?;

    let mut reader = std::io::BufReader::new(pem_data.as_slice());
    let pkcs8_keys: Vec<_> = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_default();

    if let Some(key) = pkcs8_keys.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs8(key));
    }

    let mut reader = std::io::BufReader::new(pem_data.as_slice());
    let rsa_keys: Vec<_> = rustls_pemfile::rsa_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_default();

    if let Some(key) = rsa_keys.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs1(key));
    }

    let mut reader = std::io::BufReader::new(pem_data.as_slice());
    let ec_keys: Vec<_> = rustls_pemfile::ec_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_default();

    if let Some(key) = ec_keys.into_iter().next() {
        return Ok(PrivateKeyDer::Sec1(key));
    }

    Err(anyhow::anyhow!(
        "No private key found in {}",
        path.display()
    ))
}

#[derive(Debug)]
struct MtlsClientVerifier {
    ca_cert: CertificateDer<'static>,
}

impl MtlsClientVerifier {
    fn new(ca_cert: CertificateDer<'static>) -> Result<Self> {
        Ok(Self { ca_cert })
    }
}

use x509_parser::prelude::*;

impl ClientCertVerifier for MtlsClientVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let (_, cert) = X509Certificate::from_der(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        let now_timestamp = now.as_secs();
        let not_before = cert.validity().not_before.timestamp() as u64;
        let not_after = cert.validity().not_after.timestamp() as u64;
        if now_timestamp < not_before || now_timestamp > not_after {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Expired,
            ));
        }

        let subject = cert.subject();
        let cn = subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or("unknown");

        let (_, ca_cert) = X509Certificate::from_der(self.ca_cert.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        if cert.issuer() != ca_cert.subject() {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }

        let algo_oid = &cert.signature_algorithm.algorithm;
        if algo_oid == &x509_parser::oid_registry::OID_PKCS1_SHA256WITHRSA
            || algo_oid == &x509_parser::oid_registry::OID_PKCS1_SHA384WITHRSA
            || algo_oid == &x509_parser::oid_registry::OID_PKCS1_SHA512WITHRSA
        {
        } else {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadSignature,
            ));
        }

        if !cn.starts_with("agent") {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }

        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

pub fn extract_cn_from_cert(cert: &CertificateDer) -> Result<String> {
    let (_, x509) =
        X509Certificate::from_der(cert.as_ref()).context("Failed to parse X509 certificate")?;

    let cn = x509
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .ok_or_else(|| anyhow::anyhow!("No CN found in certificate"))?;

    Ok(cn.to_string())
}
