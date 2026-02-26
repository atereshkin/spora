use rcgen::{
    CertificateParams, DistinguishedName, DnType, IsCa, BasicConstraints,
    KeyPair, KeyUsagePurpose, SanType,
};
use std::fs;

fn main() {
    let out_dir = "certs";
    fs::create_dir_all(out_dir).expect("failed to create certs directory");

    // --- CA ---
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.distinguished_name.push(DnType::CommonName, "Spora CA");
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    ca_params.key_usages.push(KeyUsagePurpose::CrlSign);

    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("failed to generate CA key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("failed to self-sign CA cert");

    fs::write(format!("{}/ca.der", out_dir), ca_cert.der()).expect("failed to write ca.der");
    println!("Wrote {}/ca.der", out_dir);

    // --- Relay ---
    let mut relay_params = CertificateParams::default();
    relay_params.distinguished_name = DistinguishedName::new();
    relay_params.distinguished_name.push(DnType::CommonName, "Spora Relay");
    relay_params.subject_alt_names.push(SanType::DnsName("relay.spora.dev".try_into().unwrap()));

    let relay_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("failed to generate relay key");
    let relay_cert = relay_params.signed_by(&relay_key, &ca_cert, &ca_key).expect("failed to sign relay cert");

    fs::write(format!("{}/relay_cert.der", out_dir), relay_cert.der()).expect("failed to write relay_cert.der");
    fs::write(format!("{}/relay_key.der", out_dir), relay_key.serialize_der()).expect("failed to write relay_key.der");
    println!("Wrote {}/relay_cert.der", out_dir);
    println!("Wrote {}/relay_key.der", out_dir);

    // Also copy ca.der to relay-client for embedding
    fs::copy(format!("{}/ca.der", out_dir), "relay-client/ca.der").expect("failed to copy ca.der to relay-client");
    println!("Copied ca.der to relay-client/ca.der");
}
