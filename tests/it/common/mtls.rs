// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Throwaway mTLS material for federation transport integration tests.

use std::io::Write;

/// Generates a throwaway CA + leaf cert/key (ServerAuth + ClientAuth EKU,
/// SAN `localhost`) written to temp files. The leaf doubles as the
/// listener's server identity and the connecting peer's client identity.
#[allow(dead_code)]
pub fn generate_mtls_certs() -> (
    tempfile::NamedTempFile,
    tempfile::NamedTempFile,
    tempfile::NamedTempFile,
) {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
    };

    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_params = CertificateParams::default();
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "Test CA");
    ca_params.distinguished_name = ca_dn;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut leaf_params = CertificateParams::default();
    let mut leaf_dn = DistinguishedName::new();
    leaf_dn.push(DnType::CommonName, "test-relay");
    leaf_params.distinguished_name = leaf_dn;
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
    leaf_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_issuer).unwrap();

    let mut ca_file = tempfile::NamedTempFile::new().unwrap();
    ca_file.write_all(ca_cert.pem().as_bytes()).unwrap();
    let mut cert_file = tempfile::NamedTempFile::new().unwrap();
    cert_file.write_all(leaf_cert.pem().as_bytes()).unwrap();
    let mut key_file = tempfile::NamedTempFile::new().unwrap();
    key_file
        .write_all(leaf_key.serialize_pem().as_bytes())
        .unwrap();
    (ca_file, cert_file, key_file)
}
