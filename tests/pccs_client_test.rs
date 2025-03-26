use dcap_rs::{solana::{CertificateAuthority, PccsClient}, types::enclave_identity::QuotingEnclaveIdentityAndSignature};
use solana_program::pubkey::pubkey;
use x509_cert::Certificate;
use x509_cert::der::DecodePem;

#[ignore]
#[test]
fn test_get_qe_enclave_identity() {
    let pccs_client = PccsClient::new(
        "http://localhost:8899".to_string(),
        pubkey!("HKKX2jURqzmwRn2uukxab8qFWKcFBipUufQ1rRogbKhT")
    );
    let enclave_identity = pccs_client.get_qe_enclave_identity("TD_QE", 2).unwrap();
    let enclave_identity_with_signature: QuotingEnclaveIdentityAndSignature = serde_json::from_slice(&enclave_identity.data).unwrap();
    println!("enclave_identity_with_signature: {:?}", enclave_identity_with_signature);
}


#[ignore]
#[test]
fn test_get_pcs_certificate() {
    let pccs_client = PccsClient::new(
        "http://localhost:8899".to_string(),
        pubkey!("HKKX2jURqzmwRn2uukxab8qFWKcFBipUufQ1rRogbKhT")
    );
    let pcs_certificate = pccs_client.get_pcs_certificate(CertificateAuthority::SIGNING).unwrap();
    let cert = Certificate::from_pem(&pcs_certificate).unwrap();
    assert_eq!(cert.tbs_certificate.subject.to_string(), "C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Intel SGX TCB Signing");
    println!("certificate: {:?}", cert);
}
