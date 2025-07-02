use std::time::{Duration, SystemTime};

use x509_cert::{crl::CertificateList, der::Decode};

use dcap_rs::types::tcb_info::TcbInfoAndSignature;
use dcap_rs::{
    types::enclave_identity::QuotingEnclaveIdentityAndSignature, 
    utils::cert_chain_processor,
    types::{collateral::Collateral, quote::Quote},
};

pub fn sgx_quote_data() -> (Collateral, Quote<'static>) {
    let collateral = include_str!("../../data/full_collateral_sgx.json");
    let collateral: Collateral = serde_json::from_str(collateral).unwrap();
    let quote = include_bytes!("../../data/quote_sgx.bin");
    let quote = Quote::read(&mut quote.as_slice()).unwrap();
    (collateral, quote)
}

pub fn tdx_quote_data() -> (Collateral, Quote<'static>) {
    let quote = include_bytes!("../../data/quote_tdx.bin");
    let quote = Quote::read(&mut quote.as_slice()).unwrap();

    let tcb_info_and_qe_identity_issuer_chain = include_bytes!("../../data/signing_cert.pem");
    let tcb_info_and_qe_identity_issuer_chain =
        cert_chain_processor::load_pem_chain_bpf_friendly(tcb_info_and_qe_identity_issuer_chain)
            .unwrap();

    let root_ca_crl = include_bytes!("../../data/intel_root_ca_crl.der");
    let root_ca_crl = CertificateList::from_der(root_ca_crl).unwrap();

    let tcb_info = include_bytes!("../../data/tcb_info_v3_with_tdx_module.json");
    let tcb_info: TcbInfoAndSignature = serde_json::from_slice(tcb_info).unwrap();

    let qe_identity = include_bytes!("../../data/qeidentityv2_apiv4.json");
    let qe_identity: QuotingEnclaveIdentityAndSignature =
        serde_json::from_slice(qe_identity).unwrap();

    let platform_ca_crl = include_bytes!("../../data/pck_platform_crl.der");
    let platform_ca_crl = CertificateList::from_der(platform_ca_crl).unwrap();

    let collateral = Collateral {
        tcb_info_and_qe_identity_issuer_chain,
        root_ca_crl,
        pck_crl: platform_ca_crl,
        tcb_info,
        qe_identity,
    };
    (collateral, quote)
}

pub fn tdx_quote_v5_data() -> (Collateral, Quote<'static>) {
    let quote = include_bytes!("../../data/v5/alibaba_quote_5.dat");
    let quote = Quote::read(&mut quote.as_slice()).unwrap();

    let collateral = Collateral::new(
        include_bytes!("../../data/intel_root_ca_crl.der"),
        include_bytes!("../../data/pck_platform_crl.der"),
        include_bytes!("../../data/v5/signing_cert.pem"),
        include_str!("../../data/v5/tcbinfov3_90C06F000000.json"),
        include_str!("../../data/v5/qe_td.json"),
    )
    .expect("Failed to load collaterals");

    (collateral, quote)
}

pub fn test_sgx_time() -> SystemTime {
    // Aug 29th 4:20pm, ~24 hours after quote was generated
    SystemTime::UNIX_EPOCH + Duration::from_secs(1724962800)
}

pub fn test_tdx_time() -> SystemTime {
    // Pinned September 10th, 2024, 6:49am GMT
    SystemTime::UNIX_EPOCH + Duration::from_secs(1725950994)
}

pub fn test_tdx_v5_time() -> SystemTime {
    // June 15th, 2025, 12am UTC
    SystemTime::UNIX_EPOCH + Duration::from_secs(1749945600)
}
