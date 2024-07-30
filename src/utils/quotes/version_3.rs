use crate::types::quotes::{body::QuoteBody, version_3::QuoteV3};
use crate::types::{
    collaterals::IntelCollateral,
    tcbinfo::{TcbInfo, TcbInfoV2},
    VerifiedOutput,
    TcbStatus
};
use crate::utils::cert::get_sgx_fmspc_tcbstatus_v2;

use super::{check_quote_header, common_verify_and_fetch_tcb, converge_tcb_status_with_qe_tcb};

pub fn verify_quote_dcapv3(
    quote: &QuoteV3,
    collaterals: &IntelCollateral,
    current_time: u64,
) -> VerifiedOutput {
    assert!(check_quote_header(&quote.header, 3), "invalid quote header");

    let quote_body = QuoteBody::SGXQuoteBody(quote.isv_enclave_report);
    let (qe_tcb_status, sgx_extensions, tcb_info) = common_verify_and_fetch_tcb(
        &quote.header,
        &quote_body,
        &quote.signature.isv_enclave_report_signature,
        &quote.signature.ecdsa_attestation_key,
        &quote.signature.qe_report,
        &quote.signature.qe_report_signature,
        &quote.signature.qe_auth_data.data,
        &quote.signature.qe_cert_data,
        collaterals,
        current_time,
    );

    let tcb_info_v2: TcbInfoV2;
    if let TcbInfo::V2(tcb) = tcb_info {
        tcb_info_v2 = tcb;
    } else {
        panic!("TcbInfo must be V2!");
    }
    let mut tcb_status = get_sgx_fmspc_tcbstatus_v2(&sgx_extensions, &tcb_info_v2);

    assert!(
        tcb_status != TcbStatus::TcbRevoked,
        "FMSPC TCB Revoked"
    );

    tcb_status = converge_tcb_status_with_qe_tcb(tcb_status, qe_tcb_status);

    VerifiedOutput {
        quote_version: quote.header.version,
        tee_type: quote.header.tee_type,
        tcb_status,
        fmspc: sgx_extensions.fmspc,
        quote_body: quote_body,
    }
}
