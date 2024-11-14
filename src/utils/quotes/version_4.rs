use crate::constants::SGX_TEE_TYPE;
use crate::types::quotes::body::QuoteBody;
use crate::types::quotes::{version_4::QuoteV4, CertDataType};
use crate::types::TcbStatus;
use crate::types::{
    tcbinfo::{TcbInfo, TcbInfoV3},
    collaterals::IntelCollateral, VerifiedOutput,
};
use crate::utils::cert::get_sgx_tdx_fmspc_tcbstatus_v3;
use crate::utils::tdx_module::{
    converge_tcb_status_with_tdx_module_tcb, get_tdx_module_identity_and_tcb,
};

use super::{check_quote_header, common_verify_and_fetch_tcb, converge_tcb_status_with_qe_tcb};

pub fn verify_quote_dcapv4(
    quote: &QuoteV4,
    collaterals: &IntelCollateral,
    current_time: u64,
) -> VerifiedOutput {
    assert!(check_quote_header(&quote.header, 4), "invalid quote header");

    // we'll now proceed to verify the qe
    let qe_cert_data_v4 = &quote.signature.qe_cert_data;

    // right now we just handle type 6, which contains the QEReport, QEReportSignature, QEAuthData and another CertData
    let qe_report_cert_data = if let CertDataType::QeReportCertData(qe_report_cert_data) =
        qe_cert_data_v4.get_cert_data()
    {
        qe_report_cert_data
    } else {
        panic!("Unsupported CertDataType in QuoteSignatureDataV4");
    };

    let (qe_tcb_status, sgx_extensions, tcb_info) = common_verify_and_fetch_tcb(
        &quote.header,
        &quote.quote_body,
        &quote.signature.quote_signature,
        &quote.signature.ecdsa_attestation_key,
        &qe_report_cert_data.qe_report,
        &qe_report_cert_data.qe_report_signature,
        &qe_report_cert_data.qe_auth_data.data,
        &qe_report_cert_data.qe_cert_data,
        collaterals,
        current_time,
    );

    let tcb_info_v3: TcbInfoV3;
    if let TcbInfo::V3(tcb) = tcb_info {
        tcb_info_v3 = tcb;
    } else {
        panic!("TcbInfo must be V3!");
    }

    let (quote_tdx_body, tee_tcb_svn) = if let QuoteBody::TD10QuoteBody(body) = &quote.quote_body {
        (Some(body), body.tee_tcb_svn)
    } else {
        // SGX does not produce tee_tcb_svns
        (None, [0; 16])
    };

    let tee_type = quote.header.tee_type;
    let (sgx_tcb_status, tdx_tcb_status, advisory_ids) =
        get_sgx_tdx_fmspc_tcbstatus_v3(tee_type, &sgx_extensions, &tee_tcb_svn, &tcb_info_v3);
    
    assert!(
        sgx_tcb_status != TcbStatus::TcbRevoked || tdx_tcb_status != TcbStatus::TcbRevoked,
        "FMSPC TCB Revoked"
    );
    
    let mut tcb_status: TcbStatus;
    if quote.header.tee_type == SGX_TEE_TYPE {
        tcb_status = sgx_tcb_status;
    } else {
        tcb_status = tdx_tcb_status;

        // Fetch TDXModule TCB and TDXModule Identity
        let (tdx_module_tcb_status, tdx_module_mrsigner, tdx_module_attributes) =
            get_tdx_module_identity_and_tcb(&tee_tcb_svn, &tcb_info_v3);

        assert!(
            tdx_module_tcb_status != TcbStatus::TcbRevoked,
            "TDX Module TCB Revoked"
        );

        // check TDX module
        let (tdx_report_mrsigner, tdx_report_attributes) = if let Some(tdx_body) = quote_tdx_body {
            (tdx_body.mrsignerseam, tdx_body.seam_attributes)
        } else {
            unreachable!();
        };

        let mr_signer_matched = tdx_module_mrsigner == tdx_report_mrsigner;
        let attributes_matched = tdx_module_attributes == tdx_report_attributes;
        assert!(
            mr_signer_matched && attributes_matched,
            "TDX module values mismatch"
        );

        tcb_status = converge_tcb_status_with_tdx_module_tcb(tcb_status, tdx_module_tcb_status)
    }

    tcb_status = converge_tcb_status_with_qe_tcb(tcb_status, qe_tcb_status);

    VerifiedOutput {
        quote_version: quote.header.version,
        tee_type: quote.header.tee_type,
        tcb_status,
        fmspc: sgx_extensions.fmspc,
        quote_body: quote.quote_body,
        advisory_ids: advisory_ids
    }
}
