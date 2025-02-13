
use crate::types::tcbinfo::{TcbInfoV2, TcbInfoV3};
use crate::utils::crypto::verify_p256_signature_bytes;
use crate::X509Certificate;

pub fn validate_tcbinfov2(tcbinfov2: &TcbInfoV2, sgx_signing_cert: &X509Certificate, current_time: u64) -> bool {
    // get tcb_info_root time
    let issue_date = chrono::DateTime::parse_from_rfc3339(&tcbinfov2.tcb_info.issue_date).unwrap();
    let next_update_date = chrono::DateTime::parse_from_rfc3339(&tcbinfov2.tcb_info.next_update).unwrap();

    // convert the issue_date and next_update_date to seconds since epoch
    let issue_date_seconds = issue_date.timestamp() as u64;
    let next_update_seconds = next_update_date.timestamp() as u64;

    // check that the current time is between the issue_date and next_update_date
    if current_time < issue_date_seconds || current_time > next_update_seconds {
        return false;
    }

    // signature is a hex string, we'll convert it to bytes
    // ZL: we'll assume that the signature is a P256 ECDSA signature
    let tcbinfov2_signature_bytes = hex::decode(&tcbinfov2.signature).unwrap();

    // verify that the tcb_info_root is signed by the root cert
    let tcbinfov2_signature_data = serde_json::to_vec(&tcbinfov2.tcb_info).unwrap();
    verify_p256_signature_bytes(&tcbinfov2_signature_data, &tcbinfov2_signature_bytes, sgx_signing_cert.public_key().subject_public_key.as_ref())
}

pub fn validate_tcbinfov3(tcbinfov3: &TcbInfoV3, sgx_signing_cert: &X509Certificate, current_time: u64) -> bool {
    // get tcb_info_root time
    let issue_date = chrono::DateTime::parse_from_rfc3339(&tcbinfov3.tcb_info.issue_date).unwrap();
    let next_update_date = chrono::DateTime::parse_from_rfc3339(&tcbinfov3.tcb_info.next_update).unwrap();

    // convert the issue_date and next_update_date to seconds since epoch
    let issue_date_seconds = issue_date.timestamp() as u64;
    let next_update_seconds = next_update_date.timestamp() as u64;

    // check that the current time is between the issue_date and next_update_date
    if current_time < issue_date_seconds || current_time > next_update_seconds {
        assert!(false);
        return false;
    }

    // signature is a hex string, we'll convert it to bytes
    // ZL: we'll assume that the signature is a P256 ECDSA signature
    let tcbinfov3_signature_bytes = hex::decode(&tcbinfov3.signature).unwrap();

    // verify that the tcb_info_root is signed by the root cert
    let tcbinfov3_signature_data = serde_json::to_vec(&tcbinfov3.tcb_info).unwrap();
    verify_p256_signature_bytes(&tcbinfov3_signature_data, &tcbinfov3_signature_bytes, sgx_signing_cert.public_key().subject_public_key.as_ref())
}
