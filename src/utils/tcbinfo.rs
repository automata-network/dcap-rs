use crate::types::tcbinfo::{TcbInfoV2, TcbInfoV3};
use crate::utils::crypto::verify_p256_signature_bytes;
use crate::X509Certificate;

use sha3::{Digest, Keccak256};

pub fn validate_tcbinfov2(
    tcbinfov2: &TcbInfoV2,
    sgx_signing_cert: &X509Certificate,
    current_time: u64,
) -> bool {
    // get tcb_info_root time
    let issue_date = chrono::DateTime::parse_from_rfc3339(&tcbinfov2.tcb_info.issue_date).unwrap();
    let next_update_date =
        chrono::DateTime::parse_from_rfc3339(&tcbinfov2.tcb_info.next_update).unwrap();

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
    verify_p256_signature_bytes(
        &tcbinfov2_signature_data,
        &tcbinfov2_signature_bytes,
        sgx_signing_cert.public_key().subject_public_key.as_ref(),
    )
}

pub fn validate_tcbinfov3(
    tcbinfov3: &TcbInfoV3,
    sgx_signing_cert: &X509Certificate,
    current_time: u64,
) -> bool {
    // get tcb_info_root time
    let issue_date = chrono::DateTime::parse_from_rfc3339(&tcbinfov3.tcb_info.issue_date).unwrap();
    let next_update_date =
        chrono::DateTime::parse_from_rfc3339(&tcbinfov3.tcb_info.next_update).unwrap();

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
    verify_p256_signature_bytes(
        &tcbinfov3_signature_data,
        &tcbinfov3_signature_bytes,
        sgx_signing_cert.public_key().subject_public_key.as_ref(),
    )
}

// A content_hash is the hash representation of tcb_info
// excluding both "issue_date" and "next_update" fields
// integers are big-endian encoded

pub fn get_tcbinfov2_content_hash(tcbinfov2: &TcbInfoV2) -> [u8; 32] {
    let mut pre_image: Vec<u8> = vec![];

    pre_image.extend_from_slice(&[tcbinfov2.tcb_info.tcb_type]);
    pre_image.extend_from_slice(&[tcb_id_string_to_u8("SGX")]); // SGX by default for V2
    pre_image.extend_from_slice(&tcbinfov2.tcb_info.version.to_be_bytes());
    pre_image.extend_from_slice(&tcbinfov2.tcb_info.tcb_evaluation_data_number.to_be_bytes());
    pre_image.extend_from_slice(hex::decode(&tcbinfov2.tcb_info.fmspc).unwrap().as_slice());
    pre_image.extend_from_slice(hex::decode(&tcbinfov2.tcb_info.pce_id).unwrap().as_slice());
    pre_image.extend_from_slice(
        serde_json::to_vec(&tcbinfov2.tcb_info.tcb_levels)
            .unwrap()
            .as_slice(),
    );

    Keccak256::digest(&pre_image).try_into().unwrap()
}

pub fn get_tcbinfov3_content_hash(tcbinfov3: &TcbInfoV3) -> [u8; 32] {
    let mut pre_image: Vec<u8> = vec![];

    pre_image.extend_from_slice(&[tcbinfov3.tcb_info.tcb_type]);
    pre_image.extend_from_slice(&[tcb_id_string_to_u8(&tcbinfov3.tcb_info.id)]); // SGX by default for V2
    pre_image.extend_from_slice(&tcbinfov3.tcb_info.version.to_be_bytes());
    pre_image.extend_from_slice(&tcbinfov3.tcb_info.tcb_evaluation_data_number.to_be_bytes());
    pre_image.extend_from_slice(hex::decode(&tcbinfov3.tcb_info.fmspc).unwrap().as_slice());
    pre_image.extend_from_slice(hex::decode(&tcbinfov3.tcb_info.pce_id).unwrap().as_slice());
    pre_image.extend_from_slice(
        serde_json::to_vec(&tcbinfov3.tcb_info.tcb_levels)
            .unwrap()
            .as_slice(),
    );

    if let Some(tdx_module) = &tcbinfov3.tcb_info.tdx_module {
        pre_image.extend_from_slice(serde_json::to_vec(tdx_module).unwrap().as_slice());
    }

    if let Some(tdx_module_identities) = &tcbinfov3.tcb_info.tdx_module_identities {
        pre_image.extend_from_slice(
            serde_json::to_vec(tdx_module_identities)
                .unwrap()
                .as_slice(),
        );
    }

    Keccak256::digest(&pre_image).try_into().unwrap()
}

fn tcb_id_string_to_u8(tcb_id: &str) -> u8 {
    match tcb_id {
        "SGX" => 0,
        "TDX" => 1,
        _ => panic!("Unknown TCB_ID"),
    }
}
