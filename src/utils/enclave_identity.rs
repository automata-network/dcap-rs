use crate::types::{enclave_identity::EnclaveIdentityV2, quotes::body::EnclaveReport, TcbStatus};
use crate::utils::crypto::verify_p256_signature_bytes;
use sha3::{Digest, Keccak256};

use crate::X509Certificate;

pub fn validate_enclave_identityv2(
    enclave_identityv2: &EnclaveIdentityV2,
    sgx_signing_pubkey: &X509Certificate,
    current_time: u64,
) -> bool {
    // get tcb_info_root time
    let issue_date =
        chrono::DateTime::parse_from_rfc3339(&enclave_identityv2.enclave_identity.issue_date)
            .unwrap();
    let next_update_date =
        chrono::DateTime::parse_from_rfc3339(&enclave_identityv2.enclave_identity.next_update)
            .unwrap();

    // convert the issue_date and next_update_date to seconds since epoch
    let issue_date_seconds = issue_date.timestamp() as u64;
    let next_update_seconds = next_update_date.timestamp() as u64;

    // check that the current time is between the issue_date and next_update_date
    if current_time < issue_date_seconds || current_time > next_update_seconds {
        return false;
    }

    // signature is a hex string, we'll convert it to bytes
    // ZL: we'll assume that the signature is a P256 ECDSA signature
    let enclave_identityv2_signature_bytes = hex::decode(&enclave_identityv2.signature).unwrap();

    // verify that the enclave_identity_root is signed by the root cert
    let enclave_identityv2_signature_data =
        serde_json::to_vec(&enclave_identityv2.enclave_identity).unwrap();
    verify_p256_signature_bytes(
        &enclave_identityv2_signature_data,
        &enclave_identityv2_signature_bytes,
        sgx_signing_pubkey.public_key().subject_public_key.as_ref(),
    )
}

pub fn get_qe_tcbstatus(
    enclave_report: &EnclaveReport,
    qeidentityv2: &EnclaveIdentityV2,
) -> TcbStatus {
    for tcb_level in qeidentityv2.enclave_identity.tcb_levels.iter() {
        if tcb_level.tcb.isvsvn <= enclave_report.isv_svn {
            let tcb_status = match &tcb_level.tcb_status[..] {
                "UpToDate" => TcbStatus::OK,
                "SWHardeningNeeded" => TcbStatus::TcbSwHardeningNeeded,
                "ConfigurationAndSWHardeningNeeded" => {
                    TcbStatus::TcbConfigurationAndSwHardeningNeeded
                }
                "ConfigurationNeeded" => TcbStatus::TcbConfigurationNeeded,
                "OutOfDate" => TcbStatus::TcbOutOfDate,
                "OutOfDateConfigurationNeeded" => TcbStatus::TcbOutOfDateConfigurationNeeded,
                "Revoked" => TcbStatus::TcbRevoked,
                _ => TcbStatus::TcbUnrecognized,
            };
            return tcb_status;
        }
    }

    TcbStatus::TcbUnrecognized
}

// A content_hash is the hash representation of the enclave_identity
// excluding both "issue_date" and "next_update" fields
// integers are big-endian encoded
pub fn get_enclave_identityv2_content_hash(enclave_identityv2: &EnclaveIdentityV2) -> [u8; 32] {
    let mut pre_image: Vec<u8> = vec![];
    pre_image.extend_from_slice(&[convert_enclave_identity_id_string_to_u8(
        &enclave_identityv2.enclave_identity.id,
    )]);
    pre_image.extend_from_slice(&enclave_identityv2.enclave_identity.version.to_be_bytes());
    pre_image.extend_from_slice(
        &enclave_identityv2
            .enclave_identity
            .tcb_evaluation_data_number
            .to_be_bytes(),
    );
    pre_image.extend_from_slice(
        hex::decode(&enclave_identityv2.enclave_identity.miscselect)
            .unwrap()
            .as_slice(),
    );
    pre_image.extend_from_slice(
        hex::decode(&enclave_identityv2.enclave_identity.miscselect_mask)
            .unwrap()
            .as_slice(),
    );
    pre_image.extend_from_slice(
        hex::decode(&enclave_identityv2.enclave_identity.attributes)
            .unwrap()
            .as_slice(),
    );
    pre_image.extend_from_slice(
        hex::decode(&enclave_identityv2.enclave_identity.attributes_mask)
            .unwrap()
            .as_slice(),
    );
    pre_image.extend_from_slice(
        hex::decode(&enclave_identityv2.enclave_identity.mrsigner)
            .unwrap()
            .as_slice(),
    );
    pre_image.extend_from_slice(&enclave_identityv2.enclave_identity.isvprodid.to_be_bytes());
    pre_image.extend_from_slice(
        serde_json::to_vec(&enclave_identityv2.enclave_identity.tcb_levels)
            .unwrap()
            .as_slice(),
    );
    Keccak256::digest(&pre_image).try_into().unwrap()
}

fn convert_enclave_identity_id_string_to_u8(id_str: &str) -> u8 {
    match id_str {
        "QE" => 0,
        "QVE" => 1,
        "TD_QE" => 2,
        _ => panic!("Unknown enclave_identity id string"),
    }
}
