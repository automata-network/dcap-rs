use sha2::{Digest, Sha256};
use crate::types::tcb_info::*;
use super::*;

#[test]
fn test_pod_tcb_info_v2() {
    // Load a TcbInfo from a test file
    let json = include_str!("../../../../data/tcb_info_v2.json");
    let tcb_info_and_signature: TcbInfoAndSignature = serde_json::from_str(json).unwrap();
    let original_hash = Sha256::digest(tcb_info_and_signature.tcb_info_raw.get().as_bytes());

    // Convert parsed data to TcbInfoPod
    let tcb_pod = TcbPod::try_from(tcb_info_and_signature).unwrap();
    let ret_tcb_info = TcbInfo::try_from(tcb_pod.tcb_info).unwrap();
    let ret_tcb_info_str = serde_json::to_string(&ret_tcb_info).unwrap();
    
    let ret_tcb_info_hash = Sha256::digest(&ret_tcb_info_str.as_bytes());

    assert_eq!(original_hash, ret_tcb_info_hash);
}

#[test]
fn test_pod_tcb_info_v3_sgx() {
    // Load a TcbInfo from a test file
    let json = include_str!("../../../../data/tcb_info_v3_sgx.json");
    let tcb_info_and_signature: TcbInfoAndSignature = serde_json::from_str(json).unwrap();
    let original_hash = Sha256::digest(tcb_info_and_signature.tcb_info_raw.get().as_bytes());

    // Convert parsed data to TcbInfoPod
    let tcb_pod = TcbPod::try_from(tcb_info_and_signature).unwrap();
    let ret_tcb_info = TcbInfo::try_from(tcb_pod.tcb_info).unwrap();
    let ret_tcb_info_str = serde_json::to_string(&ret_tcb_info).unwrap();
    
    let ret_tcb_info_hash = Sha256::digest(&ret_tcb_info_str.as_bytes());

    assert_eq!(original_hash, ret_tcb_info_hash);
}

#[test]
fn test_pod_tcb_info_v3_tdx() {
    // Load a TcbInfo from a test file
    let json = include_str!("../../../../data/tcb_info_v3_tdx_0.json");
    let tcb_info_and_signature: TcbInfoAndSignature = serde_json::from_str(json).unwrap();
    let original_hash = Sha256::digest(tcb_info_and_signature.tcb_info_raw.get().as_bytes());

    // Convert parsed data to TcbInfoPod
    let tcb_pod = TcbPod::try_from(tcb_info_and_signature).unwrap();
    let ret_tcb_info = TcbInfo::try_from(tcb_pod.tcb_info).unwrap();
    let ret_tcb_info_str = serde_json::to_string(&ret_tcb_info).unwrap();

    let ret_tcb_info_hash = Sha256::digest(&ret_tcb_info_str.as_bytes());

    assert_eq!(original_hash, ret_tcb_info_hash);
}