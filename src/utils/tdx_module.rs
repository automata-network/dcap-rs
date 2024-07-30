use crate::types::tcbinfo::TcbInfoV3;
use crate::types::TcbStatus;

// https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/Checks/TdxModuleCheck.cpp#L62-L97
pub fn get_tdx_module_identity_and_tcb(
    tee_tcb_svn: &[u8; 16],
    tcb_info_v3: &TcbInfoV3,
) -> (TcbStatus, [u8; 48], u64) {
    let tdx_module = if let Some(tdx_module_obj) = &tcb_info_v3.tcb_info.tdx_module {
        tdx_module_obj
    } else {
        panic!("TDX module not found");
    };

    let tdx_module_isv_svn = tee_tcb_svn[0];
    let tdx_module_version = tee_tcb_svn[1];

    if tdx_module_version == 0 {
        let mut mrsigner: [u8; 48] = [0; 48];
        mrsigner.copy_from_slice(&hex::decode(&tdx_module.mrsigner).unwrap());

        return (
            TcbStatus::OK,
            mrsigner,
            from_str_to_u64(tdx_module.attributes.as_str()),
        );
    }

    let tdx_module_identity_id = format!("TDX_{:02x}", tdx_module_version);
    if let Some(tdx_module_identities) = &tcb_info_v3.tcb_info.tdx_module_identities {
        for tdx_module_identity in tdx_module_identities.iter() {
            if tdx_module_identity.id == tdx_module_identity_id {
                for tcb_level in &tdx_module_identity.tcb_levels {
                    if tdx_module_isv_svn >= tcb_level.tcb.isvsvn {
                        let mut mrsigner: [u8; 48] = [0; 48];
                        mrsigner
                            .copy_from_slice(&hex::decode(&tdx_module_identity.mrsigner).unwrap());
                        let attributes = &tdx_module_identity.attributes;
                        let tcb_status = TcbStatus::from_str(tcb_level.tcb_status.as_str());
                        return (tcb_status, mrsigner, from_str_to_u64(attributes.as_str()));
                    }
                }
            }
        }
    } else {
        panic!("TDX module identities not found");
    }

    panic!("TDX Module could not match to any TCB Level for TSX Module ISVSN: {}", tdx_module_isv_svn);
}

// https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/Checks/TdxModuleCheck.cpp#L99-L137
pub fn converge_tcb_status_with_tdx_module_tcb(
    tcb_status: TcbStatus,
    tdx_module_tcb_status: TcbStatus,
) -> TcbStatus {
    let converged_tcb_status: TcbStatus;
    match tdx_module_tcb_status {
        TcbStatus::TcbOutOfDate => {
            if tcb_status == TcbStatus::OK || tcb_status == TcbStatus::TcbSwHardeningNeeded {
                converged_tcb_status = TcbStatus::TcbOutOfDate;
            } else if tcb_status == TcbStatus::TcbConfigurationNeeded
                || tcb_status == TcbStatus::TcbConfigurationAndSwHardeningNeeded
            {
                converged_tcb_status = TcbStatus::TcbOutOfDateConfigurationNeeded;
            } else {
                converged_tcb_status = tcb_status;
            }
        },
        _ => {
            converged_tcb_status = tcb_status;
        }
    }
    converged_tcb_status
}

fn from_str_to_u64(str: &str) -> u64 {
    assert!(str.len() == 16, "invalid u64 str length");

    match u64::from_str_radix(str, 16) {
        Ok(ret) => ret,
        Err(_) => panic!("Invalid hex character found"),
    }
}
