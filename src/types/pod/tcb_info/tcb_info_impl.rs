use super::*;
use crate::types::tcb_info::*;

impl TryFrom<TcbInfoAndSignature> for TcbPod {
    type Error = &'static str;

    fn try_from(
        tcb_info_json_parsed: TcbInfoAndSignature,
    ) -> std::result::Result<Self, Self::Error> {
        let tcb_info = TcbInfoPod::try_from(tcb_info_json_parsed.get_tcb_info().unwrap())?;
        let mut signature: [u8; 64] = [0; 64];
        signature.copy_from_slice(&tcb_info_json_parsed.signature);

        Ok(TcbPod {
            tcb_info,
            signature, // Placeholder for signature
        })
    }
}

impl TryFrom<TcbInfo> for TcbInfoPod {
    type Error = &'static str;

    fn try_from(tcb_info: TcbInfo) -> std::result::Result<Self, Self::Error> {
        // Convert pceid
        let mut pceid = [0u8; 4];
        let pceid_bytes = tcb_info.pce_id.as_bytes();
        if pceid_bytes.len() > 4 {
            return Err("PCE ID too long for fixed-size array");
        }
        pceid[..pceid_bytes.len()].copy_from_slice(pceid_bytes);

        // Convert id
        let mut id = [0u8; 6];
        let tcb_id = tcb_info.id;
        let id_bytes = match tcb_id {
            Some(ref id) => id.as_bytes(),
            None => b"",
        };
        id[..id_bytes.len()].copy_from_slice(id_bytes);

        // Convert fmspc
        let mut fmspc = [0u8; 12];
        let fmspc_bytes = tcb_info.fmspc.as_bytes();
        if fmspc_bytes.len() > 12 {
            return Err("FMSPC too long for fixed-size array");
        }
        fmspc[..fmspc_bytes.len()].copy_from_slice(fmspc_bytes);

        // Convert version
        let version = u32::from(tcb_info.version);

        // Convert timestamps
        let issued_timestamp = tcb_info.issue_date.timestamp() as u64;
        let next_update_timestamp = tcb_info.next_update.timestamp() as u64;

        // Convert tdx_module
        let tdx_module = match tcb_info.tdx_module {
            Some(tdx_module) => TdxModulePod::try_from(tdx_module)?,
            None => TdxModulePod {
                mrsigner_hex: [0u8; 96],
                attributes_hex: [0u8; 16],
                attributes_mask_hex: [0u8; 16],
            },
        };

        // Convert tdx_module_identities
        let mut tdx_module_identities = [TdxModuleIdentityPod {
            id: [0u8; 12],
            mrsigner_hex: [0u8; 96],
            _pad: [0u8; 4],
            attributes_hex: [0u8; 16],
            attributes_mask_hex: [0u8; 16],
            tcb_levels: [TdxTcbLevelPod {
                tcb_isvsvn: 0,
                tcb_status: 0,
                _pad: [0u8; 6],
                tcb_date: 0,
                advisory_ids: [[0u8; 32]; MAX_ADVISORY_IDS_SIZE],
            }; TDX_MODULE_TCB_MAX_LEVEL_SIZE],
        }; TDX_MODULE_TCB_MAX_LEVEL_SIZE];

        if let Some(identities) = tcb_info.tdx_module_identities {
            let len = identities.len();
            if len > TDX_MODULE_TCB_MAX_LEVEL_SIZE {
                return Err("TDX Module Identities exceeded TDX_MODULE_TCB_MAX_LEVEL_SIZE");
            }
            let len = identities.len().min(TDX_MODULE_TCB_MAX_LEVEL_SIZE);
            for (i, identity) in identities.into_iter().take(len).enumerate() {
                tdx_module_identities[i] = TdxModuleIdentityPod::try_from(identity)?;
            }
        }

        // Convert tcb_levels
        let mut tcb_levels = [TcbLevelPod {
            tcb_status: 0,
            _pad0: 0,
            pce_svn: 0,
            _pad1: [0u8; 4],
            tcb_date: 0,
            sgx_tcb_components: [TcbComponent {
                cpusvn: 0,
                category: [0u8; 16],
                component_type: [0u8; 64],
            }; 16],
            tdx_tcb_components: [TcbComponent {
                cpusvn: 0,
                category: [0u8; 16],
                component_type: [0u8; 64],
            }; 16],
            advisory_ids: [[0u8; 32]; MAX_ADVISORY_IDS_SIZE],
        }; TCB_MAX_LEVEL_SIZE];

        let len = tcb_info.tcb_levels.len();
        if len > TCB_MAX_LEVEL_SIZE {
            return Err("TCB Levels exceeded TCB_MAX_LEVEL_SIZE");
        }

        let len = tcb_info.tcb_levels.len().min(TCB_MAX_LEVEL_SIZE);
        for (i, level) in tcb_info.tcb_levels.into_iter().take(len).enumerate() {
            tcb_levels[i] = TcbLevelPod::try_from(level)?;
        }

        Ok(TcbInfoPod {
            pceid_hex: pceid,
            id,
            fmspc_hex: fmspc,
            tcb_type: tcb_info.tcb_type, // Treating as non-private
            _pad0: 0,
            version,
            _pad1: [0u8; 4],
            issued_timestamp,
            next_update_timestamp,
            tcb_evaluation_data_number: tcb_info.tcb_evaluation_data_number, // Treating as non-private
            _pad2: [0u8; 4],
            tdx_module,
            tdx_module_identities,
            tcb_levels,
        })
    }
}

impl TryFrom<TcbInfoPod> for TcbInfo {
    type Error = &'static str;

    fn try_from(tcb_info_pod: TcbInfoPod) -> std::result::Result<Self, Self::Error> {
        // Convert pceid
        let null_pos = tcb_info_pod
            .pceid_hex
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(tcb_info_pod.pceid_hex.len());
        let pce_id = String::from_utf8(tcb_info_pod.pceid_hex[..null_pos].to_vec())
            .map_err(|_| "Invalid UTF-8 in PCE ID")?;

        // Convert id
        let null_pos = tcb_info_pod
            .id
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(tcb_info_pod.id.len());
        let id = if null_pos > 0 {
            Some(
                String::from_utf8(tcb_info_pod.id[..null_pos].to_vec())
                    .map_err(|_| "Invalid UTF-8 in ID")?,
            )
        } else {
            None
        };

        // Convert fmspc
        let null_pos = tcb_info_pod
            .fmspc_hex
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(tcb_info_pod.fmspc_hex.len());
        let fmspc = String::from_utf8(tcb_info_pod.fmspc_hex[..null_pos].to_vec())
            .map_err(|_| "Invalid UTF-8 in FMSPC")?;

        // Convert version
        let version = TcbInfoVersion::try_from(tcb_info_pod.version)?;

        // Convert timestamps
        let issue_date = chrono::DateTime::<chrono::Utc>::from_timestamp(
            tcb_info_pod.issued_timestamp as i64,
            0,
        )
        .ok_or("Invalid issue date timestamp")?;
        let next_update = chrono::DateTime::<chrono::Utc>::from_timestamp(
            tcb_info_pod.next_update_timestamp as i64,
            0,
        )
        .ok_or("Invalid next update timestamp")?;

        // Convert tdx_module
        let tdx_module = if !tdx_module_is_empty(&tcb_info_pod.tdx_module) {
            Some(TdxModule::try_from(tcb_info_pod.tdx_module)?)
        } else {
            None
        };

        // Convert tdx_module_identities
        let tdx_module_identities =
            if tdx_module_identities_has_data(&tcb_info_pod.tdx_module_identities) {
                let mut identities = Vec::with_capacity(TDX_MODULE_TCB_MAX_LEVEL_SIZE);
                for identity_pod in tcb_info_pod.tdx_module_identities.iter() {
                    if !tdx_module_identity_is_empty(identity_pod) {
                        identities.push(TdxModuleIdentity::try_from(*identity_pod)?);
                    }
                }
                if identities.is_empty() {
                    None
                } else {
                    Some(identities)
                }
            } else {
                None
            };

        // Convert tcb_levels
        let mut tcb_levels = Vec::with_capacity(TCB_MAX_LEVEL_SIZE);
        for level_pod in tcb_info_pod.tcb_levels.iter() {
            if level_pod.tcb_date > 0 {
                tcb_levels.push(TcbLevel::try_from(*level_pod)?);
            }
        }

        Ok(TcbInfo {
            id,
            version,
            issue_date,
            next_update,
            fmspc,
            pce_id,
            tcb_type: tcb_info_pod.tcb_type,
            tcb_evaluation_data_number: tcb_info_pod.tcb_evaluation_data_number,
            tdx_module,
            tdx_module_identities,
            tcb_levels,
        })
    }
}

// Helper function to check if a TdxModulePod is empty (all zeros)
fn tdx_module_is_empty(module: &TdxModulePod) -> bool {
    module.mrsigner_hex.iter().all(|&b| b == 0)
        && module.attributes_hex.iter().all(|&b| b == 0)
        && module.attributes_mask_hex.iter().all(|&b| b == 0)
}

// Helper function to check if any TdxModuleIdentityPod has data
fn tdx_module_identities_has_data(identities: &[TdxModuleIdentityPod; TDX_MODULE_TCB_MAX_LEVEL_SIZE]) -> bool {
    identities
        .iter()
        .any(|identity| !tdx_module_identity_is_empty(identity))
}

// Helper function to check if a TdxModuleIdentityPod is empty
fn tdx_module_identity_is_empty(identity: &TdxModuleIdentityPod) -> bool {
    identity.id.iter().all(|&b| b == 0)
        && identity.mrsigner_hex.iter().all(|&b| b == 0)
        && identity.attributes_hex.iter().all(|&b| b == 0)
        && identity.attributes_mask_hex.iter().all(|&b| b == 0)
}

impl TryFrom<TdxModule> for TdxModulePod {
    type Error = &'static str;

    fn try_from(tdx_module: TdxModule) -> std::result::Result<Self, Self::Error> {
        // Convert mrsigner
        let mut mrsigner = [0u8; 96];
        let mrsigner_bytes = tdx_module.mrsigner.as_bytes();
        if mrsigner_bytes.len() > 96 {
            return Err("mrsigner too long for fixed-size array");
        }
        mrsigner[..mrsigner_bytes.len()].copy_from_slice(mrsigner_bytes);

        // Convert attributes
        let mut attributes = [0u8; 16];
        let attributes_bytes = tdx_module.attributes.as_bytes();
        if attributes_bytes.len() > 16 {
            return Err("attributes too long for fixed-size array");
        }
        attributes[..attributes_bytes.len()].copy_from_slice(attributes_bytes);

        // Convert attributes_mask
        let mut attributes_mask = [0u8; 16];
        let attributes_mask_bytes = tdx_module.attributes_mask.as_bytes();
        if attributes_mask_bytes.len() > 16 {
            return Err("attributes_mask too long for fixed-size array");
        }
        attributes_mask[..attributes_mask_bytes.len()].copy_from_slice(attributes_mask_bytes);

        Ok(TdxModulePod {
            mrsigner_hex: mrsigner,
            attributes_hex: attributes,
            attributes_mask_hex: attributes_mask,
        })
    }
}

impl TryFrom<TdxModulePod> for TdxModule {
    type Error = &'static str;

    fn try_from(tdx_module_pod: TdxModulePod) -> std::result::Result<Self, Self::Error> {
        // Convert mrsigner
        let null_pos = tdx_module_pod
            .mrsigner_hex
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(tdx_module_pod.mrsigner_hex.len());
        let mrsigner = String::from_utf8(tdx_module_pod.mrsigner_hex[..null_pos].to_vec())
            .map_err(|_| "Invalid UTF-8 in mrsigner")?;

        // Convert attributes
        let null_pos = tdx_module_pod
            .attributes_hex
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(tdx_module_pod.attributes_hex.len());
        let attributes = String::from_utf8(tdx_module_pod.attributes_hex[..null_pos].to_vec())
            .map_err(|_| "Invalid UTF-8 in attributes")?;

        // Convert attributes_mask
        let null_pos = tdx_module_pod
            .attributes_mask_hex
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(tdx_module_pod.attributes_mask_hex.len());
        let attributes_mask =
            String::from_utf8(tdx_module_pod.attributes_mask_hex[..null_pos].to_vec())
                .map_err(|_| "Invalid UTF-8 in attributes_mask")?;

        Ok(TdxModule {
            mrsigner,
            attributes,
            attributes_mask,
        })
    }
}

impl TryFrom<TdxModuleIdentity> for TdxModuleIdentityPod {
    type Error = &'static str;

    fn try_from(tdx_module_identity: TdxModuleIdentity) -> std::result::Result<Self, Self::Error> {
        // Convert id
        let mut id = [0u8; 12];
        let id_bytes = tdx_module_identity.id.as_bytes();
        if id_bytes.len() > 12 {
            return Err("id too long for fixed-size array");
        }
        id[..id_bytes.len()].copy_from_slice(id_bytes);

        // Convert mrsigner
        let mut mrsigner = [0u8; 96];
        let mrsigner_bytes = tdx_module_identity.mrsigner.as_bytes();
        if mrsigner_bytes.len() > 96 {
            return Err("mrsigner too long for fixed-size array");
        }
        mrsigner[..mrsigner_bytes.len()].copy_from_slice(mrsigner_bytes);

        // Convert attributes
        let mut attributes = [0u8; 16];
        let attributes_bytes = tdx_module_identity.attributes.as_bytes();
        if attributes_bytes.len() > 16 {
            return Err("attributes too long for fixed-size array");
        }
        attributes[..attributes_bytes.len()].copy_from_slice(attributes_bytes);

        // Convert attributes_mask
        let mut attributes_mask = [0u8; 16];
        let attributes_mask_bytes = tdx_module_identity.attributes_mask.as_bytes();
        if attributes_mask_bytes.len() > 16 {
            return Err("attributes_mask too long for fixed-size array");
        }
        attributes_mask[..attributes_mask_bytes.len()].copy_from_slice(attributes_mask_bytes);

        // Convert tcb_levels
        let mut tcb_levels = [TdxTcbLevelPod {
            tcb_isvsvn: 0,
            tcb_status: 0,
            _pad: [0u8; 6],
            tcb_date: 0,
            advisory_ids: [[0u8; 32]; MAX_ADVISORY_IDS_SIZE],
        }; TDX_MODULE_TCB_MAX_LEVEL_SIZE];

        let len = tdx_module_identity.tcb_levels.len();
        if len > TDX_MODULE_TCB_MAX_LEVEL_SIZE {
            return Err("TCB Levels exceeded TDX_MODULE_TCB_MAX_LEVEL_SIZE");
        }

        let len = tdx_module_identity.tcb_levels.len().min(TDX_MODULE_TCB_MAX_LEVEL_SIZE);
        for (i, level) in tdx_module_identity
            .tcb_levels
            .into_iter()
            .take(len)
            .enumerate()
        {
            tcb_levels[i] = TdxTcbLevelPod::try_from(level)?;
        }

        Ok(TdxModuleIdentityPod {
            id,
            mrsigner_hex: mrsigner,
            _pad: [0u8; 4],
            attributes_hex: attributes,
            attributes_mask_hex: attributes_mask,
            tcb_levels,
        })
    }
}

impl TryFrom<TdxModuleIdentityPod> for TdxModuleIdentity {
    type Error = &'static str;

    fn try_from(
        tdx_module_identity_pod: TdxModuleIdentityPod,
    ) -> std::result::Result<Self, Self::Error> {
        // Convert id
        let null_pos = tdx_module_identity_pod
            .id
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(tdx_module_identity_pod.id.len());
        let id = String::from_utf8(tdx_module_identity_pod.id[..null_pos].to_vec())
            .map_err(|_| "Invalid UTF-8 in id")?;

        // Convert mrsigner
        let null_pos = tdx_module_identity_pod
            .mrsigner_hex
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(tdx_module_identity_pod.mrsigner_hex.len());
        let mrsigner = String::from_utf8(tdx_module_identity_pod.mrsigner_hex[..null_pos].to_vec())
            .map_err(|_| "Invalid UTF-8 in mrsigner")?;

        // Convert attributes
        let null_pos = tdx_module_identity_pod
            .attributes_hex
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(tdx_module_identity_pod.attributes_hex.len());
        let attributes = String::from_utf8(tdx_module_identity_pod.attributes_hex[..null_pos].to_vec())
            .map_err(|_| "Invalid UTF-8 in attributes")?;

        // Convert attributes_mask
        let null_pos = tdx_module_identity_pod
            .attributes_mask_hex
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(tdx_module_identity_pod.attributes_mask_hex.len());
        let attributes_mask =
            String::from_utf8(tdx_module_identity_pod.attributes_mask_hex[..null_pos].to_vec())
                .map_err(|_| "Invalid UTF-8 in attributes_mask")?;

        // Convert tcb_levels
        let mut tcb_levels = Vec::with_capacity(TDX_MODULE_TCB_MAX_LEVEL_SIZE);
        for level_pod in tdx_module_identity_pod.tcb_levels.iter() {
            if level_pod.tcb_date > 0 {
                tcb_levels.push(TdxTcbLevel::try_from(*level_pod)?);
            }
        }

        Ok(TdxModuleIdentity {
            id,
            mrsigner,
            attributes,
            attributes_mask,
            tcb_levels,
        })
    }
}

impl TryFrom<TdxTcbLevel> for TdxTcbLevelPod {
    type Error = &'static str;

    fn try_from(tdx_tcb_level: TdxTcbLevel) -> std::result::Result<Self, Self::Error> {
        // Convert tcb_isvsvn
        let tcb_isvsvn = tdx_tcb_level.tcb.isvsvn;

        // Convert tcb_status
        let tcb_status = tdx_tcb_level.tcb_status as u8;

        // Convert tcb_date
        let tcb_date = tdx_tcb_level.tcb_date.timestamp() as u64;

        // Convert advisory_ids
        let mut advisory_ids = [[0u8; 32]; MAX_ADVISORY_IDS_SIZE];
        if let Some(ids) = tdx_tcb_level.advisory_ids {
            let len = ids.len();
            if len > MAX_ADVISORY_IDS_SIZE {
                return Err("Advisory IDs exceeded MAX_ADVISORY_IDS_SIZE");
            }
            let len = ids.len().min(MAX_ADVISORY_IDS_SIZE);
            for (i, id) in ids.into_iter().take(len).enumerate() {
                let id_bytes = id.as_bytes();
                if id_bytes.len() > 32 {
                    return Err("Advisory ID too long for fixed-size array");
                }
                advisory_ids[i][..id_bytes.len()].copy_from_slice(id_bytes);
            }
        }

        Ok(TdxTcbLevelPod {
            tcb_isvsvn,
            tcb_status,
            _pad: [0u8; 6],
            tcb_date,
            advisory_ids,
        })
    }
}

impl TryFrom<TdxTcbLevelPod> for TdxTcbLevel {
    type Error = &'static str;

    fn try_from(tdx_tcb_level_pod: TdxTcbLevelPod) -> std::result::Result<Self, Self::Error> {
        // Convert tcb
        let tcb = TcbTdx {
            isvsvn: tdx_tcb_level_pod.tcb_isvsvn,
        };

        // Convert tcb_status
        let tcb_status = TcbStatus::try_from(tdx_tcb_level_pod.tcb_status)?;

        // Convert tcb_date
        let tcb_date =
            chrono::DateTime::<chrono::Utc>::from_timestamp(tdx_tcb_level_pod.tcb_date as i64, 0)
                .ok_or("Invalid tcb_date timestamp")?;

        // Convert advisory_ids
        let mut advisory_ids = Vec::new();
        for id_array in tdx_tcb_level_pod.advisory_ids.iter() {
            if id_array.iter().any(|&b| b != 0) {
                let null_pos = id_array
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(id_array.len());
                let id = String::from_utf8(id_array[..null_pos].to_vec())
                    .map_err(|_| "Invalid UTF-8 in advisory ID")?;
                advisory_ids.push(id);
            }
        }

        Ok(TdxTcbLevel {
            tcb,
            tcb_date,
            tcb_status,
            advisory_ids: if advisory_ids.is_empty() {
                None
            } else {
                Some(advisory_ids)
            },
        })
    }
}

impl TryFrom<TcbLevel> for TcbLevelPod {
    type Error = &'static str;

    fn try_from(tcb_level: TcbLevel) -> std::result::Result<Self, Self::Error> {
        // Convert tcb_status
        let tcb_status = tcb_level.tcb_status as u8;

        // Convert pce_svn
        let pce_svn = tcb_level.tcb.pcesvn();

        // Convert sgx_tcb_components
        let sgx_components = tcb_level.tcb.sgx_tcb_components();
        let mut sgx_tcb_components = [TcbComponent {
            cpusvn: 0,
            category: [0u8; 16],
            component_type: [0u8; 64],
        }; 16];

        match &tcb_level.tcb {
            Tcb::V2(_) => {
                for (i, &svn) in sgx_components.iter().enumerate() {
                    sgx_tcb_components[i] = TcbComponent {
                        cpusvn: svn,
                        category: [0u8; 16],
                        component_type: [0u8; 64],
                    };
                }
            },
            Tcb::V3(v3) => {
                for (i, component) in v3.sgxtcbcomponents.iter().enumerate() {
                    let mut category = [0u8; 16];
                    if let Some(cat) = &component.category {
                        let cat_bytes = cat.as_bytes();
                        if cat_bytes.len() > 16 {
                            return Err("Category too long for fixed-size array");
                        }
                        category[..cat_bytes.len()].copy_from_slice(cat_bytes);
                    }

                    let mut component_type = [0u8; 64];
                    if let Some(typ) = &component.component_type {
                        let typ_bytes = typ.as_bytes();
                        if typ_bytes.len() > 64 {
                            return Err("Component type too long for fixed-size array");
                        }
                        component_type[..typ_bytes.len()].copy_from_slice(typ_bytes);
                    }

                    sgx_tcb_components[i] = TcbComponent {
                        cpusvn: component.svn,
                        category,
                        component_type,
                    };
                }
            },
        }

        // Convert tdx_tcb_components
        let mut tdx_tcb_components = [TcbComponent {
            cpusvn: 0,
            category: [0u8; 16],
            component_type: [0u8; 64],
        }; 16];

        if let Some(tdx_components) = tcb_level.tcb.tdx_tcb_components() {
            if let Tcb::V3(v3) = &tcb_level.tcb {
                if let Some(tdx_comps) = &v3.tdxtcbcomponents {
                    for (i, (component, &svn)) in
                        tdx_comps.iter().zip(tdx_components.iter()).enumerate()
                    {
                        let mut category = [0u8; 16];
                        if let Some(cat) = &component.category {
                            let cat_bytes = cat.as_bytes();
                            if cat_bytes.len() > 16 {
                                return Err("Category too long for fixed-size array");
                            }
                            category[..cat_bytes.len()].copy_from_slice(cat_bytes);
                        }

                        let mut component_type = [0u8; 64];
                        if let Some(typ) = &component.component_type {
                            let typ_bytes = typ.as_bytes();
                            if typ_bytes.len() > 64 {
                                return Err("Component type too long for fixed-size array");
                            }
                            component_type[..typ_bytes.len()].copy_from_slice(typ_bytes);
                        }

                        tdx_tcb_components[i] = TcbComponent {
                            cpusvn: svn,
                            category,
                            component_type,
                        };
                    }
                }
            }
        }

        // Convert advisory_ids
        let mut advisory_ids = [[0u8; 32]; MAX_ADVISORY_IDS_SIZE];

        if let Some(ids) = &tcb_level.advisory_ids {
            let len = ids.len();
            if len > MAX_ADVISORY_IDS_SIZE {
                return Err("Advisory IDs exceeded MAX_ADVISORY_IDS_SIZE");
            }
            let len = ids.len().min(MAX_ADVISORY_IDS_SIZE);
            for (i, id) in ids.iter().take(len).enumerate() {
                let id_bytes = id.as_bytes();
                if id_bytes.len() > 32 {
                    return Err("Advisory ID too long for fixed-size array");
                }
                advisory_ids[i][..id_bytes.len()].copy_from_slice(id_bytes);
            }
        }

        let tcb_date = tcb_level.tcb_date.timestamp() as u64;

        Ok(TcbLevelPod {
            tcb_status,
            _pad0: 0,
            pce_svn,
            _pad1: [0u8; 4],
            tcb_date,
            sgx_tcb_components,
            tdx_tcb_components,
            advisory_ids,
        })
    }
}

impl TryFrom<TcbLevelPod> for TcbLevel {
    type Error = &'static str;

    fn try_from(tcb_level_pod: TcbLevelPod) -> std::result::Result<Self, Self::Error> {
        // Convert tcb_status
        let tcb_status = TcbStatus::try_from(tcb_level_pod.tcb_status)?;

        // Determine if we're dealing with V2 or V3 based on component data
        let has_v3_data = tcb_level_pod.sgx_tcb_components.iter().any(|comp| {
            comp.category.iter().any(|&b| b != 0) || comp.component_type.iter().any(|&b| b != 0)
        });

        let mut advisory_ids = Vec::new();

        // Convert tcb
        let tcb = if has_v3_data {
            // Create V3 TCB
            let sgxtcbcomponents = core::array::from_fn(|_| TcbComponentV3 {
                svn: 0,
                category: None,
                component_type: None,
            });

            let mut sgxtcbcomponents = sgxtcbcomponents;
            for (i, comp) in tcb_level_pod.sgx_tcb_components.iter().enumerate() {
                let category = if comp.category.iter().any(|&b| b != 0) {
                    let null_pos = comp
                        .category
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(comp.category.len());
                    let category_str = String::from_utf8(comp.category[..null_pos].to_vec())
                        .map_err(|_| "Invalid UTF-8 in category")?;
                    Some(category_str)
                } else {
                    None
                };

                let component_type = if comp.component_type.iter().any(|&b| b != 0) {
                    let null_pos = comp
                        .component_type
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(comp.component_type.len());
                    let type_str = String::from_utf8(comp.component_type[..null_pos].to_vec())
                        .map_err(|_| "Invalid UTF-8 in component_type")?;
                    Some(type_str)
                } else {
                    None
                };

                sgxtcbcomponents[i] = TcbComponentV3 {
                    svn: comp.cpusvn,
                    category,
                    component_type,
                };
            }

            let tdxtcbcomponents = if tcb_level_pod
                .tdx_tcb_components
                .iter()
                .any(|comp| comp.cpusvn != 0)
            {
                let tdx_components = core::array::from_fn(|_| TcbComponentV3 {
                    svn: 0,
                    category: None,
                    component_type: None,
                });
                let mut tdx_components = tdx_components;
                for (i, comp) in tcb_level_pod.tdx_tcb_components.iter().enumerate() {
                    let category = if comp.category.iter().any(|&b| b != 0) {
                        let null_pos = comp
                            .category
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(comp.category.len());
                        let category_str = String::from_utf8(comp.category[..null_pos].to_vec())
                            .map_err(|_| "Invalid UTF-8 in category")?;
                        Some(category_str)
                    } else {
                        None
                    };

                    let component_type = if comp.component_type.iter().any(|&b| b != 0) {
                        let null_pos = comp
                            .component_type
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(comp.component_type.len());
                        let type_str = String::from_utf8(comp.component_type[..null_pos].to_vec())
                            .map_err(|_| "Invalid UTF-8 in component_type")?;
                        Some(type_str)
                    } else {
                        None
                    };

                    tdx_components[i] = TcbComponentV3 {
                        svn: comp.cpusvn,
                        category,
                        component_type,
                    };
                }
                Some(tdx_components)
            } else {
                None
            };

            // Convert advisory_ids
            for id_array in tcb_level_pod.advisory_ids.iter() {
                if id_array.iter().any(|&b| b != 0) {
                    let null_pos = id_array
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(id_array.len());
                    let id = String::from_utf8(id_array[..null_pos].to_vec())
                        .map_err(|_| "Invalid UTF-8 in advisory ID")?;
                    advisory_ids.push(id);
                }
            }

            Tcb::V3(TcbV3 {
                sgxtcbcomponents,
                pcesvn: tcb_level_pod.pce_svn,
                tdxtcbcomponents,
            })
        } else {
            // Create V2 TCB
            let svns = tcb_level_pod.sgx_tcb_components.map(|comp| comp.cpusvn);

            Tcb::V2(TcbV2 {
                sgxtcbcomp01svn: svns[0],
                sgxtcbcomp02svn: svns[1],
                sgxtcbcomp03svn: svns[2],
                sgxtcbcomp04svn: svns[3],
                sgxtcbcomp05svn: svns[4],
                sgxtcbcomp06svn: svns[5],
                sgxtcbcomp07svn: svns[6],
                sgxtcbcomp08svn: svns[7],
                sgxtcbcomp09svn: svns[8],
                sgxtcbcomp10svn: svns[9],
                sgxtcbcomp11svn: svns[10],
                sgxtcbcomp12svn: svns[11],
                sgxtcbcomp13svn: svns[12],
                sgxtcbcomp14svn: svns[13],
                sgxtcbcomp15svn: svns[14],
                sgxtcbcomp16svn: svns[15],
                pcesvn: tcb_level_pod.pce_svn,
            })
        };

        let tcb_date =
            chrono::DateTime::<chrono::Utc>::from_timestamp(tcb_level_pod.tcb_date as i64, 0)
                .ok_or("Invalid tcb_date timestamp")?;

        Ok(TcbLevel {
            tcb,
            tcb_date,
            tcb_status,
            advisory_ids: if advisory_ids.is_empty() {
                None
            } else {
                Some(advisory_ids)
            },
        })
    }
}
