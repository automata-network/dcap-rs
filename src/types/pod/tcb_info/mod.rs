use bytemuck::{Pod, Zeroable};

pub mod tcb_info_impl;
pub mod zero_copy; // Changed from views to zero_copy
#[cfg(test)]
mod tests;

// --- New Header and Data Structs ---

/// Header for a TCB Component.
/// The actual string data for category and component_type will be in the parent's payload.
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable, Default)]
pub struct TcbComponentHeader {
    pub cpusvn: u8,
    pub category_len: u8,
    pub component_type_len: u8,
    pub _padding: [u8; 5], // Align to 8 bytes
}

/// Header for a TDX TCB Level.
/// The actual advisory ID strings and their lengths array will be in this header's payload.
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable, Default)]
pub struct TdxTcbLevelHeader {
    pub tcb_isvsvn: u8,
    pub tcb_status: u8, // Represents crate::src::types::tcb_info::TcbStatus
    pub _padding0: [u8; 6], // Align tcb_date_timestamp to 8 bytes
    pub tcb_date_timestamp: u64,
    pub advisory_ids_count: u32,
    pub advisory_ids_lengths_array_len: u32, // Total byte length of the array of u16 lengths
    pub advisory_ids_data_total_len: u32,    // Total byte length of concatenated advisory ID strings
    pub _padding1: [u8; 4], // Align to 8 bytes boundary if needed or for future fields
}

/// Header for a TDX Module Identity.
/// The ID string and its TdxTcbLevel headers/payloads will be in this header's payload.
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct TdxModuleIdentityHeader {
    pub mrsigner_hex: [u8; 96],       // Hex string
    pub attributes_hex: [u8; 16],     // Hex string
    pub attributes_mask_hex: [u8; 16], // Hex string
    pub id_len: u8,                   // Length of the ID string (e.g., "TDX_01")
    pub _padding0: [u8; 7],           // Align tcb_levels_count
    pub tcb_levels_count: u32,        // Number of TdxTcbLevelHeader + payload sections
    pub tcb_levels_total_payload_len: u32, // Total byte length for all TdxTcbLevelHeader sections for this identity
}

/// POD structure for TDX Module data. This is part of TcbInfoHeader's payload if tdx_module_present.
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct TdxModulePodData {
    pub mrsigner_hex: [u8; 96],       // Hex string
    pub attributes_hex: [u8; 16],     // Hex string
    pub attributes_mask_hex: [u8; 16], // Hex string
}

/// Header for a general TCB Level (SGX or TDX platform).
/// Component string data and advisory ID data will be in this header's payload.
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable, Default)]
pub struct TcbLevelHeader {
    pub tcb_status: u8, // Represents crate::src::types::tcb_info::TcbStatus
    pub _padding0_a: u8, // Renamed to avoid conflict, aligns pce_svn
    pub pce_svn: u16,
    pub _padding1_a: [u8; 4], // Renamed, aligns tcb_date_timestamp
    pub tcb_date_timestamp: u64,

    pub sgx_tcb_components: [TcbComponentHeader; 16],
    pub tdx_tcb_components_present: u8, // 1 if present, 0 if not
    pub _padding2_a: [u8; 7], // Renamed, aligns tdx_tcb_components
    pub tdx_tcb_components: [TcbComponentHeader; 16], // Valid if tdx_tcb_components_present is 1

    // Metadata for payload section of this TcbLevelHeader
    pub sgx_components_strings_total_len: u32, // Sum of (category_len + component_type_len) for all 16 SGX components
    pub tdx_components_strings_total_len: u32, // Sum for TDX components, if present (0 otherwise)
    pub advisory_ids_count: u32,
    pub advisory_ids_lengths_array_len: u32, // Total byte length of the array of u16 lengths
    pub advisory_ids_data_total_len: u32,    // Total byte length of concatenated advisory ID strings
    pub _final_padding: [u8; 4], // Ensures total size is multiple of 8 (304 bytes)
}

/// Main header for TCB Info.
/// This is followed by a variable-length payload containing data for tdx_module,
/// tdx_module_identities, and tcb_levels.
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable, Default)]
pub struct TcbInfoHeader {
    pub id_type: [u8; 6], 
    pub _pad_id_type: [u8; 2], // Aligns version
    pub version: u32,     
    pub _pad_version: [u8; 4], // Aligns issue_date_timestamp
    pub issue_date_timestamp: u64,
    pub next_update_timestamp: u64,
    pub fmspc_hex: [u8; 12],          
    pub pce_id_hex: [u8; 4],          
    pub tcb_type: u8,                 
    pub _pad_tcb_type: [u8; 3], // Aligns tcb_evaluation_data_number
    pub tcb_evaluation_data_number: u32, 
    
    pub tdx_module_present: u8, 
    pub _pad_tdx_module_present: [u8; 3], // Aligns tdx_module_data_len (was _padding0)
    pub tdx_module_data_len: u32, 

    pub tdx_module_identities_count: u32,
    pub tdx_module_identities_total_payload_len: u32, 

    pub tcb_levels_count: u32,
    pub tcb_levels_total_payload_len: u32, 
    // Total size is 80 bytes, which is a multiple of 8. No final padding field needed here.
}

/// The top-level POD structure for TCB Info and its signature.
/// The variable payload for TcbInfoHeader follows it directly in memory.
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct TcbPod {
    pub signature: [u8; 64],
    pub tcb_info_header: TcbInfoHeader,
    // The variable payload associated with tcb_info_header follows here in memory.
}
