use bytemuck::{Pod, Zeroable};
pub const TDX_MODULE_TCB_MAX_LEVEL_SIZE: usize = 4;
pub const TCB_MAX_LEVEL_SIZE: usize = 15;
pub const MAX_ADVISORY_IDS_SIZE: usize = 16;

// pub mod v2;
// pub mod v3_sgx;
// pub mod v3_tdx;

// use v2::*;
// use v3_sgx::*;
// use v3_tdx::*;

// /// 1648 bytes
// #[repr(C)]
// #[derive(Copy, Clone, Debug, Pod, Zeroable)]
// pub struct TcbV2Pod {
//     pub tcb_info_v2: TcbInfoV2Pod,
//     pub signature: [u8; 64],
// }

// /// 27472 bytes
// #[repr(C)]
// #[derive(Copy, Clone, Debug, Pod, Zeroable)]
// pub struct TcbV3SGXPod {
//     pub tcb_info_v3_sgx: TcbInfoV3SGXPod,
//     pub signature: [u8; 64],
// }

// #[repr(C)]
// #[derive(Copy, Clone, Debug, Pod, Zeroable)]
// pub struct TcbV3TDXPod {
//     pub tcb_info_v3_tdx: TcbInfoV3TDXPod,
//     pub signature: [u8; 64],
// }

// /// 81 bytes
// #[repr(C)]
// #[derive(Copy, Clone, Debug, Pod, Zeroable)]
// pub struct TcbV3Component {
//     pub cpusvn: u8,
//     pub category: [u8; 16], // 16-byte string
//     pub component_type: [u8; 64] // 64-byte string
// }

// ================================================================

pub mod tcb_info_impl;
#[cfg(test)]
mod tests;

/// The TCB POD structure should be BPF friendly.
/// 56072 bytes
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct TcbPod {
    pub tcb_info: TcbInfoPod,
    pub signature: [u8; 64],
}

/// 56008 bytes
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct TcbInfoPod {
    pub pceid_hex: [u8; 4], // 4 characters for hexstring representation of PCEID
    pub id: [u8; 6], // "SGX" or "TDX" strings
    pub fmspc_hex: [u8; 12], // 6 characters for hexstring representation of FMSPC
    pub tcb_type: u8,
    pub _pad0: u8, 
    pub version: u32,
    pub _pad1: [u8; 4],
    pub issued_timestamp: u64,
    pub next_update_timestamp: u64,
    pub tcb_evaluation_data_number: u32,
    pub _pad2: [u8; 4],
    pub tdx_module: TdxModulePod,
    pub tdx_module_identities: [TdxModuleIdentityPod; TDX_MODULE_TCB_MAX_LEVEL_SIZE], // Fixed at size 4 for now
    pub tcb_levels: [TcbLevelPod; TCB_MAX_LEVEL_SIZE], // Fixed at size 15 for now
}

/// 128 bytes
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct TdxModulePod {
    pub mrsigner_hex: [u8; 96], // 48 characters for hexstring representation of MRSIGNER
    pub attributes_hex: [u8; 16], // 8 characters for hexstring representation of ATTRIBUTES
    pub attributes_mask_hex: [u8; 16] // 8 characters for hexstring representation of ATTRIBUTES_MASK
}

/// 2256 bytes
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct TdxModuleIdentityPod {
    pub id: [u8; 12], // ID is a string in the format of "TDX_<two-digit-number>"
    pub mrsigner_hex: [u8; 96], // 48 characters for hexstring representation of MRSIGNER
    pub _pad: [u8; 4], // Padding to align to 8 bytes
    pub attributes_hex: [u8; 16], // 8 characters for hexstring representation of ATTRIBUTES
    pub attributes_mask_hex: [u8; 16], // 8 characters for hexstring representation of ATTRIBUTES_MASK
    pub tcb_levels: [TdxTcbLevelPod; TDX_MODULE_TCB_MAX_LEVEL_SIZE], // Fixed at size 4 for now
}

/// 528 bytes
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct TdxTcbLevelPod {
    pub tcb_isvsvn: u8,
    pub tcb_status: u8,
    pub _pad: [u8; 6], // Padding to align to 8 bytes
    pub tcb_date: u64,
    pub advisory_ids: [[u8; 32]; MAX_ADVISORY_IDS_SIZE], // Fixed at size 16 for now
}

/// 3120 bytes
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct TcbLevelPod {
    pub tcb_status: u8,
    pub _pad0: u8, // Padding to align to 2 bytes
    pub pce_svn: u16,
    pub _pad1: [u8; 4], // Padding to align to 8 bytes
    pub tcb_date: u64,
    pub sgx_tcb_components: [TcbComponent; 16],
    pub tdx_tcb_components: [TcbComponent; 16],
    pub advisory_ids: [[u8; 32]; MAX_ADVISORY_IDS_SIZE], // Fixed at size 16 for now
}

/// 81 bytes
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct TcbComponent {
    pub cpusvn: u8,
    pub category: [u8; 16], // 16-byte string
    pub component_type: [u8; 64] // 64-byte string
}