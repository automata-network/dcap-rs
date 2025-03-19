use quote::QuoteBody;
use tcb_info::TcbStatus;

pub mod collateral;
pub mod enclave_identity;
pub mod quote;
pub mod report;
pub mod sgx_x509;
pub mod tcb_info;

pub type UInt16LE = zerocopy::little_endian::U16;
pub type UInt32LE = zerocopy::little_endian::U32;
pub type UInt64LE = zerocopy::little_endian::U64;

// serialization:
// [quote_vesion][tee_type][tcb_status][fmspc][quote_body_raw_bytes]
// 2 bytes + 4 bytes + 1 byte + 6 bytes + var (SGX_ENCLAVE_REPORT = 384; TD10_REPORT = 584)
// total: 13 + var bytes
#[derive(Debug)]
pub struct VerifiedOutput {
    pub quote_version: u16,
    pub tee_type: u32,
    pub tcb_status: TcbStatus,
    pub fmspc: [u8; 6],
    pub quote_body: QuoteBody,
    pub advisory_ids: Option<Vec<String>>,
}
