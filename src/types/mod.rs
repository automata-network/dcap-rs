use alloy_sol_types::SolValue;

use quote::QuoteBody;
// use super::types::report::{EnclaveReportBody, Td10ReportBody};
// use quote::{QuoteBody, SGX_TEE_TYPE, TDX_TEE_TYPE};

#[cfg(feature = "full")]
pub mod collateral;
#[cfg(feature = "full")]
pub mod enclave_identity;
pub mod pod;
pub mod quote;
pub mod report;
pub mod sgx_x509;
#[cfg(feature = "full")]
pub mod tcb_info;

// const ENCLAVE_REPORT_LEN: usize = 384; // SGX_ENCLAVE_REPORT
// const TD10_REPORT_LEN: usize = 584; // TD10_REPORT
// const TD15_REPORT_LEN: usize = 648; // TD15_REPORT

// serialization:
// [quote_vesion][tee_type][tcb_status][fmspc][quote_body_raw_bytes][abi-encoded string array of tcb_advisory_ids]
// 2 bytes + 4 bytes + 1 byte + 6 bytes + var (SGX_ENCLAVE_REPORT = 384; TD10_REPORT = 584; TD15_REPORT = 648) + var
// total: 13 + (384 or 584) + var bytes
#[derive(Debug)]
pub struct VerifiedOutput {
    pub quote_version: u16,
    pub tee_type: u32,
    pub tcb_status: u8,
    pub fmspc: [u8; 6],
    pub quote_body: QuoteBody,
    pub advisory_ids: Option<Vec<String>>,
}

impl VerifiedOutput {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.quote_version.to_be_bytes());
        bytes.extend_from_slice(&self.tee_type.to_le_bytes());
        bytes.push(self.tcb_status);
        bytes.extend_from_slice(&self.fmspc);
        bytes.extend_from_slice(self.quote_body.as_bytes());

        if let Some(ref ids) = self.advisory_ids {
            let encoded = ids.abi_encode();
            bytes.extend_from_slice(&encoded);
        }

        bytes
    }

    // pub fn from_bytes(slice: &[u8]) -> VerifiedOutput {
    //     let mut quote_version = [0; 2];
    //     quote_version.copy_from_slice(&slice[0..2]);
    //     let mut tee_type = [0; 4];
    //     tee_type.copy_from_slice(&slice[2..6]);
    //     let tcb_status = slice[6];
    //     let mut fmspc = [0; 6];
    //     fmspc.copy_from_slice(&slice[7..13]);

    //     let mut offset = 13usize;
    //     let quote_body = match u32::from_le_bytes(tee_type) {
    //         SGX_TEE_TYPE => {
    //             let raw_quote_body: [u8; ENCLAVE_REPORT_LEN] = slice
    //                 [offset..offset + ENCLAVE_REPORT_LEN]
    //                 .try_into()
    //                 .unwrap();
    //             offset += ENCLAVE_REPORT_LEN;
    //             QuoteBody::SgxQuoteBody(EnclaveReportBody::try_from(raw_quote_body).unwrap())
    //         },
    //         TDX_TEE_TYPE => {
    //             // TODO: Currently there is no way to distinguish between TD10 and TD15 reports
    //             let raw_quote_body: [u8; TD10_REPORT_LEN] =
    //                 slice[offset..offset + TD10_REPORT_LEN].try_into().unwrap();
    //             offset += TD10_REPORT_LEN;
    //             QuoteBody::Td10QuoteBody(Td10ReportBody::try_from(raw_quote_body).unwrap())
    //         },
    //         _ => panic!("unknown TEE type"),
    //     };

    //     let mut advisory_ids = None;
    //     if offset < slice.len() {
    //         let advisory_ids_slice = &slice[offset..];
    //         advisory_ids = Some(<Vec<String>>::abi_decode(advisory_ids_slice).unwrap());
    //     }

    //     VerifiedOutput {
    //         quote_version: u16::from_be_bytes(quote_version),
    //         tee_type: u32::from_le_bytes(tee_type),
    //         tcb_status,
    //         fmspc,
    //         quote_body,
    //         advisory_ids,
    //     }
    // }
}
