// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf

use super::{QuoteHeader, QeAuthData, CertData, body::EnclaveReport};
use serde::{Serialize, Deserialize};
use serde_big_array::BigArray;

// high level sgx quote structure
// [48 - header] [384 - isv enclave report] [4 - quote signature length] [var - quote signature] 
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteV3 {
    pub header: QuoteHeader,                    // [48 bytes]
                                                // Header of Quote data structure. This field is transparent (the user knows
                                                // its internal structure). Rest of the Quote data structure can be
                                                // treated as opaque (hidden from the user).
    pub isv_enclave_report: EnclaveReport,      // [384 bytes]
                                                // Report of the attested ISV Enclave.
                                                // The CPUSVN and ISVSVN is the TCB when the quote is generated.
                                                // The REPORT.ReportData is defined by the ISV but should provide quote replay 
                                                // protection if required.
    pub signature_len: u32,                     // [4 bytes]
                                                // Size of the Quote Signature Data structure in bytes.
    pub signature: QuoteSignatureDataV3,        // [variable bytes]
                                                // Variable-length data containing the signature and supporting data. 
                                                // E.g. ECDSA 256-bit Quote Signature Data Structure (SgxQuoteSignatureData)
}

impl QuoteV3 {
    pub fn from_bytes(raw_bytes: &[u8]) -> QuoteV3 {
        let header = QuoteHeader::from_bytes(&raw_bytes[0..48]);
        let isv_enclave_report = EnclaveReport::from_bytes(&raw_bytes[48..432]);
        let signature_len = u32::from_le_bytes([raw_bytes[432], raw_bytes[433], raw_bytes[434], raw_bytes[435]]);
        // allocate and create a buffer for signature
        let signature_slice = &raw_bytes[436..436 + signature_len as usize];
        let signature = QuoteSignatureDataV3::from_bytes(signature_slice);

        QuoteV3 {
            header,
            isv_enclave_report,
            signature_len,
            signature,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteSignatureDataV3 {
    #[serde(with = "BigArray")]
    pub isv_enclave_report_signature: [u8; 64],     // ECDSA signature, the r component followed by the s component, 2 x 32 bytes.
    #[serde(with = "BigArray")]
    pub ecdsa_attestation_key: [u8; 64],            // EC KT-I Public Key, the x-coordinate followed by the y-coordinate 
                                                    // (on the RFC 6090 P-256 curve), 2 x 32 bytes.
    pub qe_report: EnclaveReport,
    #[serde(with = "BigArray")]
    pub qe_report_signature: [u8; 64],
    pub qe_auth_data: QeAuthData,
    pub qe_cert_data: CertData,
}

impl QuoteSignatureDataV3 {
    pub fn from_bytes(raw_bytes: &[u8]) -> QuoteSignatureDataV3 {
        let mut isv_enclave_report_signature = [0u8; 64];
        let mut ecdsa_attestation_key = [0u8; 64];
        let mut qe_report_signature = [0u8; 64];

        isv_enclave_report_signature.copy_from_slice(&raw_bytes[0..64]);
        ecdsa_attestation_key.copy_from_slice(&raw_bytes[64..128]);
        let qe_report = EnclaveReport::from_bytes(&raw_bytes[128..512]);
        qe_report_signature.copy_from_slice(&raw_bytes[512..576]);
        let qe_auth_data = QeAuthData::from_bytes(&raw_bytes[576..]);
        let qe_cert_data_start = 576 + 2 + qe_auth_data.size as usize;
        let qe_cert_data = CertData::from_bytes(&raw_bytes[qe_cert_data_start..]);

        QuoteSignatureDataV3 {
            isv_enclave_report_signature,
            ecdsa_attestation_key,
            qe_report,
            qe_report_signature,
            qe_auth_data,
            qe_cert_data,
        }
    }
}