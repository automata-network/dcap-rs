use super::cert::Certificates;

pub mod version_3;
pub mod version_4;
pub mod body;

use body::EnclaveReport;
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteHeader {
    pub version: u16,                   // [2 bytes]
                                        // Version of the quote data structure - 4, 5
    pub att_key_type: u16,              // [2 bytes]
                                        // Type of the Attestation Key used by the Quoting Enclave -
                                        // 2 (ECDSA-256-with-P-256 curve) 
                                        // 3 (ECDSA-384-with-P-384 curve)
    pub tee_type: u32,                  // [4 bytes]
                                        // TEE for this Attestation
                                        // 0x00000000: SGX
                                        // 0x00000081: TDX
    pub qe_svn: [u8; 2],                // [2 bytes]
                                        // Security Version of the Quoting Enclave - 1 (only applicable for SGX Quotes)
    pub pce_svn: [u8; 2],               // [2 bytes]
                                        // Security Version of the PCE - 0 (only applicable for SGX Quotes)
    pub qe_vendor_id: [u8; 16],         // [16 bytes]
                                        // Unique identifier of the QE Vendor. 
                                        // Value: 939A7233F79C4CA9940A0DB3957F0607 (Intel® SGX QE Vendor)
                                        // Note: Each vendor that decides to provide a customized Quote data structure should have
                                        // unique ID.
    pub user_data: [u8; 20],            // [20 bytes]
                                        // Custom user-defined data. For the Intel® SGX and TDX DCAP Quote Generation Libraries, 
                                        // the first 16 bytes contain a Platform Identifier that is used to link a PCK Certificate to an Enc(PPID).
}

impl QuoteHeader {
    pub fn from_bytes(raw_bytes: &[u8]) -> Self {
        let version = u16::from_le_bytes([raw_bytes[0], raw_bytes[1]]);
        let att_key_type = u16::from_le_bytes([raw_bytes[2], raw_bytes[3]]);
        let tee_type = u32::from_le_bytes([raw_bytes[4], raw_bytes[5], raw_bytes[6], raw_bytes[7]]);
        let mut qe_svn = [0; 2];
        qe_svn.copy_from_slice(&raw_bytes[8..10]);
        let mut pce_svn = [0; 2];
        pce_svn.copy_from_slice(&raw_bytes[10..12]);
        let mut qe_vendor_id = [0; 16];
        qe_vendor_id.copy_from_slice(&raw_bytes[12..28]);
        let mut user_data = [0; 20];
        user_data.copy_from_slice(&raw_bytes[28..48]);

        QuoteHeader {
            version,
            att_key_type,
            tee_type,
            qe_svn,
            pce_svn,
            qe_vendor_id,
            user_data,
        }
    }

    pub fn to_bytes(&self) -> [u8; 48] {
        let mut raw_bytes = [0; 48];
        raw_bytes[0..2].copy_from_slice(&self.version.to_le_bytes());
        raw_bytes[2..4].copy_from_slice(&self.att_key_type.to_le_bytes());
        raw_bytes[4..8].copy_from_slice(&self.tee_type.to_le_bytes());
        raw_bytes[8..10].copy_from_slice(&self.qe_svn);
        raw_bytes[10..12].copy_from_slice(&self.pce_svn);
        raw_bytes[12..28].copy_from_slice(&self.qe_vendor_id);
        raw_bytes[28..48].copy_from_slice(&self.user_data);

        raw_bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QeAuthData {
    pub size: u16,
    pub data: Vec<u8>,
}

impl QeAuthData {
    pub fn from_bytes(raw_bytes: &[u8]) -> QeAuthData {
        let size = u16::from_le_bytes([raw_bytes[0], raw_bytes[1]]);
        let data = raw_bytes[2..2+size as usize].to_vec();
        QeAuthData {
            size,
            data,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertData {
    pub cert_data_type: u16,            // [2 bytes]
                                        // Determines type of data required to verify the QE Report Signature in the Quote Signature Data structure. 
                                        // 1 - (PCK identifier: PPID in plain text, CPUSVN, and PCESVN)
                                        // 2 - (PCK identifier: PPID encrypted using RSA-2048-OAEP, CPUSVN, and PCESVN)
                                        // 3 - (PCK identifier: PPID encrypted using RSA-2048-OAEP, CPUSVN, PCESVN, and QEID)
                                        // 4 - (PCK Leaf Certificate in plain text; currently not supported)
                                        // 5 - (Concatenated PCK Cert Chain)
                                        // 6 - (QE Report Certification Data)
                                        // 7 - (PLATFORM_MANIFEST; currently not supported)
    pub cert_data_size: u32,            // [4 bytes]
                                        // Size of Certification Data field.
    pub cert_data: Vec<u8>,             // [variable bytes]
                                        // Data required to verify the QE Report Signature depending on the value of the Certification Data Type:
                                        // 1: Byte array that contains concatenation of PPID, CPUSVN, PCESVN (LE), PCEID (LE).
                                        // 2: Byte array that contains concatenation of PPID encrypted using RSA-2048-OAEP, CPUSVN, PCESVN (LE), PCEID (LE).
                                        // 3: Byte array that contains concatenation of PPID encrypted using RSA-3072-OAEP, CPUSVN, PCESVN (LE), PCEID (LE).
                                        // 4: PCK Leaf Certificate
                                        // 5: Concatenated PCK Cert Chain (PEM formatted). PCK Leaf Cert || Intermediate CA Cert || Root CA Cert 
                                        // 6: QE Report Certification Data
                                        // 7: PLATFORM_MANIFEST
}

impl CertData {
    pub fn from_bytes(raw_bytes: &[u8]) -> Self {
        let cert_data_type = u16::from_le_bytes([raw_bytes[0], raw_bytes[1]]);
        let cert_data_size = u32::from_le_bytes([raw_bytes[2], raw_bytes[3], raw_bytes[4], raw_bytes[5]]);
        let cert_data = raw_bytes[6..6+cert_data_size as usize].to_vec();

        CertData {
            cert_data_type,
            cert_data_size,
            cert_data,
        }
    }

    pub fn get_cert_data(&self) -> CertDataType {
        match self.cert_data_type {
            1 => CertDataType::Type1(self.cert_data.clone()),
            2 => CertDataType::Type2(self.cert_data.clone()),
            3 => CertDataType::Type3(self.cert_data.clone()),
            4 => CertDataType::Type4(self.cert_data.clone()),
            5 => CertDataType::CertChain(Certificates::from_pem(&self.cert_data)),
            6 => CertDataType::QeReportCertData(QeReportCertData::from_bytes(&self.cert_data)),
            7 => CertDataType::Type7(self.cert_data.clone()),
            _ => CertDataType::Unused,
        }
    }
}

pub enum CertDataType {
    Unused,
    Type1(Vec<u8>),
    Type2(Vec<u8>),
    Type3(Vec<u8>),
    Type4(Vec<u8>),
    CertChain(Certificates),
    QeReportCertData(QeReportCertData),
    Type7(Vec<u8>),
}

#[derive(Clone, Debug)]
pub struct QeReportCertData {
    pub qe_report: EnclaveReport,
    pub qe_report_signature: [u8; 64],
    pub qe_auth_data: QeAuthData,
    pub qe_cert_data: CertData,
}

impl QeReportCertData {
    pub fn from_bytes(raw_bytes: &[u8]) -> Self {
        // 384 bytes for qe_report
        let qe_report = EnclaveReport::from_bytes(&raw_bytes[0..384]);
        // 64 bytes for qe_report_signature
        let mut qe_report_signature = [0; 64];
        qe_report_signature.copy_from_slice(&raw_bytes[384..448]);
        // qe auth data is variable length, we'll pass remaining bytes to the from_bytes method
        let qe_auth_data = QeAuthData::from_bytes(&raw_bytes[448..]);
        // get the length of qe_auth_data
        let qe_auth_data_size = 2 + qe_auth_data.size as usize;
        // finish off with the parsing of qe_cert_data
        let qe_cert_data_start = 448 + qe_auth_data_size;
        let qe_cert_data = CertData::from_bytes(&raw_bytes[qe_cert_data_start..]);

        QeReportCertData {
            qe_report,
            qe_report_signature,
            qe_auth_data,
            qe_cert_data,
        }
    }
}