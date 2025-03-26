use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::pubkey::Pubkey;


#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct EnclaveIdentity {
    pub owner: Pubkey,
    pub identity_type: EnclaveIdentityType,
    pub version: u8,
    pub data: Vec<u8>,
}

/// Represents the different types of Enclave Identities in the Intel SGX
/// attestation.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum EnclaveIdentityType {
    QE = 0,
    QVE = 1,
    TdQe = 2,
}

impl EnclaveIdentityType {
    pub fn common_name(&self) -> &'static str {
        match self {
            EnclaveIdentityType::QE => "QE",
            EnclaveIdentityType::QVE => "QVE",
            EnclaveIdentityType::TdQe => "TD_QE",
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(EnclaveIdentityType::QE),
            1 => Some(EnclaveIdentityType::QVE),
            2 => Some(EnclaveIdentityType::TdQe),
            _ => None,
        }
    }
}


#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct PcsCertificate {
    pub owner: Pubkey,
    pub ca_type: CertificateAuthority,
    pub cert_data: Vec<u8>,
}


#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum CertificateAuthority {
    ROOT = 0,
    PLATFORM = 1,
    PROCESSOR = 2,
    SIGNING = 3,
}

impl CertificateAuthority {
    pub fn common_name(&self) -> &'static str {
        match self {
            CertificateAuthority::ROOT => "Intel SGX Root CA",
            CertificateAuthority::PLATFORM => "Intel SGX Platform CA",
            CertificateAuthority::PROCESSOR => "Intel SGX Processor CA",
            CertificateAuthority::SIGNING => "Intel SGX TCB Signing CA",
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(CertificateAuthority::ROOT),
            1 => Some(CertificateAuthority::PLATFORM),
            2 => Some(CertificateAuthority::PROCESSOR),
            3 => Some(CertificateAuthority::SIGNING),
            _ => None,
        }
    }
}
