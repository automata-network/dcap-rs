#[cfg(feature = "zero-copy")]
use crate::utils::cert_chain_processor;
use crate::utils::{cert_chain, crl};
use crate::utils::keccak;
use anyhow::Result;
use serde::{Deserialize, Serialize};
#[cfg(not(feature = "zero-copy"))]
use x509_cert::certificate::CertificateInner;
use x509_cert::{crl::CertificateList, der::{Decode, Encode}};

use super::{enclave_identity::QuotingEnclaveIdentityAndSignature, tcb_info::TcbInfoAndSignature};

#[derive(Debug, Serialize, Deserialize)]
pub struct Collateral {
    /* Certificate Revocation List */
    /// Root CA CRL in PEM format
    /// Contains a list of revoked certificates signed by Intel SGX Root CA.
    /// It is used to check if any certificates in the verification chain have been revoked.
    #[serde(with = "crl")]
    pub root_ca_crl: CertificateList,

    /// PCK CRL in PEM format
    ///
    /// This can be Platform CA CRL or Processor CA CRL.
    /// Contains a list of revoked certificates signed by Intel SGX Platform CA or Intel SGX Processor CA.
    /// It is used to check if any certificates in the verification chain have been revoked.
    /// Only to be passed if the quote is expected to be signed by Intel SGX PCK CA.
    #[serde(with = "crl")]
    pub pck_crl: CertificateList,

    /* Issuer Certificate Chains */
    /// TCB Info and Identity Issuer Chain in PEM format
    /// Chain of certificates used to verify TCB Info and Identity signature.
    #[serde(with = "cert_chain")]
    pub tcb_info_and_qe_identity_issuer_chain: Vec<CertificateInner>,

    /* Structured Data */
    /// TCB Info Structure
    /// Contains security version information and TCB levels.
    pub tcb_info: TcbInfoAndSignature,

    /// QE Identity Structure
    /// Contains Quoting Enclave identity information.
    pub qe_identity: QuotingEnclaveIdentityAndSignature,
}

impl Collateral {
    pub fn new(
        root_ca_crl_der: &[u8],
        pck_crl_der: &[u8],
        tcb_info_and_qe_identity_issuer_chain_pem_bytes: &[u8],
        tcb_info_json_str: &str,
        qe_identity_json_str: &str,
    ) -> Result<Self> {
        let root_ca_crl = CertificateList::from_der(root_ca_crl_der)?;
        let pck_crl = CertificateList::from_der(pck_crl_der)?;
        #[cfg(not(feature = "zero-copy"))]
        let tcb_info_and_qe_identity_issuer_chain: Vec<CertificateInner> =
            CertificateInner::load_pem_chain(tcb_info_and_qe_identity_issuer_chain_pem_bytes)?;
        #[cfg(feature = "zero-copy")]
        let tcb_info_and_qe_identity_issuer_chain: Vec<CertificateInner> =
            cert_chain_processor::load_pem_chain_bpf_friendly(
                tcb_info_and_qe_identity_issuer_chain_pem_bytes,
            )?;
        let tcb_info: TcbInfoAndSignature = serde_json::from_str(tcb_info_json_str)?;
        let qe_identity: QuotingEnclaveIdentityAndSignature =
            serde_json::from_str(qe_identity_json_str)?;

        Ok(Self {
            root_ca_crl,
            pck_crl,
            tcb_info_and_qe_identity_issuer_chain,
            tcb_info,
            qe_identity,
        })
    }

    pub fn get_cert_hash(cert: &CertificateInner) -> Result<[u8; 32]> {
        let tbs = cert.tbs_certificate.to_der()?;
        Ok(keccak::hash(&tbs))
    }

    pub fn get_crl_hash(crl: &CertificateList) -> Result<[u8; 32]> {
        let tbs = crl.tbs_cert_list.to_der()?;
        Ok(keccak::hash(&tbs))
    }
}

#[cfg(test)]
mod tests {
    use super::Collateral;

    #[test]
    fn test_encode_collateral() {
        let collateral = Collateral::new(
            include_bytes!("../../data/intel_root_ca_crl.der"),
            include_bytes!("../../data/pck_platform_crl.der"),
            include_bytes!("../../data/tcb_signing_cert.pem"),
            include_str!("../../data/tcb_info_v2.json"),
            include_str!("../../data/qeidentityv2.json"),
        )
        .expect("collateral to be created");

        let json = serde_json::to_string(&collateral).expect("collateral to serialize");
        assert!(!json.is_empty(), "collateral JSON should not be empty");
        println!("Collateral JSON: {}", json);
    }

    #[test]
    fn test_decode_collateral_json() {
        let json = include_str!("../../data/full_collateral_sgx.json");
        let _collateral: Collateral = serde_json::from_str(json).expect("json to parse");
    }
}
