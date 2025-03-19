use crate::utils::{cert_chain, crl};
use serde::{Deserialize, Serialize};
use x509_cert::{Certificate, crl::CertificateList};

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
    pub tcb_info_and_qe_identity_issuer_chain: Vec<Certificate>,

    /* Structured Data */
    /// TCB Info Structure
    /// Contains security version information and TCB levels.
    pub tcb_info: TcbInfoAndSignature,

    /// QE Identity Structure
    /// Contains Quoting Enclave identity information.
    pub qe_identity: QuotingEnclaveIdentityAndSignature,
}

#[cfg(test)]
mod tests {
    use super::Collateral;

    #[test]
    fn encode_decode_collateral_json() {
        let json = include_str!("../../data/full_collateral_sgx.json");
        let _collateral: Collateral = serde_json::from_str(json).expect("json to parse");
    }
}
