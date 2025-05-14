use super::UInt32LE;
use crate::utils::u32_hex;
use anyhow::Context;
use chrono::Utc;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
#[cfg(feature = "full")]
use super::tcb_info::TcbStatus;

const ENCLAVE_IDENTITY_V2: u16 = 2;

#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QeTcb {
    pub isvsvn: u16,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct QuotingEnclaveIdentityAndSignature {
    #[serde(rename = "enclaveIdentity")]
    pub enclave_identity_raw: Box<RawValue>,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
}

impl QuotingEnclaveIdentityAndSignature {
    /// Validate the enclave identity and return the enclave identity if it is valid
    /// It checks the signature, the version, and the timestamp.
    /// The enclave identities should have their version set to 2.
    pub fn validate_as_enclave_identity(
        &self,
        public_key: &VerifyingKey,
    ) -> anyhow::Result<EnclaveIdentity> {
        public_key
            .verify(
                self.enclave_identity_raw.to_string().as_bytes(),
                &Signature::from_slice(&self.signature)?,
            )
            .context("Failed to verify enclave identity signature")?;

        let enclave_identity: EnclaveIdentity =
            serde_json::from_str(self.enclave_identity_raw.get())
                .context("Failed to deserialize enclave identity")?;

        if enclave_identity.version != ENCLAVE_IDENTITY_V2 {
            return Err(anyhow::anyhow!(
                "unsupported enclave identity version, only v2 is supported"
            ));
        }

        Ok(enclave_identity)
    }

    pub fn get_enclave_identity_bytes(&self) -> Vec<u8> {
        self.enclave_identity_raw.to_string().into_bytes()
    }

    pub fn get_enclave_identity(&self) -> anyhow::Result<EnclaveIdentity> {
        serde_json::from_str(self.enclave_identity_raw.get()).context("Failed to deserialize enclave identity")
    }

    pub fn get_signature_bytes(&self) -> Vec<u8> {
        self.signature.clone()
    }
}

#[derive(Deserialize, Serialize, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveIdentity {
    /// Identifier of the SGX Enclave issued by Intel.
    pub id: EnclaveType,

    /// Version of the structure.
    pub version: u16,

    /// The time the Enclave Identity Information was created. The time shalle be in UTC
    /// and the encoding shall be compliant to ISO 8601 standard (YYYY-MM-DDhh:mm:ssZ)
   
    pub issue_date: chrono::DateTime<Utc>,

    /// The time by which next Enclave Identity information will be issued. The time shall be in UTC
    /// and the encoding shall be compliant to ISO 8601 standard (YYYY-MM-DDhh:mm:ssZ)
   
    pub next_update: chrono::DateTime<Utc>,

    /// A monotonically increasing sequence number changed when Intel updates the content of the TCB evaluation data set:
    /// TCB Info, QE Identity, QVE Identity. The tcbEvaluationDataNUmber update is synchronized across TCB infor for all
    /// flavours of SGX CPUs (Family-Model-Stepping-Platform-CustomSKU) and QE/QVE Identity.
    /// This sequence number allows users to easily determine when a particular TCB Info/QE Identity/QVE Identity
    /// superseedes another TCB Info/QE Identity/QVE Identity (value: current TCB Recovery event number stored in the database).
    pub tcb_evaluation_data_number: u16,

    /// Base 16-encoded string representing miscselect "golden" value (upon applying mask).
    #[serde(with = "u32_hex")]
    pub miscselect: UInt32LE,

    /// Base 16-encoded string representing mask to be applied to miscselect value retrieved from the platform.
    #[serde(with = "u32_hex")]
    pub miscselect_mask: UInt32LE,

    /// Base 16-encoded string representing attributes "golden" value (upon applying mask).
    #[serde(with = "hex")]
    pub attributes: [u8; 16],

    /// Base 16-encoded string representing mask to be applied to attributes value retrieved from the platform.
    #[serde(with = "hex")]
    pub attributes_mask: [u8; 16],

    /// Base 16-encoded string representing mrsigner hash.
    #[serde(with = "hex")]
    pub mrsigner: [u8; 32],

    /// Enclave Product ID.
    pub isvprodid: u16,

    /// Sorted list of supported Enclave TCB levels for given QVE encoded as a JSON array of Enclave TCB level objects.
    pub tcb_levels: Vec<QeTcbLevel>,
}

impl EnclaveIdentity {
    pub fn get_qe_tcb_status(&self, isv_svn: u16) -> QeTcbStatus {
        self.tcb_levels
            .iter()
            .find(|level| level.tcb.isvsvn <= isv_svn)
            .map(|level| level.tcb_status.clone())
            .unwrap_or(QeTcbStatus::Unspecified)
    }
}

/// Enclave TCB level
#[derive(Deserialize, Serialize, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct QeTcbLevel {
    /// SGX Enclave's ISV SVN
    tcb: QeTcb,
    /// The time the TCB was evaluated. The time shall be in UTC and the encoding shall be compliant to ISO 8601 standard (YYYY-MM-DDhh:mm:ssZ)
   
    _tcb_date: chrono::DateTime<Utc>,
    /// TCB level status
    tcb_status: QeTcbStatus,
    #[serde(rename = "advisoryIDs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory_ids: Option<Vec<String>>,
}

/// TCB level status
#[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq)]
pub enum QeTcbStatus {
    /// TCB level of the SGX platform is up-to-date.
    UpToDate,
    /// TCB level of SGX platform requires SW hardening.
    SWHardeningNeeded,
    /// TCB level of SGX platform is outdated.
    OutOfDate,
    /// TCB level of SGX platform is outdated and requires a configuration change.
    OutOfDateConfigurationNeeded,
    /// TCB level of SGX platform is outdated and requires a configuration change.
    ConfigurationNeeded,
    /// TCB level of SGX platform is outdated and requires a configuration change and SW hardening.
    ConfigurationAndSWHardeningNeeded,
    /// TCB level of SGX platform is revoked.
    Revoked,
    /// Unknown TCB level status.
    Unspecified,
}

impl std::fmt::Display for QeTcbStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QeTcbStatus::UpToDate => write!(f, "UpToDate"),
            QeTcbStatus::OutOfDate => write!(f, "OutOfDate"),
            QeTcbStatus::Revoked => write!(f, "Revoked"),
            QeTcbStatus::ConfigurationNeeded => write!(f, "ConfigurationNeeded"),
            QeTcbStatus::ConfigurationAndSWHardeningNeeded => write!(f, "ConfigurationAndSWHardeningNeeded"),
            QeTcbStatus::SWHardeningNeeded => write!(f, "SWHardeningNeeded"),
            QeTcbStatus::OutOfDateConfigurationNeeded => write!(f, "OutOfDateConfigurationNeeded"),
            QeTcbStatus::Unspecified => write!(f, "Unspecified"),
        }
    }
}

#[cfg(feature = "full")]
#[allow(clippy::from_over_into)]
impl Into<TcbStatus> for QeTcbStatus {
    fn into(self) -> TcbStatus {
        match self {
            QeTcbStatus::UpToDate => TcbStatus::UpToDate,
            QeTcbStatus::OutOfDate => TcbStatus::OutOfDate,
            QeTcbStatus::Revoked => TcbStatus::Revoked,
            QeTcbStatus::ConfigurationNeeded => TcbStatus::ConfigurationNeeded,
            QeTcbStatus::ConfigurationAndSWHardeningNeeded => {
                TcbStatus::ConfigurationAndSWHardeningNeeded
            },
            QeTcbStatus::SWHardeningNeeded => TcbStatus::SWHardeningNeeded,
            QeTcbStatus::OutOfDateConfigurationNeeded => TcbStatus::OutOfDateConfigurationNeeded,
            QeTcbStatus::Unspecified => TcbStatus::Unspecified,
        }
    }
}

impl std::str::FromStr for QeTcbStatus {
    type Err = anyhow::Error;

    fn from_str(status: &str) -> Result<Self, Self::Err> {
        match status {
            "UpToDate" => Ok(QeTcbStatus::UpToDate),
            "OutOfDate" => Ok(QeTcbStatus::OutOfDate),
            "Revoked" => Ok(QeTcbStatus::Revoked),
            _ => Ok(QeTcbStatus::Unspecified),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EnclaveType {
    /// Quoting Enclave
    Qe,
    /// Quote Verification Enclave
    Qve,
    /// TDX Quoting Enclave
    #[serde(rename = "TD_QE")]
    TdQe,
}


// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_enclave_identity_serialization() {
//         let qe_identity = include_bytes!("../../data/qeidentityv2_apiv4.json");
//         let qe_identity: QuotingEnclaveIdentityAndSignature = serde_json::from_slice(qe_identity).unwrap();
//         let original_qe_identity = qe_identity.get_enclave_identity().unwrap();

//         let enclave_identity_bytes = borsh::to_vec(&original_qe_identity).unwrap();
//         let deserialized_qe_identity = EnclaveIdentity::try_from_slice(&enclave_identity_bytes).unwrap();

//         // Verify that the deserialized enclave identity matches the original
//         assert_eq!(original_qe_identity.id, deserialized_qe_identity.id);
//         assert_eq!(original_qe_identity.version, deserialized_qe_identity.version);
//         assert_eq!(original_qe_identity.issue_date, deserialized_qe_identity.issue_date);
//         assert_eq!(original_qe_identity.next_update, deserialized_qe_identity.next_update);
//         assert_eq!(original_qe_identity.miscselect, deserialized_qe_identity.miscselect);
//         assert_eq!(original_qe_identity.miscselect_mask, deserialized_qe_identity.miscselect_mask);
//         assert_eq!(original_qe_identity.attributes, deserialized_qe_identity.attributes);
//         assert_eq!(original_qe_identity.attributes_mask, deserialized_qe_identity.attributes_mask);
//         assert_eq!(original_qe_identity.mrsigner, deserialized_qe_identity.mrsigner);
//         assert_eq!(original_qe_identity.isvprodid, deserialized_qe_identity.isvprodid);
//         assert_eq!(original_qe_identity.tcb_levels.len(), deserialized_qe_identity.tcb_levels.len());

//         // Detailed verification of each tcb_level
//         for (i, original_tcb_level) in original_qe_identity.tcb_levels.iter().enumerate() {
//             let deserialized_tcb_level = &deserialized_qe_identity.tcb_levels[i];

//             // Verify TCB values
//             assert_eq!(original_tcb_level.tcb.isvsvn, deserialized_tcb_level.tcb.isvsvn);

//             // Verify TCB date
//             assert_eq!(original_tcb_level._tcb_date, deserialized_tcb_level._tcb_date);

//             // Verify TCB status
//             assert!(matches!(
//                 &original_tcb_level.tcb_status,
//                 status if std::mem::discriminant(status) == std::mem::discriminant(&deserialized_tcb_level.tcb_status)
//             ));

//             // Verify advisory IDs
//             match (&original_tcb_level.advisory_ids, &deserialized_tcb_level.advisory_ids) {
//                 (Some(original_ids), Some(deserialized_ids)) => {
//                     assert_eq!(original_ids.len(), deserialized_ids.len());
//                     for (j, original_id) in original_ids.iter().enumerate() {
//                         assert_eq!(original_id, &deserialized_ids[j]);
//                     }
//                 },
//                 (None, None) => {},
//                 _ => panic!("Advisory IDs mismatch in TCB level {}", i),
//             }
//         }
//     }
// }
