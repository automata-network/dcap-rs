use std::time::SystemTime;

use anyhow::{Context, bail};
use chrono::{DateTime, Utc};
use p256::ecdsa::VerifyingKey;
use p256::ecdsa::signature::Verifier;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use borsh::{BorshDeserialize, BorshSerialize};
use crate::utils::borsh_datetime_as_instant;

use super::{quote::{Quote, QuoteBody}, report::Td10ReportBody, sgx_x509::SgxPckExtension};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TcbInfoAndSignature {
    #[serde(rename = "tcbInfo")]
    tcb_info_raw: Box<RawValue>,
    #[serde(with = "hex")]
    signature: Vec<u8>,
}

impl TryFrom<String> for TcbInfoAndSignature {
    type Error = serde_json::Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        serde_json::from_str(&value)
    }
}

impl TcbInfoAndSignature {
    pub fn as_tcb_info_and_verify(
        &self,
        current_time: SystemTime,
        public_key: VerifyingKey,
    ) -> anyhow::Result<TcbInfo> {
        let tcb_info: TcbInfo =
            serde_json::from_str(self.tcb_info_raw.get()).context("tcb info")?;

        // Make sure current time is between issue_date and next_update
        let current_time: DateTime<Utc> = current_time.into();
        if current_time < tcb_info.issue_date || current_time > tcb_info.next_update {
            bail!("tcb info is not valid at current time");
        }

        let sig = p256::ecdsa::Signature::from_slice(&self.signature).unwrap();
        public_key
            .verify(self.tcb_info_raw.get().as_bytes(), &sig)
            .expect("valid signature expected");

        if tcb_info
            .tcb_levels
            .iter()
            .any(|e| e.tcb.version() != tcb_info.version)
        {
            bail!(
                "mismatched tcb info versions, should all be {:?}",
                tcb_info.version,
            );
        }

        // tcb_type determines how to compare tcb level
        // currently, only 0 is valid
        if tcb_info.tcb_type != 0 {
            bail!("unsupported tcb type {}", tcb_info.tcb_type,);
        }
        Ok(tcb_info)
    }

    pub fn get_tcb_info(&self) -> anyhow::Result<TcbInfo> {
        serde_json::from_slice(self.tcb_info_raw.get().as_bytes())
            .map_err(|e| anyhow::anyhow!("tcb info parsing failed: {}", e))
    }
}

/// Version of the TcbInfo JSON structure
///
/// In the PCS V3 API the TcbInfo version is V2, in the PCS V4 API the TcbInfo
/// version is V3. The V3 API includes advisoryIDs and changes the format of
/// the TcbLevel

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
#[serde(try_from = "u16")]
#[borsh(use_discriminant = true)]
pub(crate) enum TcbInfoVersion {
    V2 = 2,
    V3 = 3,
}

impl TryFrom<u16> for TcbInfoVersion {
    type Error = &'static str;
    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            2 => Ok(TcbInfoVersion::V2),
            3 => Ok(TcbInfoVersion::V3),
            _ => Err("Unsupported TCB Info version"),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Deserialize, Serialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
    #[serde(skip_serializing_if = "Option::is_none", rename = "id")]
    id: Option<String>,
    version: TcbInfoVersion,
    #[borsh(deserialize_with = "borsh_datetime_as_instant::deserialize", serialize_with = "borsh_datetime_as_instant::serialize")]
    pub issue_date: chrono::DateTime<Utc>,
    #[borsh(deserialize_with = "borsh_datetime_as_instant::deserialize", serialize_with = "borsh_datetime_as_instant::serialize")]
    pub next_update: chrono::DateTime<Utc>,
    #[serde(with = "hex")]
    pub fmspc: [u8; 6],
    #[serde(with = "hex")]
    pub pce_id: [u8; 2],
    tcb_type: u16,
    _tcb_evaluation_data_number: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    tdx_module: Option<TdxModule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tdx_module_identities: Option<Vec<TdxModuleIdentity>>,
    tcb_levels: Vec<TcbLevel>,
}

impl TcbInfo {
    pub fn verify_tdx_module(&self, quote_body: &Td10ReportBody) -> anyhow::Result<TcbStatus> {
        if self.tdx_module.is_none() {
            return Err(anyhow::anyhow!("no tdx module found in tcb info"));
        }

        let (tdx_module_isv_svn, tdx_module_version) =
            (quote_body.tee_tcb_svn[0], quote_body.tee_tcb_svn[1]);
        let tdx_module_identity_id = format!("TDX_{:02x}", tdx_module_version);

        if self.tdx_module_identities.is_none() {
            return Err(anyhow::anyhow!(
                "no tdx module identities found in tcb info"
            ));
        }

        let tdx_module_identity = self
            .tdx_module_identities
            .as_ref()
            .unwrap()
            .iter()
            .find(|identity| identity.id == tdx_module_identity_id)
            .ok_or(anyhow::anyhow!("tdx module identity not found in tcb info"))?;

        // Get the TDX module reference based on version
        let (mrsigner, attributes) = if tdx_module_version > 0 {
            (
                &tdx_module_identity.mrsigner,
                &tdx_module_identity.attributes,
            )
        } else {
            let tdx_module = self.tdx_module.as_ref().unwrap();
            (&tdx_module.mrsigner, &tdx_module.attributes)
        };

        // Check for mismatches with a single validation
        if mrsigner != &quote_body.mr_signer_seam {
            return Err(anyhow::anyhow!(
                "mrsigner mismatch between tdx module identity and tdx quote body"
            ));
        }

        if attributes != &quote_body.seam_attributes {
            return Err(anyhow::anyhow!(
                "attributes mismatch between tdx module identity and tdx quote body"
            ));
        }

        let tcb_level = tdx_module_identity
            .tcb_levels
            .iter()
            .find(|level| level.in_tcb_level(tdx_module_isv_svn))
            .ok_or(anyhow::anyhow!(
                "no tcb level found for tdx module identity within tdx module levels"
            ))?;

        Ok(tcb_level.tcb_status)
    }

    pub fn converge_tcb_status_with_tdx_module(
        platform_status: TcbStatus,
        tdx_module_status: TcbStatus,
    ) -> TcbStatus {
        // Only adjust if TDX module is OutOfDate
        if tdx_module_status != TcbStatus::OutOfDate {
            return tdx_module_status;
        }

        match platform_status {
            TcbStatus::UpToDate | TcbStatus::SWHardeningNeeded => TcbStatus::OutOfDate,

            TcbStatus::ConfigurationNeeded | TcbStatus::ConfigurationAndSWHardeningNeeded => {
                TcbStatus::OutOfDateConfigurationNeeded
            },

            _ => platform_status,
        }
    }
    /// Converge platform TCB status with QE TCB status
    ///
    /// This function implements the rules for combining platform and Quote Enclave TCB
    /// status values, prioritizing the more severe status according to Intel's rules.
    pub fn converge_tcb_status_with_qe_tcb(
        platform_status: TcbStatus,
        qe_status: TcbStatus,
    ) -> TcbStatus {
        // Only adjust status if QE is OutOfDate
        if qe_status != TcbStatus::OutOfDate {
            return platform_status;
        }

        match platform_status {
            // These statuses get overridden to OutOfDate
            TcbStatus::UpToDate | TcbStatus::SWHardeningNeeded => TcbStatus::OutOfDate,

            // These statuses change to reflect both configuration and outdated problems
            TcbStatus::ConfigurationNeeded | TcbStatus::ConfigurationAndSWHardeningNeeded => {
                TcbStatus::OutOfDateConfigurationNeeded
            },

            // All other statuses remain unchanged
            _ => platform_status,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        borsh::from_slice::<TcbInfo>(bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse TcbInfo: {}", e))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    pub tcb: Tcb,
    #[borsh(deserialize_with = "borsh_datetime_as_instant::deserialize", serialize_with = "borsh_datetime_as_instant::serialize")]
    pub tcb_date: chrono::DateTime<Utc>,
    pub tcb_status: TcbStatus,
    #[serde(rename = "advisoryIDs", skip_serializing_if = "Option::is_none")]
    pub advisory_ids: Option<Vec<String>>,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, Deserialize, Serialize, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
pub enum TcbStatus {
    UpToDate,
    OutOfDate,
    ConfigurationNeeded,
    SWHardeningNeeded,
    ConfigurationAndSWHardeningNeeded,
    OutOfDateConfigurationNeeded,
    Revoked,
    Unspecified,
}

impl std::fmt::Display for TcbStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcbStatus::UpToDate => write!(f, "UpToDate"),
            TcbStatus::OutOfDate => write!(f, "OutOfDate"),
            TcbStatus::ConfigurationNeeded => write!(f, "ConfigurationNeeded"),
            TcbStatus::SWHardeningNeeded => write!(f, "SWHardeningNeeded"),
            TcbStatus::ConfigurationAndSWHardeningNeeded => write!(f, "ConfigurationAndSWHardeningNeeded"),
            TcbStatus::OutOfDateConfigurationNeeded => write!(f, "OutOfDateConfigurationNeeded"),
            TcbStatus::Revoked => write!(f, "Revoked"),
            TcbStatus::Unspecified => write!(f, "Unspecified"),
        }
    }
}

/// Contains information identifying a TcbLevel.
#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug, BorshSerialize, BorshDeserialize)]
#[serde(untagged)]
#[borsh(use_discriminant = true)]
pub enum Tcb {
    V2(TcbV2),
    V3(TcbV3),
}

impl Tcb {
    fn version(&self) -> TcbInfoVersion {
        match self {
            Tcb::V2(_) => TcbInfoVersion::V2,
            Tcb::V3(_) => TcbInfoVersion::V3,
        }
    }
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct TcbV3 {
    sgxtcbcomponents: [TcbComponentV3; 16],
    #[serde(skip_serializing_if = "Option::is_none")]
    tdxtcbcomponents: Option<[TcbComponentV3; 16]>,
    pcesvn: u16,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug, Copy, BorshSerialize, BorshDeserialize)]
pub struct TcbComponentV3 {
    svn: u8,
}


#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct TcbV2 {
    sgxtcbcomp01svn: u8,
    sgxtcbcomp02svn: u8,
    sgxtcbcomp03svn: u8,
    sgxtcbcomp04svn: u8,
    sgxtcbcomp05svn: u8,
    sgxtcbcomp06svn: u8,
    sgxtcbcomp07svn: u8,
    sgxtcbcomp08svn: u8,
    sgxtcbcomp09svn: u8,
    sgxtcbcomp10svn: u8,
    sgxtcbcomp11svn: u8,
    sgxtcbcomp12svn: u8,
    sgxtcbcomp13svn: u8,
    sgxtcbcomp14svn: u8,
    sgxtcbcomp15svn: u8,
    sgxtcbcomp16svn: u8,
    pcesvn: u16,
}

impl Tcb {
    pub fn pcesvn(&self) -> u16 {
        match self {
            Self::V2(v2) => v2.pcesvn,
            Self::V3(v3) => v3.pcesvn,
        }
    }

    pub fn sgx_tcb_components(&self) -> [u8; 16] {
        match self {
            Self::V2(v2) => [
                v2.sgxtcbcomp01svn,
                v2.sgxtcbcomp02svn,
                v2.sgxtcbcomp03svn,
                v2.sgxtcbcomp04svn,
                v2.sgxtcbcomp05svn,
                v2.sgxtcbcomp06svn,
                v2.sgxtcbcomp07svn,
                v2.sgxtcbcomp08svn,
                v2.sgxtcbcomp09svn,
                v2.sgxtcbcomp10svn,
                v2.sgxtcbcomp11svn,
                v2.sgxtcbcomp12svn,
                v2.sgxtcbcomp13svn,
                v2.sgxtcbcomp14svn,
                v2.sgxtcbcomp15svn,
                v2.sgxtcbcomp16svn,
            ],
            Self::V3(v3) => v3.sgxtcbcomponents.map(|comp| comp.svn),
        }
    }

    pub fn tdx_tcb_components(&self) -> Option<[u8; 16]> {
        match self {
            Self::V2(_) => None,
            Self::V3(v3) => v3.tdxtcbcomponents.map(|components| components.map(|comp| comp.svn)),
        }
    }
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModule {
    #[serde(with = "hex", rename = "mrsigner")]
    mrsigner: [u8; 48],
    #[serde(with = "hex")]
    attributes: [u8; 8],
    #[serde(with = "hex")]
    attributes_mask: [u8; 8],
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModuleIdentity {
    #[serde(rename = "id")]
    id: String,
    #[serde(with = "hex", rename = "mrsigner")]
    mrsigner: [u8; 48],
    #[serde(with = "hex")]
    attributes: [u8; 8],
    #[serde(with = "hex")]
    attributes_mask: [u8; 8],
    tcb_levels: Vec<TdxTcbLevel>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxTcbLevel {
    tcb: TcbTdx,
    #[borsh(deserialize_with = "borsh_datetime_as_instant::deserialize", serialize_with = "borsh_datetime_as_instant::serialize")]
    tcb_date: chrono::DateTime<Utc>,
    tcb_status: TcbStatus,
    #[serde(rename = "advisoryIDs", skip_serializing_if = "Option::is_none")]
    advisory_ids: Option<Vec<String>>,
}

impl TdxTcbLevel {
    pub fn in_tcb_level(&self, isv_svn: u8) -> bool {
        self.tcb.isvsvn <= isv_svn
    }
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct TcbTdx {
    isvsvn: u8,
}

impl TcbStatus {

    /// Determine the status of the TCB level that is trustable for the platform
    ///
    /// This function performs TCB (Trusted Computing Base) level verification by:
    /// 1. Finding a matching SGX TCB level based on PCK extension values
    /// 2. Extracting the SGX TCB status and advisories
    /// 3. Checking for TDX TCB status if applicable
    ///
    /// Returns:
    ///   - A tuple containing (sgx_tcb_status, tdx_tcb_status, advisory_ids)
    ///   - sgx_tcb_status: Status of SGX platform components
    ///   - tdx_tcb_status: Status of TDX components (defaults to Unspecified if not applicable)
    ///   - advisory_ids: List of security advisories affecting this TCB level
    pub fn lookup(
        pck_extension: &SgxPckExtension,
        tcb_info: &TcbInfo,
        quote: &Quote,
    ) -> anyhow::Result<(Self, Self, Vec<String>)> {
        // Find first matching TCB level with its index
        let (index, first_matching_level) = tcb_info
            .tcb_levels
            .iter()
            .enumerate()
            .find(|(_, level)| TcbStatus::pck_in_tcb_level(level, pck_extension))
            .ok_or_else(|| anyhow::anyhow!("unsupported TCB in pck extension"))?;

        // Extract the SGX TCB status and advisories from the matching level
        let sgx_tcb_status = first_matching_level.tcb_status;
        let mut advisory_ids = first_matching_level.advisory_ids.clone().unwrap_or_default();

        // Default TDX TCB status to Unspecified
        // Will be updated if a valid TDX module is found in the quote
        let mut tdx_tcb_status = TcbStatus::Unspecified;

        // Check if the quote contains a TDX module (TD 1.0 Quote Body)
        if let QuoteBody::Td10QuoteBody(body) = &quote.body {
            // Start iterating from the found sgx matching level
            for level in &tcb_info.tcb_levels[index..] {
                // Process each level starting from the matching one
                if let Some(tdx_tcb_components) = level.tcb.tdx_tcb_components() {
                    let components_match = tdx_tcb_components
                        .iter()
                        .zip(body.tee_tcb_svn.iter())
                        .all(|(&comp, &svn)| comp >= svn);

                    if components_match {
                        tdx_tcb_status = level.tcb_status;
                        advisory_ids = level.advisory_ids.clone().unwrap_or_default();
                        break;
                    }
                } else {
                    // This should not happen, meaning if you have a Td10QuoteBody, you should have a TDX TCB Component present in the TCB Info
                    return Err(anyhow::anyhow!("did not find tdx tcb components in tcb info when Td10QuoteBody is provided for the quote"));
                }
            }
        }

        // Return the final status determination as a tuple
        Ok((sgx_tcb_status, tdx_tcb_status, advisory_ids))
    }

    /// Returns true if all the pck componenets are >= all the tcb level components and e
    /// the pck pcesvn is >= the tcb level pcesvn.
    fn pck_in_tcb_level(level: &TcbLevel, pck_extension: &SgxPckExtension) -> bool {
        const SVN_LENGTH: usize = 16;
        let pck_components: &[u8; SVN_LENGTH] = &pck_extension.tcb.compsvn;

        pck_components
            .iter()
            .zip(level.tcb.sgx_tcb_components())
            .all(|(&pck, tcb)| pck >= tcb)
            && pck_extension.tcb.pcesvn >= level.tcb.pcesvn()
    }

}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parsing_tcb_info_without_tdx_module() {
        let json = include_str!("../../data/tcb_info_v2.json");
        let tcb_info_and_signature: TcbInfoAndSignature = serde_json::from_str(json).unwrap();
        let tcb_info = tcb_info_and_signature.get_tcb_info().unwrap();

        assert_eq!(tcb_info.tdx_module.is_none(), true);
    }

    #[test]
    fn test_parsing_tcb_info_with_tdx_module() {
        let json = include_str!("../../data/tcb_info_v3_with_tdx_module.json");
        let tcb_info_and_signature: TcbInfoAndSignature = serde_json::from_str(json).unwrap();
        let original_tcb_info = tcb_info_and_signature.get_tcb_info().unwrap();
        assert_eq!(original_tcb_info.tdx_module.is_some(), true);

        // Serialize and Deserialize the TcbInfo
        let tcb_info_borsh = borsh::to_vec(&original_tcb_info).unwrap();
        let tcb_info_deserialized: TcbInfo = borsh::from_slice(&tcb_info_borsh).unwrap();

        // 3. Verify that deserialized matches original
        assert_eq!(original_tcb_info.version, tcb_info_deserialized.version);
        assert_eq!(original_tcb_info.issue_date, tcb_info_deserialized.issue_date);
        assert_eq!(original_tcb_info.next_update, tcb_info_deserialized.next_update);
        assert_eq!(original_tcb_info.fmspc, tcb_info_deserialized.fmspc);
        assert_eq!(original_tcb_info.pce_id, tcb_info_deserialized.pce_id);
        assert_eq!(original_tcb_info.tcb_type, tcb_info_deserialized.tcb_type);

        if let Some(original_tdx) = &original_tcb_info.tdx_module {
            let deserialized_tdx = tcb_info_deserialized.tdx_module.as_ref().unwrap();
            assert_eq!(original_tdx.mrsigner, deserialized_tdx.mrsigner);
            assert_eq!(original_tdx.attributes, deserialized_tdx.attributes);
            assert_eq!(original_tdx.attributes_mask, deserialized_tdx.attributes_mask);
        }

        // 5. Test TcbLevels
        assert_eq!(original_tcb_info.tcb_levels.len(), tcb_info_deserialized.tcb_levels.len());

        // Test the first TcbLevel in detail
        let original_level = &original_tcb_info.tcb_levels[0];
        let deserialized_level = &tcb_info_deserialized.tcb_levels[0];

        assert_eq!(original_level.tcb_date, deserialized_level.tcb_date);
        assert_eq!(original_level.tcb_status, deserialized_level.tcb_status);

        // Test TcbLevel.tcb
        match (&original_level.tcb, &deserialized_level.tcb) {
            (Tcb::V2(original_v2), Tcb::V2(deserialized_v2)) => {
                assert_eq!(original_v2.pcesvn, deserialized_v2.pcesvn);
                assert_eq!(original_v2.sgxtcbcomp01svn, deserialized_v2.sgxtcbcomp01svn);
                // Add more component checks as needed
            },
            (Tcb::V3(original_v3), Tcb::V3(deserialized_v3)) => {
                assert_eq!(original_v3.pcesvn, deserialized_v3.pcesvn);
                assert_eq!(original_v3.sgxtcbcomponents.len(), deserialized_v3.sgxtcbcomponents.len());

                // Check if tdxtcbcomponents exist and match
                if let Some(original_tdx_comps) = &original_v3.tdxtcbcomponents {
                    let deserialized_tdx_comps = deserialized_v3.tdxtcbcomponents.as_ref().unwrap();
                    assert_eq!(original_tdx_comps.len(), deserialized_tdx_comps.len());
                    for (i, comp) in original_tdx_comps.iter().enumerate() {
                        assert_eq!(comp.svn, deserialized_tdx_comps[i].svn);
                    }
                }
            },
            _ => panic!("Tcb variant mismatch after deserialization"),
        }

        // Test TdxModuleIdentities if present
        if let Some(original_identities) = &original_tcb_info.tdx_module_identities {
            let deserialized_identities = tcb_info_deserialized.tdx_module_identities.as_ref().unwrap();
            assert_eq!(original_identities.len(), deserialized_identities.len());

            // Test the first TdxModuleIdentity
            let original_identity = &original_identities[0];
            let deserialized_identity = &deserialized_identities[0];

            assert_eq!(original_identity.id, deserialized_identity.id);
            assert_eq!(original_identity.mrsigner, deserialized_identity.mrsigner);
            assert_eq!(original_identity.attributes, deserialized_identity.attributes);
            assert_eq!(original_identity.attributes_mask, deserialized_identity.attributes_mask);

            // Test TcbLevels in TdxModuleIdentity
            assert_eq!(
                original_identity.tcb_levels.len(),
                deserialized_identity.tcb_levels.len()
            );

            if !original_identity.tcb_levels.is_empty() {
                let original_tdx_level = &original_identity.tcb_levels[0];
                let deserialized_tdx_level = &deserialized_identity.tcb_levels[0];

                assert_eq!(original_tdx_level.tcb.isvsvn, deserialized_tdx_level.tcb.isvsvn);
                assert_eq!(original_tdx_level.tcb_date, deserialized_tdx_level.tcb_date);
                assert_eq!(original_tdx_level.tcb_status, deserialized_tdx_level.tcb_status);
            }
        }
    }
}
