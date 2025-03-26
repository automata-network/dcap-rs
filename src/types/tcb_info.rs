use std::time::SystemTime;

use anyhow::{Context, bail};
use chrono::{DateTime, Utc};
use p256::ecdsa::VerifyingKey;
use p256::ecdsa::signature::Verifier;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use super::{report::Td10ReportBody, sgx_x509::SgxPckExtension};

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
        serde_json::from_str(self.tcb_info_raw.get())
            .map_err(|e| anyhow::anyhow!("tcb info parsing failed: {}", e))
    }
}

/// Version of the TcbInfo JSON structure
///
/// In the PCS V3 API the TcbInfo version is V2, in the PCS V4 API the TcbInfo
/// version is V3. The V3 API includes advisoryIDs and changes the format of
/// the TcbLevel

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
#[serde(try_from = "u16")]
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

#[derive(Debug, Eq, PartialEq, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
    #[serde(skip_serializing_if = "Option::is_none", rename = "id")]
    id: Option<String>,
    version: TcbInfoVersion,
    pub issue_date: chrono::DateTime<Utc>,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    pub tcb: Tcb,
    pub tcb_date: chrono::DateTime<Utc>,
    pub tcb_status: TcbStatus,
    #[serde(rename = "advisoryIDs", skip_serializing_if = "Option::is_none")]
    pub advisory_ids: Option<Vec<String>>,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, Deserialize, Serialize)]
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

/// Contains information identifying a TcbLevel.
#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug)]
#[serde(untagged)]
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

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug)]
pub struct TcbV3 {
    sgxtcbcomponents: [TcbComponentV3; 16],
    pcesvn: u16,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug, Copy)]
pub struct TcbComponentV3 {
    svn: u8,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug)]
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

    pub fn components(&self) -> [u8; 16] {
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
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TdxModule {
    #[serde(with = "hex", rename = "mrsigner")]
    mrsigner: [u8; 48],
    #[serde(with = "hex")]
    attributes: [u8; 8],
    #[serde(with = "hex")]
    attributes_mask: [u8; 8],
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug)]
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

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TdxTcbLevel {
    tcb: TcbTdx,
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

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug)]
pub struct TcbTdx {
    isvsvn: u8,
}

impl TcbStatus {
    /// Determine the status of the TCB level that is trustable for the platform represented
    /// by `pck_extension`.
    ///
    /// Returns the TCB status and the advisory IDs that are associated with the TCB level.
    pub fn lookup(
        pck_extension: &SgxPckExtension,
        tcb_info: &TcbInfo,
    ) -> anyhow::Result<(Self, Vec<String>)> {
        let first_matching_level = tcb_info
            .tcb_levels
            .iter()
            .find(|level| TcbStatus::in_tcb_level(level, pck_extension));

        first_matching_level
            .map(|level| {
                Ok((
                    level.tcb_status,
                    level.advisory_ids.clone().unwrap_or_default(),
                ))
            })
            .unwrap_or_else(|| Err(anyhow::anyhow!("unsupported TCB in pck extension")))
    }

    /// Returns true if all the pck componenets are >= all the tcb level components and e
    /// the pck pcesvn is >= the tcb level pcesvn.
    fn in_tcb_level(level: &TcbLevel, pck_extension: &SgxPckExtension) -> bool {
        const SVN_LENGTH: usize = 16;
        let pck_components: &[u8; SVN_LENGTH] = &pck_extension.tcb.compsvn;

        pck_components
            .iter()
            .zip(level.tcb.components())
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
        let tcb_info = tcb_info_and_signature.get_tcb_info().unwrap();

        assert_eq!(tcb_info.tdx_module.is_some(), true);
    }
}
