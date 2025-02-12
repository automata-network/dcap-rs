use serde::{Deserialize, Serialize};

pub enum TcbInfo {
    V2(TcbInfoV2),
    V3(TcbInfoV3)
}

// TcbInfoV2:
//     type: object
//     description: >-
//         SGX TCB Info encoded as JSON string in case of success (200 HTTP
//         status code)
//     properties:
//         tcbInfo:
//             type: object
//             properties:
//                 version:
//                     type: integer
//                     example: 2
//                     description: Version of the structure
//                 issueDate:
//                     type: string
//                     format: date-time
//                     description: >-
//                         Representation of date and time the TCB information
//                         was created. The time shall be in UTC and the
//                         encoding shall be compliant to ISO 8601 standard
//                         (YYYY-MM-DDThh:mm:ssZ)
//                 nextUpdate:
//                     type: string
//                     format: date-time
//                     description: >-
//                         Representation of date and time by which next TCB
//                         information will be issued. The time shall be in UTC
//                         and the encoding shall be compliant to ISO 8601
//                         standard (YYYY-MM-DDThh:mm:ssZ)
//                 fmspc:
//                     type: string
//                     pattern: ^[0-9a-fA-F]{12}$
//                     example: '000000000000'
//                     description: >-
//                         Base 16-encoded string representation of FMSPC
//                         (Family-Model-Stepping-Platform-CustomSKU)
//                 pceId:
//                     type: string
//                     pattern: ^[0-9a-fA-F]{4}$
//                     example: '0000'
//                     description: Base 16-encoded string representation of PCE identifier
//                 tcbType:
//                     type: integer
//                     example: 0
//                     description: >-
//                         Type of TCB level composition that determines TCB
//                         level comparison logic
//                 tcbEvaluationDataNumber:
//                     type: integer
//                     example: 2
//                     description: >-
//                         A monotonically increasing sequence number changed
//                         when Intel updates the content of the TCB evaluation data
//                         set: TCB Info, QE Idenity and QVE Identity. The tcbEvaluationDataNumber
//                         update is synchronized across TCB Info for all flavors of
//                         SGX CPUs (Family-Model-Stepping-Platform-CustomSKU) and QE/QVE
//                         Identity. This sequence number allows users to easily determine
//                         when a particular TCB Info/QE Idenity/QVE Identiy superseedes
//                         another TCB Info/QE Identity/QVE Identity (value: current
//                         TCB Recovery event number stored in the database).
//                 tcbLevels:
//                     type: array
//                     description: >-
//                         Sorted list of supported TCB levels for given FMSPC
//                         encoded as a JSON array of TCB level objects
//                     items:
//                         type: object
//                         properties:
//                             tcb:
//                                 type: object
//                                 properties:
//                                     pcesvn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 65535
//                                     sgxtcbcomp01svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp02svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp03svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp04svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp05svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp06svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp07svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp08svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp09svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp10svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp11svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp12svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp13svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp14svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp15svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp16svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                             tcbDate:
//                                 type: string
//                                 format: date-time
//                                 description: >-
//                                     If there are security advisories published by Intel after tcbDate
//                                     that are for issues whose mitigations are currently enforced* by SGX attestation,
//                                     then the value of tcbStatus for the TCB level will not be UpToDate.
//                                     Otherwise (i.e., either no advisories after or not currently enforced),
//                                     the value of tcbStatus for the TCB level will not be OutOfDate.
// 
//                                     The time shall be in UTC and the encoding shall
//                                     be compliant to ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ).
//                             tcbStatus:
//                                 type: string
//                                 enum:
//                                     - UpToDate
//                                     - SWHardeningNeeded
//                                     - ConfigurationNeeded
//                                     - ConfigurationAndSWHardeningNeeded
//                                     - OutOfDate
//                                     - OutOfDateConfigurationNeeded
//                                     - Revoked
//                                 description: >-
//                                     TCB level status. One of the following values:
// 
//                                     "UpToDate" - TCB level of the SGX platform is up-to-date.
// 
//                                     "SWHardeningNeeded" - TCB level of the SGX platform
//                                     is up-to-date but due to certain issues affecting the
//                                     platform, additional SW Hardening in the attesting
//                                     SGX enclaves may be needed.
// 
//                                     "ConfigurationNeeded" - TCB level of the SGX platform
//                                     is up-to-date but additional configuration of SGX
//                                     platform may be needed.
// 
//                                     "ConfigurationAndSWHardeningNeeded" - TCB level of the
//                                     SGX platform is up-to-date but additional configuration
//                                     for the platform and SW Hardening in the attesting SGX
//                                     enclaves may be needed.
// 
//                                     "OutOfDate" - TCB level of SGX platform is outdated.
// 
//                                     "OutOfDateConfigurationNeeded" - TCB level of SGX
//                                     platform is outdated and additional configuration
//                                     of SGX platform may be needed.
// 
//                                     "Revoked" - TCB level of SGX platform is revoked.
//                                     The platform is not trustworthy.
//                             ZL: This new field is added for v3, seems like a mistake in Intel's documentation.
//                                 Going to keep it here for now.
//                             advisoryIDs:
//                                 type: array
//                                 description: >-
//                                     Array of Advisory IDs referring to Intel security advisories that
//                                     provide insight into the reason(s) for the value of tcbStatus for
//                                     this TCB level when the value is not UpToDate.
// 
//                                     Note: The value can be different for different
//                                     FMSPCs.
// 
//                                     This field is optional. It will be present only
//                                     if the list of Advisory IDs is not empty.
//                                 items:
//                                     type: string
//         signature:
//             type: string
//             description: >-
//                 Base 16-encoded string representation of signature calculated over tcbInfo
//                 body without whitespaces using TCB Signing Key
//                 i.e:
//                 {"version":2,"issueDate":"2019-07-30T12:00:00Z","nextUpdate":"2019-08-30T12:00:00Z",...}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV2 {
    pub tcb_info: TcbInfoV2Inner,
    pub signature: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV2Inner {
    pub version: u32,
    pub issue_date: String,
    pub next_update: String,
    pub fmspc: String,
    pub pce_id: String,
    pub tcb_type: u8,
    pub tcb_evaluation_data_number: u32,
    pub tcb_levels: Vec<TcbInfoV2TcbLevelItem>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV2TcbLevelItem {
    pub tcb: TcbInfoV2TcbLevel,
    pub tcb_date: String,
    pub tcb_status: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV2TcbLevel {
    pub sgxtcbcomp01svn: u8,
    pub sgxtcbcomp02svn: u8,
    pub sgxtcbcomp03svn: u8,
    pub sgxtcbcomp04svn: u8,
    pub sgxtcbcomp05svn: u8,
    pub sgxtcbcomp06svn: u8,
    pub sgxtcbcomp07svn: u8,
    pub sgxtcbcomp08svn: u8,
    pub sgxtcbcomp09svn: u8,
    pub sgxtcbcomp10svn: u8,
    pub sgxtcbcomp11svn: u8,
    pub sgxtcbcomp12svn: u8,
    pub sgxtcbcomp13svn: u8,
    pub sgxtcbcomp14svn: u8,
    pub sgxtcbcomp15svn: u8,
    pub sgxtcbcomp16svn: u8,
    pub pcesvn: u16,
}
// TcbInfoV3:
//     type: object
//     description: >-
//         SGX TCB Info encoded as JSON string in case of success (200 HTTP
//         status code)
//     properties:
//         tcbInfo:
//             type: object
//             properties:
//                 id:
//                     type: string
//                     description: Identifier of the TCB Info issued by Intel. Supported values are SGX or TDX.
//                 version:
//                     type: integer
//                     example: 2
//                     description: Version of the structure
//                 issueDate:
//                     type: string
//                     format: date-time
//                     description: >-
//                         Representation of date and time the TCB information
//                         was created. The time shall be in UTC and the
//                         encoding shall be compliant to ISO 8601 standard
//                         (YYYY-MM-DDThh:mm:ssZ)
//                 nextUpdate:
//                     type: string
//                     format: date-time
//                     description: >-
//                         Representation of date and time by which next TCB
//                         information will be issued. The time shall be in UTC
//                         and the encoding shall be compliant to ISO 8601
//                         standard (YYYY-MM-DDThh:mm:ssZ)
//                 fmspc:
//                     type: string
//                     pattern: ^[0-9a-fA-F]{12}$
//                     example: '000000000000'
//                     description: >-
//                         Base 16-encoded string representation of FMSPC
//                         (Family-Model-Stepping-Platform-CustomSKU)
//                 pceId:
//                     type: string
//                     pattern: ^[0-9a-fA-F]{4}$
//                     example: '0000'
//                     description: Base 16-encoded string representation of PCE identifier
//                 tcbType:
//                     type: integer
//                     example: 0
//                     description: >-
//                         Type of TCB level composition that determines TCB
//                         level comparison logic
//                 tcbEvaluationDataNumber:
//                     type: integer
//                     example: 2
//                     description: >-
//                         A monotonically increasing sequence number changed
//                         when Intel updates the content of the TCB evaluation data
//                         set: TCB Info, QE Idenity and QVE Identity. The tcbEvaluationDataNumber
//                         update is synchronized across TCB Info for all flavors of
//                         SGX CPUs (Family-Model-Stepping-Platform-CustomSKU) and QE/QVE
//                         Identity. This sequence number allows users to easily determine
//                         when a particular TCB Info/QE Idenity/QVE Identiy superseedes
//                         another TCB Info/QE Identity/QVE Identity (value: current
//                         TCB Recovery event number stored in the database).
//                 tdxModule:
//                     type: object
//                     description: >-
//                         This field is optional. It will be present only
//                         in context of TDX TCB Info.
//                     properties:
//                         mrsigner:
//                             type: string
//                             pattern: ^[0-9a-fA-F]{96}$
//                             example: '0000000000000000000000000000000000000000000000000000000000000000'
//                             description: Base 16-encoded string representation of the measurement of a TDX SEAM module's signer.
//                         attributes:
//                             type: string
//                             pattern: ^[0-9a-fA-F]{16}$
//                             example: '0000000000000000'
//                             description: Hex-encoded byte array (8 bytes) representing attributes "golden" value (upon applying mask) for TDX SEAM module.
//                         attributesMask:
//                             type: string
//                             pattern: ^[0-9a-fA-F]{16}$
//                             example: 'FFFFFFFFFFFFFFFF'
//                             description: Hex-encoded byte array (8 bytes) representing mask to be applied to TDX SEAM module's attributes value retrieved from the platform.
//                 tdxModuleIdentities:
//                     type: array
//                     description: >-
//                         This field is optional. It will be present only in context of TDX TCB Info when the platform supports more than one TDX SEAM Module.
//                     items:
//                         type: object
//                         properties:
//                             id:
//                                 type: string
//                                 description: Identifier of TDX Module
//                             mrsigner:
//                                 type: string
//                                 pattern: ^[0-9a-fA-F]{96}$
//                                 example: '0000000000000000000000000000000000000000000000000000000000000000'
//                                 description: Base 16-encoded string representation of the measurement of a TDX SEAM module's signer.
//                             attributes:
//                                 type: string
//                                 pattern: ^[0-9a-fA-F]{16}$
//                                 example: '0000000000000000'
//                                 description: Base 16-encoded string representation of the byte array (8 bytes) representing attributes "golden" value (upon applying mask) for TDX SEAM module.
//                             attributesMask:
//                                 type: string
//                                 pattern: ^[0-9a-fA-F]{16}$
//                                 example: 'FFFFFFFFFFFFFFFF'
//                                 description: Base 16-encoded string representation of the byte array (8 bytes) representing mask to be applied to TDX SEAM module's attributes value retrieved from the platform.
//                             tcbLevels:
//                                 type: array
//                                 description: >-
//                                     Sorted list of supported TCB levels for given TDX SEAM module encoded as a JSON array of TCB level objects.
//                                 items:
//                                     type: object
//                                     properties:
//                                         tcb:
//                                             type: object
//                                             properties:
//                                                 isvnsvn:
//                                                     description: TDX SEAM module's ISV SVN
//                                                     type: integer
//                                         tcbDate:
//                                             type: string
//                                             format: date-time
//                                             description: >-
//                                                 If there are security advisories published by Intel after tcbDate
//                                                 that are for issues whose mitigations are currently enforced* by SGX/TDX attestation,
//                                                 then the value of tcbStatus for the TCB level will not be UpToDate.
//                                                 Otherwise (i.e., either no advisories after or not currently enforced),
//                                                 the value of tcbStatus for the TCB level will not be OutOfDate.
// 
//                                                 The time shall be in UTC and the encoding shall
//                                                 be compliant to ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ).
//                                         tcbStatus:
//                                             type: string
//                                             enum:
//                                                 - UpToDate
//                                                 - OutOfDate
//                                                 - Revoked
//                                             description: >-
//                                                 TCB level status. One of the following values:
// 
//                                                 "UpToDate" - TCB level of the TDX SEAM Module is up-to-date.
// 
//                                                 "OutOfDate" - TCB level of TDX SEAM Module is outdated.
// 
//                                                 "Revoked" - TCB level of TDX SEAM Module is revoked.
//                                                 The platform is not trustworthy.
//                                         advisoryIDs:
//                                             type: array
//                                             description: >-
//                                                 Array of Advisory IDs referring to Intel security advisories that
//                                                 provide insight into the reason(s) for the value of tcbStatus for
//                                                 this TCB level when the value is not UpToDate.
// 
//                                                 This field is optional. It will be present only
//                                                 if the list of Advisory IDs is not empty.
//                                             items:
//                                                 type: string
//                 tcbLevels:
//                     type: array
//                     description: >-
//                         Sorted list of supported TCB levels for given FMSPC
//                         encoded as a JSON array of TCB level objects
//                     items:
//                         type: object
//                         properties:
//                             tcb:
//                                 type: object
//                                 properties:
//                                     sgxtcbcomponents:
//                                         description: >-
//                                             Array of 16 SGX TCB Components (as in CPUSVN) encoded as a JSON array of TCB Component objects.
//                                         items:
//                                             properties:
//                                                 svn:
//                                                     type: "integer"
//                                                     description: SVN of TCB Component. This field is mandatory.
//                                                 category:
//                                                     type: "string"
//                                                     description: Category of TCB Component (e.g. ucode, BIOS, SW). This field is optional and will be present only for selected TCB Components.
//                                                 type:
//                                                     type: "string"
//                                                     description: Type of TCB Component (e.g. Patch@Reset, Late Patch). This field is optional and will be present only for selected TCB Components.
//                                     pcesvn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 65535
//                                     tdxtcbcomponents:
//                                         description: >-
//                                             Array of 16 TDX TCB Components (as in TEE TCB SVN array in TD Report) encoded as a JSON array of TCB Component objects.
// 
//                                             This field is optional and only present in TDX TCB Info.
//                                         items:
//                                             properties:
//                                                 svn:
//                                                     type: "integer"
//                                                     description: SVN of TCB Component. This field is mandatory.
//                                                 category:
//                                                     type: "string"
//                                                     description: Category of TCB Component (e.g. ucode, BIOS, SW). This field is optional and will be present only for selected TCB Components.
//                                                 type:
//                                                     type: "string"
//                                                     description: Type of TCB Component (e.g. Patch@Reset, Late Patch). This field is optional and will be present only for selected TCB Components.
//                             tcbDate:
//                                 type: string
//                                 format: date-time
//                                 description: >-
//                                     If there are security advisories published by Intel after tcbDate
//                                     that are for issues whose mitigations are currently enforced* by SGX attestation,
//                                     then the value of tcbStatus for the TCB level will not be UpToDate.
//                                     Otherwise (i.e., either no advisories after or not currently enforced),
//                                     the value of tcbStatus for the TCB level will not be OutOfDate.
// 
//                                     The time shall be in UTC and the encoding shall
//                                     be compliant to ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ).
//                             tcbStatus:
//                                 type: string
//                                 enum:
//                                     - UpToDate
//                                     - SWHardeningNeeded
//                                     - ConfigurationNeeded
//                                     - ConfigurationAndSWHardeningNeeded
//                                     - OutOfDate
//                                     - OutOfDateConfigurationNeeded
//                                     - Revoked
//                                 description: >-
//                                     TCB level status. One of the following values:
// 
//                                     "UpToDate" - TCB level of the SGX platform is up-to-date.
// 
//                                     "SWHardeningNeeded" - TCB level of the SGX platform
//                                     is up-to-date but due to certain issues affecting the
//                                     platform, additional SW Hardening in the attesting
//                                     SGX enclaves may be needed.
// 
//                                     "ConfigurationNeeded" - TCB level of the SGX platform
//                                     is up-to-date but additional configuration of SGX
//                                     platform may be needed.
// 
//                                     "ConfigurationAndSWHardeningNeeded" - TCB level of the
//                                     SGX platform is up-to-date but additional configuration
//                                     for the platform and SW Hardening in the attesting SGX
//                                     enclaves may be needed.
// 
//                                     "OutOfDate" - TCB level of SGX platform is outdated.
// 
//                                     "OutOfDateConfigurationNeeded" - TCB level of SGX
//                                     platform is outdated and additional configuration
//                                     of SGX platform may be needed.
// 
//                                     "Revoked" - TCB level of SGX platform is revoked.
//                                     The platform is not trustworthy.
//                             advisoryIDs:
//                                 type: array
//                                 description: >-
//                                     Array of Advisory IDs referring to Intel security advisories that
//                                     provide insight into the reason(s) for the value of tcbStatus for
//                                     this TCB level when the value is not UpToDate.
// 
//                                     Note: The value can be different for different
//                                     FMSPCs.
// 
//                                     This field is optional. It will be present only
//                                     if the list of Advisory IDs is not empty.
//                                 items:
//                                     type: string
//         signature:
//             type: string
//             description: >-
//                 Base 16-encoded string representation of signature calculated over tcbInfo
//                 body without whitespaces using TCB Signing Key
//                 i.e:
//                 {"version":2,"issueDate":"2019-07-30T12:00:00Z","nextUpdate":"2019-08-30T12:00:00Z",...}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV3 {
    pub tcb_info: TcbInfoV3Inner,
    pub signature: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV3Inner {
    pub id: String,
    pub version: u32,
    pub issue_date: String,
    pub next_update: String,
    pub fmspc: String,
    pub pce_id: String,
    pub tcb_type: u8,
    pub tcb_evaluation_data_number: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx_module: Option<TdxModule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx_module_identities: Option<Vec<TdxModuleIdentities>>,
    pub tcb_levels: Vec<TcbInfoV3TcbLevelItem>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModule {
    pub mrsigner: String,                   // Base 16-encoded string representation of the measurement of a TDX SEAM module’s signer.
    pub attributes: String,                 // Hex-encoded byte array (8 bytes) representing attributes "golden" value.
    pub attributes_mask: String,            // Hex-encoded byte array (8 bytes) representing mask to be applied to TDX SEAM module’s
                                            // attributes value retrieved from the platform
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModuleIdentities {
    pub id: String,                         // Identifier of TDX Module
    pub mrsigner: String,                   // Base 16-encoded string representation of the measurement of a TDX SEAM module’s signer.
    pub attributes: String,                 // Base 16-encoded string representation of the byte array (8 bytes) representing attributes "golden" value.
    pub attributes_mask: String,            // Base 16-encoded string representation of the byte array (8 bytes) representing mask to be applied to TDX SEAM module’s
                                            // attributes value retrieved from the platform
    pub tcb_levels: Vec<TdxModuleIdentitiesTcbLevelItem>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModuleIdentitiesTcbLevelItem {
    pub tcb: TdxModuleIdentitiesTcbLevel,
    pub tcb_date: String,
    pub tcb_status: String,
    #[serde(rename(serialize = "advisoryIDs", deserialize = "advisoryIDs"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory_ids: Option<Vec<String>>,

}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModuleIdentitiesTcbLevel {
    pub isvsvn: u8,                        // TDX SEAM module’s ISV SVN
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV3TcbLevelItem {
    pub tcb: TcbInfoV3TcbLevel,
    pub tcb_date: String,
    pub tcb_status: String,
    #[serde(rename(serialize = "advisoryIDs", deserialize = "advisoryIDs"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory_ids: Option<Vec<String>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV3TcbLevel {
    pub sgxtcbcomponents: Vec<TcbComponent>,
    pub pcesvn: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdxtcbcomponents: Option<Vec<TcbComponent>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbComponent {
    pub svn: u8,                                                   // SVN of TCB Component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,                                   // Category of TCB Component (e.g. BIOS, OS/VMM).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename(serialize = "type", deserialize = "type"))]
    pub type_: Option<String>,                                      // Type of TCB Component (e.g. SGX Late Microcode Update, TXT SINIT).
}