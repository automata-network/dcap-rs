use serde::{Serialize, Deserialize};
use serde_big_array::BigArray;

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum QuoteBody {
    SGXQuoteBody(EnclaveReport),
    TD10QuoteBody(TD10ReportBody)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnclaveReport {
    pub cpu_svn: [u8; 16],      // [16 bytes]
                                // Security Version of the CPU (raw value)
    pub misc_select: [u8; 4],   // [4 bytes]
                                // SSA Frame extended feature set. 
                                // Reports what SECS.MISCSELECT settings are used in the enclave. You can limit the
                                // allowed MISCSELECT settings in the sigstruct using MISCSELECT/MISCMASK.
    pub reserved_1: [u8; 28],   // [28 bytes]
                                // Reserved for future use - 0
    pub attributes: [u8; 16],   // [16 bytes]
                                // Set of flags describing attributes of the enclave.
                                // Reports what SECS.ATTRIBUTES settings are used in the enclave. The ISV can limit what
                                // SECS.ATTRIBUTES can be used when loading the enclave through parameters to the SGX Signtool.
                                // The Signtool will produce a SIGSTRUCT with ATTRIBUTES and ATTRIBUTESMASK 
                                // which determine allowed ATTRIBUTES.
                                // - For each SIGSTRUCT.ATTRIBUTESMASK bit that is set, then corresponding bit in the
                                // SECS.ATTRIBUTES must match the same bit in SIGSTRUCT.ATTRIBUTES.
    pub mrenclave: [u8; 32],    // [32 bytes] 
                                // Measurement of the enclave. 
                                // The MRENCLAVE value is the SHA256 hash of the ENCLAVEHASH field in the SIGSTRUCT.
    pub reserved_2: [u8; 32],   // [32 bytes] 
                                // Reserved for future use - 0
    pub mrsigner: [u8; 32],     // [32 bytes]
                                // Measurement of the enclave signer. 
                                // The MRSIGNER value is the SHA256 hash of the MODULUS field in the SIGSTRUCT.
    #[serde(with = "BigArray")]
    pub reserved_3: [u8; 96],   // [96 bytes]
                                // Reserved for future use - 0
    pub isv_prod_id: u16,       // [2 bytes]
                                // Product ID of the enclave. 
                                // The ISV should configure a unique ISVProdID for each product which may
                                // want to share sealed data between enclaves signed with a specific MRSIGNER. The ISV
                                // may want to supply different data to identical enclaves signed for different products.
    pub isv_svn: u16,           // [2 bytes]
                                // Security Version of the enclave
    #[serde(with = "BigArray")]
    pub reserved_4: [u8; 60],   // [60 bytes]
                                // Reserved for future use - 0
    #[serde(with = "BigArray")]
    pub report_data: [u8; 64],  // [64 bytes]
                                // Additional report data.
                                // The enclave is free to provide 64 bytes of custom data to the REPORT.
                                // This can be used to provide specific data from the enclave or it can be used to hold 
                                // a hash of a larger block of data which is provided with the quote. 
                                // The verification of the quote signature confirms the integrity of the
                                // report data (and the rest of the REPORT body).
}

impl EnclaveReport {
    pub fn from_bytes(raw_bytes: &[u8]) -> EnclaveReport{
        assert_eq!(raw_bytes.len(), 384);
        let mut obj = EnclaveReport {
            cpu_svn: [0; 16],
            misc_select: [0; 4],
            reserved_1: [0; 28],
            attributes: [0; 16],
            mrenclave: [0; 32],
            reserved_2: [0; 32],
            mrsigner: [0; 32],
            reserved_3: [0; 96],
            isv_prod_id: 0,
            isv_svn: 0,
            reserved_4: [0; 60],
            report_data: [0; 64],
        };

        // parse raw bytes into obj
        obj.cpu_svn.copy_from_slice(&raw_bytes[0..16]);
        obj.misc_select.copy_from_slice(&raw_bytes[16..20]);
        obj.reserved_1.copy_from_slice(&raw_bytes[20..48]);
        obj.attributes.copy_from_slice(&raw_bytes[48..64]);
        obj.mrenclave.copy_from_slice(&raw_bytes[64..96]);
        obj.reserved_2.copy_from_slice(&raw_bytes[96..128]);
        obj.mrsigner.copy_from_slice(&raw_bytes[128..160]);
        obj.reserved_3.copy_from_slice(&raw_bytes[160..256]);
        obj.isv_prod_id = u16::from_le_bytes([raw_bytes[256], raw_bytes[257]]);
        obj.isv_svn = u16::from_le_bytes([raw_bytes[258], raw_bytes[259]]);
        obj.reserved_4.copy_from_slice(&raw_bytes[260..320]);
        obj.report_data.copy_from_slice(&raw_bytes[320..384]);

        return obj;
    }

    pub fn to_bytes(&self) -> [u8; 384] {
        // convert the struct into raw bytes
        let mut raw_bytes = [0; 384];
        // copy the fields into the raw bytes
        raw_bytes[0..16].copy_from_slice(&self.cpu_svn);
        raw_bytes[16..20].copy_from_slice(&self.misc_select);
        raw_bytes[20..48].copy_from_slice(&self.reserved_1);
        raw_bytes[48..64].copy_from_slice(&self.attributes);
        raw_bytes[64..96].copy_from_slice(&self.mrenclave);
        raw_bytes[96..128].copy_from_slice(&self.reserved_2);
        raw_bytes[128..160].copy_from_slice(&self.mrsigner);
        raw_bytes[160..256].copy_from_slice(&self.reserved_3);
        raw_bytes[256..258].copy_from_slice(&self.isv_prod_id.to_le_bytes());
        raw_bytes[258..260].copy_from_slice(&self.isv_svn.to_le_bytes());
        raw_bytes[260..320].copy_from_slice(&self.reserved_4);
        raw_bytes[320..384].copy_from_slice(&self.report_data);

        raw_bytes
    }
}

// TD Attributes:
// [bits]   : [description]
// [0:7]    : (TUD) TD Under Debug flags. 
//            If any of the bits in this group are set to 1, the TD is untrusted.
//            [0]     - (DEBUG) Defines whether the TD runs in TD debug mode (set to 1) or not (set to 0). 
//                      In TD debug mode, the CPU state and private memory are accessible by the host VMM.
//            [1:7]   - (RESERVED) Reserved for future TUD flags, must be 0.
// [8:31]   : (SEC) Attributes that may impact the security of the TD
//            [8:27]  - (RESERVED) Reserved for future SEC flags, must be 0.
//            [28]    - (SEPT_VE_DISABLE) Disable EPT violation conversion to #VE on TD access of PENDING pages
//            [29]    - (RESERVED) Reserved for future SEC flags, must be 0.
//            [30]    - (PKS) TD is allowed to use Supervisor Protection Keys.
//            [31]    - (KL) TD is allowed to use Key Locker.
// [32:63]  : (OTHER) Attributes that do not impact the security of the TD
//            [32:62] - (RESERVED) Reserved for future OTHER flags, must be 0.
//            [63]    - (PERFMON) TD is allowed to use Perfmon and PERF_METRICS capabilities.

// TEE_TCB_SVN:
// [bytes]  : [Name]            : [description]
// [0]      : Tdxtcbcomp01      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[0]
// [1]      : Tdxtcbcomp02      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[1]
// [2]      : Tdxtcbcomp03      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[2
// [3]      : Tdxtcbcomp04      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[3]
// [4]      : Tdxtcbcomp05      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[4]
// [5]      : Tdxtcbcomp06      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[5]
// [6]      : Tdxtcbcomp07      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[6]
// [7]      : Tdxtcbcomp08      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[7]
// [8]      : Tdxtcbcomp09      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[8]
// [9]      : Tdxtcbcomp10      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[9]
// [10]     : Tdxtcbcomp11      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[10]
// [11]     : Tdxtcbcomp12      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[11]
// [12]     : Tdxtcbcomp13      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[12]
// [13]     : Tdxtcbcomp14      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[13]
// [14]     : Tdxtcbcomp15      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[14]
// [15]     : Tdxtcbcomp16      : QVL compares with TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn[15]

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct TD10ReportBody {
    pub tee_tcb_svn: [u8; 16],          // [16 bytes]
                                        // Describes the TCB of TDX. (Refer to above)
    #[serde(with = "BigArray")]
    pub mrseam: [u8; 48],               // [48 bytes]
                                        // Measurement of the TDX Module.
    #[serde(with = "BigArray")]
    pub mrsignerseam: [u8; 48],         // [48 bytes]
                                        // Zero for Intel TDX Module
    pub seam_attributes: u64,           // [8 bytes]
                                        // Must be zero for TDX 1.0
    pub td_attributes: u64,             // [8 bytes]
                                        // TD Attributes (Refer to above)
    pub xfam: u64,                      // [8 bytes]
                                        // XFAM (eXtended Features Available Mask) is defined as a 64b bitmap, which has the same format as XCR0 or IA32_XSS MSR.
    #[serde(with = "BigArray")]
    pub mrtd: [u8; 48],                 // [48 bytes]
                                        // (SHA384) Measurement of the initial contents of the TD.
    #[serde(with = "BigArray")]
    pub mrconfigid: [u8; 48],           // [48 bytes]
                                        // Software-defined ID for non-owner-defined configuration of the TD, e.g., runtime or OS configuration.
    #[serde(with = "BigArray")]
    pub mrowner: [u8; 48],              // [48 bytes]
                                        // Software-defined ID for the TD’s owner
    #[serde(with = "BigArray")]
    pub mrownerconfig: [u8; 48],        // [48 bytes]
                                        // Software-defined ID for owner-defined configuration of the TD, 
                                        // e.g., specific to the workload rather than the runtime or OS.
    #[serde(with = "BigArray")]
    pub rtmr0: [u8; 48],                // [48 bytes]
                                        // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    #[serde(with = "BigArray")]
    pub rtmr1: [u8; 48],                // [48 bytes]
                                        // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    #[serde(with = "BigArray")]
    pub rtmr2: [u8; 48],                // [48 bytes]
                                        // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    #[serde(with = "BigArray")]
    pub rtmr3: [u8; 48],                // [48 bytes]
                                        // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    #[serde(with = "BigArray")]
    pub report_data: [u8; 64],          // [64 bytes]
                                        // Additional report data.
                                        // The TD is free to provide 64 bytes of custom data to the REPORT.
                                        // This can be used to provide specific data from the TD or it can be used to hold a hash of a larger block of data which is provided with the quote.
                                        // Note that the signature of a TD Quote covers the REPORTDATA field. As a result, the integrity is protected with a key rooted in an Intel CA.
}

impl TD10ReportBody {
    pub fn from_bytes(raw_bytes: &[u8]) -> Self {
        // copy the bytes into the struct
        let mut tee_tcb_svn = [0; 16];
        tee_tcb_svn.copy_from_slice(&raw_bytes[0..16]);
        let mut mrseam = [0; 48];
        mrseam.copy_from_slice(&raw_bytes[16..64]);
        let mut mrsignerseam = [0; 48];
        mrsignerseam.copy_from_slice(&raw_bytes[64..112]);
        let seam_attributes = u64::from_le_bytes([raw_bytes[112], raw_bytes[113], raw_bytes[114], raw_bytes[115], raw_bytes[116], raw_bytes[117], raw_bytes[118], raw_bytes[119]]);
        let td_attributes = u64::from_le_bytes([raw_bytes[120], raw_bytes[121], raw_bytes[122], raw_bytes[123], raw_bytes[124], raw_bytes[125], raw_bytes[126], raw_bytes[127]]);
        let xfam = u64::from_le_bytes([raw_bytes[128], raw_bytes[129], raw_bytes[130], raw_bytes[131], raw_bytes[132], raw_bytes[133], raw_bytes[134], raw_bytes[135]]);
        let mut mrtd = [0; 48];
        mrtd.copy_from_slice(&raw_bytes[136..184]);
        let mut mrconfigid = [0; 48];
        mrconfigid.copy_from_slice(&raw_bytes[184..232]);
        let mut mrowner = [0; 48];
        mrowner.copy_from_slice(&raw_bytes[232..280]);
        let mut mrownerconfig = [0; 48];
        mrownerconfig.copy_from_slice(&raw_bytes[280..328]);
        let mut rtmr0 = [0; 48];
        rtmr0.copy_from_slice(&raw_bytes[328..376]);
        let mut rtmr1 = [0; 48];
        rtmr1.copy_from_slice(&raw_bytes[376..424]);
        let mut rtmr2 = [0; 48];
        rtmr2.copy_from_slice(&raw_bytes[424..472]);
        let mut rtmr3 = [0; 48];
        rtmr3.copy_from_slice(&raw_bytes[472..520]);
        let mut report_data = [0; 64];
        report_data.copy_from_slice(&raw_bytes[520..584]);

        TD10ReportBody {
            tee_tcb_svn,
            mrseam,
            mrsignerseam,
            seam_attributes,
            td_attributes,
            xfam,
            mrtd,
            mrconfigid,
            mrowner,
            mrownerconfig,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
            report_data,
        }
    }

    pub fn to_bytes(&self) -> [u8; 584] {
        let mut raw_bytes = [0; 584];
        raw_bytes[0..16].copy_from_slice(&self.tee_tcb_svn);
        raw_bytes[16..64].copy_from_slice(&self.mrseam);
        raw_bytes[64..112].copy_from_slice(&self.mrsignerseam);
        raw_bytes[112..120].copy_from_slice(&self.seam_attributes.to_le_bytes());
        raw_bytes[120..128].copy_from_slice(&self.td_attributes.to_le_bytes());
        raw_bytes[128..136].copy_from_slice(&self.xfam.to_le_bytes());
        raw_bytes[136..184].copy_from_slice(&self.mrtd);
        raw_bytes[184..232].copy_from_slice(&self.mrconfigid);
        raw_bytes[232..280].copy_from_slice(&self.mrowner);
        raw_bytes[280..328].copy_from_slice(&self.mrownerconfig);
        raw_bytes[328..376].copy_from_slice(&self.rtmr0);
        raw_bytes[376..424].copy_from_slice(&self.rtmr1);
        raw_bytes[424..472].copy_from_slice(&self.rtmr2);
        raw_bytes[472..520].copy_from_slice(&self.rtmr3);
        raw_bytes[520..584].copy_from_slice(&self.report_data);

        raw_bytes
    }
}