mod body;
mod cert_data;
mod header;
mod signature;

use anyhow::anyhow;
pub use body::*;
pub use cert_data::*;
pub use header::*;
pub use signature::*;

use crate::utils;

use super::report::*;

pub const SGX_TEE_TYPE: u32 = 0x00000000;
pub const TDX_TEE_TYPE: u32 = 0x00000081;

/// A DCAP quote, used for verification.
#[derive(Debug)]
pub struct Quote<'a> {
    pub header: QuoteHeader,
    pub body_type: u16,
    pub body_size: u32,
    pub body: QuoteBody,
    pub signature: QuoteSignatureData<'a>,
}

impl<'a> Quote<'a> {
    pub fn read(bytes: &mut &'a [u8]) -> anyhow::Result<Self> {
        if bytes.len() < std::mem::size_of::<QuoteHeader>() {
            return Err(anyhow!("incorrect buffer size"));
        }

        // Read the quote header
        let quote_header = utils::read_from_bytes::<QuoteHeader>(bytes)
            .ok_or_else(|| anyhow!("underflow reading quote header"))?;

        // Read the quote body and signature
        let quote_body_type;
        let quote_body_size;
        let quote_body = if quote_header.version.get() <= 4 {
            if quote_header.tee_type == SGX_TEE_TYPE {
                quote_body_type = 1;
                quote_body_size = std::mem::size_of::<EnclaveReportBody>() as u32;
                let isv_report_body = utils::read_from_bytes::<EnclaveReportBody>(bytes)
                    .ok_or_else(|| anyhow!("underflow reading enclave report body"))?;
                QuoteBody::SgxQuoteBody(isv_report_body)
            } else if quote_header.tee_type == TDX_TEE_TYPE {
                quote_body_type = 2;
                quote_body_size = std::mem::size_of::<Td10ReportBody>() as u32;
                let td_report = utils::read_from_bytes::<Td10ReportBody>(bytes)
                    .ok_or_else(|| anyhow!("underflow reading td10 report body"))?;
                QuoteBody::Td10QuoteBody(td_report)
            } else {
                return Err(anyhow!("unsupported TEE type"));
            }
        } else {
            quote_body_type = u16::from_le_bytes([bytes[0], bytes[1]]);
            *bytes = &bytes[2..];

            quote_body_size = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            *bytes = &bytes[4..];

            if quote_body_type == 1 {
                if quote_header.tee_type != SGX_TEE_TYPE {
                    return Err(anyhow!("Quote body type 1 must be SGX TEE type"));
                }
                if quote_body_size as usize != std::mem::size_of::<EnclaveReportBody>() {
                    return Err(anyhow!("Quote body size mismatch for SGX TEE type"));
                }
                let isv_report_body = utils::read_from_bytes::<EnclaveReportBody>(bytes)
                    .ok_or_else(|| anyhow!("underflow reading enclave report body"))?;
                QuoteBody::SgxQuoteBody(isv_report_body)
            } else if quote_body_type == 2 {
                if quote_header.tee_type != TDX_TEE_TYPE {
                    return Err(anyhow!("Quote body type 2 must be TDX TEE type"));
                }
                if quote_body_size as usize != std::mem::size_of::<Td10ReportBody>() {
                    return Err(anyhow!("Quote body size mismatch for TDX TEE type"));
                }
                let td_report = utils::read_from_bytes::<Td10ReportBody>(bytes)
                    .ok_or_else(|| anyhow!("underflow reading td10 report body"))?;
                QuoteBody::Td10QuoteBody(td_report)
            } else if quote_body_type == 3 {
                if quote_header.tee_type != TDX_TEE_TYPE {
                    return Err(anyhow!("Quote body type 3 must be TDX TEE type"));
                }
                if quote_body_size as usize != std::mem::size_of::<Td15ReportBody>() {
                    return Err(anyhow!("Quote body size mismatch for TDX TEE type"));
                }
                let td_report = utils::read_from_bytes::<Td15ReportBody>(bytes)
                    .ok_or_else(|| anyhow!("underflow reading td15 report body"))?;
                QuoteBody::Td15QuoteBody(td_report)
            } else {
                return Err(anyhow!("unsupported quote body type"));
            }
        };

        // Read the quote signature
        let quote_signature = QuoteSignatureData::read(bytes, quote_header.version.get())?;

        Ok(Quote {
            header: quote_header,
            body_type: quote_body_type,
            body_size: quote_body_size,
            body: quote_body,
            signature: quote_signature,
        })
    }
}
