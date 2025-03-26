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

use super::report::{EnclaveReportBody, Td10ReportBody};

#[allow(non_snake_case)]
const QUOTE_V3: u16 = 3;
#[allow(non_snake_case)]
const QUOTE_V4: u16 = 4;

pub const SGX_TEE_TYPE: u32 = 0x00000000;
pub const TDX_TEE_TYPE: u32 = 0x00000081;

/// A DCAP quote, used for verification.
#[derive(Debug)]
pub struct Quote<'a> {
    /// Header of the SGX Quote data structure.
    pub header: QuoteHeader,

    /// Software Vendor enclave report.
    pub body: QuoteBody,

    /// Signature of the quote body.
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
        if quote_header.tee_type == SGX_TEE_TYPE {
            let quote_body = utils::read_from_bytes::<EnclaveReportBody>(bytes)
                .ok_or_else(|| anyhow!("underflow reading enclave report body"))?;
            let quote_signature = QuoteSignatureData::read(bytes, quote_header.version.get())?;
            Ok(Quote {
                header: quote_header,
                body: QuoteBody::SgxQuoteBody(quote_body),
                signature: quote_signature,
            })
        } else if quote_header.tee_type == TDX_TEE_TYPE {
            let quote_body = utils::read_from_bytes::<Td10ReportBody>(bytes)
                .ok_or_else(|| anyhow!("underflow reading td10 report body"))?;
            let quote_signature = QuoteSignatureData::read(bytes, quote_header.version.get())?;

            return Ok(Quote {
                header: quote_header,
                body: QuoteBody::Td10QuoteBody(quote_body),
                signature: quote_signature,
            });
        } else {
            return Err(anyhow!("unsupported quote version"));
        }
    }
}
