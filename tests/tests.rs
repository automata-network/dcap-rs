mod common;

use dcap_rs::{verify_dcap_quote, types::quote::Quote};
use common::*;

#[test]
fn parse_tdx_v5_quote() {
    let bytes = include_bytes!("../data/v5/alibaba_quote_5.dat");
    let quote = Quote::read(&mut bytes.as_slice()).unwrap();
    println!("{:?}", quote);
}

#[test]
fn parse_tdx_v4_quote() {
    let bytes = include_bytes!("../data/quote_tdx.bin");
    let quote = Quote::read(&mut bytes.as_slice()).unwrap();
    println!("{:?}", quote);
}

#[test]
fn parse_sgx_quote() {
    let bytes = include_bytes!("../data/quote_sgx.bin");
    let quote = Quote::read(&mut bytes.as_slice()).unwrap();
    println!("{:?}", quote);
}

#[test]
fn e2e_sgx_quote() {
    let (collateral, quote) = sgx_quote_data();
    verify_dcap_quote(test_sgx_time(), collateral, quote)
        .expect("certificate chain integrity should succeed");
}

#[test]
fn e2e_tdx_quote() {
    let (collateral, quote) = tdx_quote_data();
    verify_dcap_quote(test_tdx_time(), collateral, quote)
        .expect("certificate chain integrity should succeed");
}

#[test]
fn e2e_tdx_v5_quote() {
    let (collateral, quote) = tdx_quote_v5_data();
    let output = verify_dcap_quote(test_tdx_v5_time(), collateral, quote)
        .expect("certificate chain integrity should succeed");
    println!("{:?}", output);
}
