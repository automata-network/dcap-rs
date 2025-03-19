pub mod trust_store;
pub mod types;
pub mod utils;

use std::time::SystemTime;

use anyhow::{Context, anyhow, bail};
use chrono::{DateTime, Utc};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use trust_store::{TrustStore, TrustedIdentity};
use types::{
    VerifiedOutput,
    collateral::Collateral,
    enclave_identity::QeTcbStatus,
    quote::{AttestationKeyType, Quote, TDX_TEE_TYPE},
    sgx_x509::SgxPckExtension,
    tcb_info::{TcbInfo, TcbStatus},
};
use utils::Expireable;
use x509_cert::der::{Any, DecodePem};
use x509_verify::VerifyingKey as X509VerifyingKey;
use zerocopy::AsBytes;

pub const INTEL_ROOT_CA_PEM: &str = "\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi71OiO
SLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlA==
-----END PUBLIC KEY-----";

pub fn verify_dcap_quote(
    current_time: SystemTime,
    collateral: Collateral,
    quote: Quote,
) -> anyhow::Result<VerifiedOutput> {
    // 1. Verify the integrity of the signature chain from the Quote to the Intel-issued PCK
    //    certificate, and that no keys in the chain have been revoked.
    let tcb_info = verify_integrity(current_time, &collateral, &quote)?;

    // 2. Verify the Quoting Enclave source and all signatures in the Quote.
    let qe_tcb_status = verify_quote(current_time, &collateral, &quote)?;
    // 3. Verify the status of Intel SGX TCB described in the chain.
    let pck_cert_chain = quote.signature.get_pck_cert_chain()?;
    let pck_extension = &pck_cert_chain.pck_extension;
    let (mut tcb_status, advisory_ids) =
        verify_tcb_status(&tcb_info, &pck_cert_chain.pck_extension)?;

    let advisory_ids = if advisory_ids.is_empty() {
        None
    } else {
        Some(advisory_ids)
    };

    // 4. If TDX type then verify the status of TDX Module status and converge and send
    if quote.header.tee_type == TDX_TEE_TYPE {
        let tdx_module_status =
            tcb_info.verify_tdx_module(quote.body.as_tdx_report_body().unwrap())?;
        tcb_status = TcbInfo::converge_tcb_status_with_tdx_module(tcb_status, tdx_module_status);
    }

    // 5. Converge platform TCB status with QE TCB status
    tcb_status = TcbInfo::converge_tcb_status_with_qe_tcb(tcb_status, qe_tcb_status.into());

    Ok(VerifiedOutput {
        quote_version: quote.header.version.get(),
        tee_type: quote.header.tee_type,
        tcb_status,
        fmspc: pck_extension.fmspc,
        quote_body: quote.body,
        advisory_ids,
    })
}

fn verify_integrity(
    current_time: SystemTime,
    collateral: &Collateral,
    quote: &Quote,
) -> anyhow::Result<types::tcb_info::TcbInfo> {
    if !collateral
        .tcb_info_and_qe_identity_issuer_chain
        .valid_at(current_time)
    {
        bail!("expired tcb info issuer chain");
    }
    let pck_cert_chain_data = quote.signature.get_pck_cert_chain()?;

    if !pck_cert_chain_data.pck_cert_chain.valid_at(current_time) {
        bail!("expired pck cert chain");
    }

    let root_ca = collateral
        .tcb_info_and_qe_identity_issuer_chain
        .last()
        .context("tcb issuer chain is empty")?;

    // Verify the root certificate is self issued
    if root_ca.tbs_certificate.issuer != root_ca.tbs_certificate.subject {
        bail!("root certificate is not self issued");
    }

    let spki = x509_cert::spki::SubjectPublicKeyInfo::<Any, _>::from_pem(INTEL_ROOT_CA_PEM)?;
    let intel_root_ca = X509VerifyingKey::try_from(spki).unwrap();
    intel_root_ca
        .verify(root_ca)
        .context("Root CA signature verification failed")?;

    // Build initial trust store with the root certificate
    let mut trust_store = TrustStore::new(current_time, vec![root_ca.clone()])?;

    // Verify that the CRL is signed by Intel and add it to the store.
    trust_store
        .add_crl(collateral.root_ca_crl.clone(), true, None)
        .context("failed to verify root ca crl")?;

    // Build intermediaries from the PCK cert chain, EXCLUDING the leaf certificate
    let mut intermediaries = std::collections::BTreeMap::new();
    // Skip the first certificate (leaf) and only use intermediates and root
    for cert in pck_cert_chain_data.pck_cert_chain.iter().skip(1) {
        let subject = cert.tbs_certificate.subject.to_string();
        let pk = cert
            .try_into()
            .map_err(|e| anyhow::anyhow!("failed to decode key from certificate: {}", e))?;

        intermediaries.insert(
            subject,
            TrustedIdentity {
                cert: cert.clone(), //TODO: remove clone eventually, or else may hit solana limits
                pk,
            },
        );
    }

    trust_store
        .add_crl(collateral.pck_crl.clone(), true, Some(&intermediaries))
        .context("failed to verify pck crl")?;

    // Verify PCK Cert Chain and add it to the store.
    let pck_cert_chain_data = quote.signature.get_pck_cert_chain()?;
    trust_store
        .verify_chain_leaf(&pck_cert_chain_data.pck_cert_chain)
        .context("failed to verify pck crl issuer chain")?;

    // Verify TCB Info Issuer Chain
    let tcb_issuer = trust_store
        .verify_chain_leaf(&collateral.tcb_info_and_qe_identity_issuer_chain)
        .context("failed to verify tcb info issuer chain")?;

    // Get TCB Signer Public Key
    let tcb_signer = tcb_issuer
        .cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("missing tcb signer public key")?;

    // We are making big assumption here that the key is ECDSA P-256
    let tcb_signer = p256::ecdsa::VerifyingKey::from_sec1_bytes(tcb_signer)
        .context("invalid tcb signer public key")?;

    // Verify the TCB Info
    let tcb_info = collateral
        .tcb_info
        .as_tcb_info_and_verify(current_time, tcb_signer)
        .context("failed to verify tcb info signature")?;

    // Verify the quote identity issuer chain
    let _qe_id_issuer = trust_store
        .verify_chain_leaf(&collateral.tcb_info_and_qe_identity_issuer_chain)
        .context("failed to verify pck crl issuer certificate chain")?;

    Ok(tcb_info)
}

fn verify_quote(
    current_time: SystemTime,
    collateral: &Collateral,
    quote: &Quote,
) -> anyhow::Result<QeTcbStatus> {
    let qe_tcb_status = verify_quote_enclave_source(current_time, collateral, quote)?;
    verify_quote_signatures(quote)?;
    Ok(qe_tcb_status)
}

/// Verify the quote enclave source and return the TCB status
/// of the quoting enclave.
pub fn verify_quote_enclave_source(
    current_time: SystemTime,
    collateral: &Collateral,
    quote: &Quote,
) -> anyhow::Result<QeTcbStatus> {
    // Verify that the enclave identity root is signed by root certificate
    let qe_identity = collateral
        .qe_identity
        .validate_as_enclave_identity(
            &VerifyingKey::from_sec1_bytes(
                collateral.tcb_info_and_qe_identity_issuer_chain[0]
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .as_bytes()
                    .context("missing qe identity public key")?,
            )
            .context("failed to verify quote enclave identity")?,
        )
        .context("failed to verify quote enclave identity")?;

    // Validate that current time is between issue_date and next_update
    let current_time: DateTime<Utc> = current_time.into();
    if current_time < qe_identity.issue_date || current_time > qe_identity.next_update {
        bail!("tcb info is not valid at current time");
    }

    // Compare the mr_signer values
    if qe_identity.mrsigner != quote.signature.qe_report_body.mr_signer {
        bail!(
            "invalid qe mrsigner, expected {} but got {}",
            hex::encode(qe_identity.mrsigner),
            hex::encode(quote.signature.qe_report_body.mr_signer)
        );
    }

    // Compare the isv_prod_id values
    if qe_identity.isvprodid != quote.signature.qe_report_body.isv_prod_id.get() {
        bail!(
            "invalid qe isv_prod_id, expected {} but got {}",
            qe_identity.isvprodid,
            quote.signature.qe_report_body.isv_prod_id.get()
        );
    }

    // Compare the attribute values
    let qe_report_attributes = quote.signature.qe_report_body.sgx_attributes;
    let calculated_mask = qe_identity
        .attributes_mask
        .iter()
        .zip(qe_report_attributes.iter())
        .map(|(&mask, &attribute)| mask & attribute);

    if calculated_mask
        .zip(qe_identity.attributes)
        .any(|(masked, identity)| masked != identity)
    {
        bail!("qe attrtibutes mismatch");
    }

    // Compare misc_select values
    let misc_select = quote.signature.qe_report_body.misc_select;
    let calculated_mask = qe_identity
        .miscselect_mask
        .as_bytes()
        .iter()
        .zip(misc_select.as_bytes().iter())
        .map(|(&mask, &attribute)| mask & attribute);

    if calculated_mask
        .zip(qe_identity.miscselect.as_bytes().iter())
        .any(|(masked, &identity)| masked != identity)
    {
        bail!("qe misc_select mismatch");
    }

    let qe_tcb_status = qe_identity.get_qe_tcb_status(quote.signature.qe_report_body.isv_svn.get());

    Ok(qe_tcb_status)
}

/// Verify the quote signatures.
pub fn verify_quote_signatures(quote: &Quote) -> anyhow::Result<()> {
    let pck_cert_chain_data = quote.signature.get_pck_cert_chain()?;
    let pck_pk_bytes = pck_cert_chain_data.pck_cert_chain[0]
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("missing pck public key")?;

    let pck_pkey = VerifyingKey::from_sec1_bytes(pck_pk_bytes)
        .map_err(|e| anyhow!("failed to parse pck public key: {}", e))?;

    let qe_report_signature = Signature::from_slice(quote.signature.qe_report_signature)?;
    pck_pkey
        .verify(
            quote.signature.qe_report_body.as_bytes(),
            &qe_report_signature,
        )
        .map_err(|e| anyhow!("failed to verify qe report signature. {e}"))?;

    quote.signature.verify_qe_report()?;

    let mut key = [0u8; 65];
    key[0] = 4;
    key[1..].copy_from_slice(quote.signature.attestation_pub_key);

    if quote.header.attestation_key_type.get() != AttestationKeyType::Ecdsa256P256 as u16 {
        bail!("unsupported attestation key type");
    }

    let attest_key = VerifyingKey::from_sec1_bytes(&key)
        .map_err(|e| anyhow!("failed to parse attest key: {e}"))?;

    let header_bytes = quote.header.as_bytes();
    let body_bytes = quote.body.as_bytes();
    let mut data = Vec::with_capacity(header_bytes.len() + body_bytes.len());
    data.extend_from_slice(header_bytes);
    data.extend_from_slice(body_bytes);

    let sig = Signature::from_slice(quote.signature.isv_signature)?;
    attest_key
        .verify(&data, &sig)
        .context("failed to verify quote signature")?;

    Ok(())
}

/// Ensure the latest tcb info is not revoked, and is either up to date or only needs a configuration
/// change.
fn verify_tcb_status(
    tcb_info: &TcbInfo,
    pck_extension: &SgxPckExtension,
) -> anyhow::Result<(TcbStatus, Vec<String>)> {
    // Make sure the tcb_info matches the enclave's model/PCE version
    if pck_extension.fmspc != tcb_info.fmspc {
        return Err(anyhow::anyhow!(
            "tcb fmspc mismatch (pck extension: {:?}, tcb_info: {:?})",
            pck_extension.fmspc,
            tcb_info.fmspc
        ));
    }

    if pck_extension.pceid != tcb_info.pce_id {
        return Err(anyhow::anyhow!(
            "tcb pceid mismatch (pck extension: {:?}, tcb_info: {:?})",
            pck_extension.pceid,
            tcb_info.pce_id
        ));
    }

    TcbStatus::lookup(pck_extension, tcb_info)
}

#[cfg(test)]
mod tests {

    use std::time::Duration;

    use x509_cert::{crl::CertificateList, der::Decode};

    use crate::{
        types::{
            enclave_identity::QuotingEnclaveIdentityAndSignature, tcb_info::TcbInfoAndSignature,
        },
        utils::cert_chain_processor,
    };

    use super::*;

    fn sgx_quote_data() -> (Collateral, Quote<'static>) {
        let collateral = include_str!("../data/full_collateral_sgx.json");
        let collateral: Collateral = serde_json::from_str(collateral).unwrap();
        let quote = include_bytes!("../data/quote_sgx.bin");
        let quote = Quote::read(&mut quote.as_slice()).unwrap();
        (collateral, quote)
    }

    fn tdx_quote_data() -> (Collateral, Quote<'static>) {
        let quote = include_bytes!("../data/quote_tdx.bin");
        let quote = Quote::read(&mut quote.as_slice()).unwrap();

        let tcb_info_and_qe_identity_issuer_chain = include_bytes!("../data/signing_cert.pem");
        let tcb_info_and_qe_identity_issuer_chain =
            cert_chain_processor::load_pem_chain_bpf_friendly(
                tcb_info_and_qe_identity_issuer_chain,
            )
            .unwrap();

        let root_ca_crl = include_bytes!("../data/intel_root_ca_crl.der");
        let root_ca_crl = CertificateList::from_der(root_ca_crl).unwrap();

        let tcb_info = include_bytes!("../data/tcb_info_v3_with_tdx_module.json");
        let tcb_info: TcbInfoAndSignature = serde_json::from_slice(tcb_info).unwrap();

        let qe_identity = include_bytes!("../data/qeidentityv2_apiv4.json");
        let qe_identity: QuotingEnclaveIdentityAndSignature =
            serde_json::from_slice(qe_identity).unwrap();

        let platform_ca_crl = include_bytes!("../data/pck_platform_crl.der");
        let platform_ca_crl = CertificateList::from_der(platform_ca_crl).unwrap();

        let collateral = Collateral {
            tcb_info_and_qe_identity_issuer_chain,
            root_ca_crl,
            pck_crl: platform_ca_crl,
            tcb_info,
            qe_identity,
        };
        (collateral, quote)
    }

    fn test_sgx_time() -> SystemTime {
        // Aug 29th 4:20pm, ~24 hours after quote was generated
        SystemTime::UNIX_EPOCH + Duration::from_secs(1724962800)
    }

    fn test_tdx_time() -> SystemTime {
        // Pinned September 10th, 2024, 6:49am GMT
        SystemTime::UNIX_EPOCH + Duration::from_secs(1725950994)
    }

    #[test]
    fn parse_tdx_quote() {
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
    fn verify_integrity() {
        let (collateral, quote) = sgx_quote_data();
        super::verify_integrity(test_sgx_time(), &collateral, &quote)
            .expect("certificate chain integrity should succeed");
    }

    #[test]
    fn e2e_sgx_quote() {
        let (collateral, quote) = sgx_quote_data();
        super::verify_dcap_quote(test_sgx_time(), collateral, quote)
            .expect("certificate chain integrity should succeed");
    }

    #[test]
    fn e2e_tdx_quote() {
        let (collateral, quote) = tdx_quote_data();
        super::verify_dcap_quote(test_tdx_time(), collateral, quote)
            .expect("certificate chain integrity should succeed");
    }
}
