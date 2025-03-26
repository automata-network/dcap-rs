use std::io::Cursor;

use solana_client::rpc_client::RpcClient;
use solana_program::pubkey::Pubkey;
use borsh::BorshDeserialize;

use super::{CertificateAuthority, EnclaveIdentity, PcsCertificate};


pub struct PccsClient {
    pub rpc_client: RpcClient,
    pub program_id: Pubkey,
}

impl PccsClient {
    pub fn new(url: String, program_id: Pubkey) -> Self {
        Self {
            rpc_client: RpcClient::new(url),
            program_id,
        }
    }

    pub fn get_qe_enclave_identity(&self, enclave_id: &str, version: u8) -> anyhow::Result<EnclaveIdentity> {
        let enclave_identity_pda = Pubkey::find_program_address(
            &[b"enclave_identity", enclave_id.as_bytes(), &version.to_le_bytes()[..1]],
            &self.program_id
        ).0;
        let result = self.rpc_client.get_account(&enclave_identity_pda);
        match result {
            Ok(account) => {
                // Skip Anchor's 8-byte discriminator and create a cursor
                // We use cursor to avoid the trailing padding bytes
                let mut cursor = Cursor::new(&account.data[8..]);
                let enclave_identity = EnclaveIdentity::deserialize_reader(&mut cursor)?;
                Ok(enclave_identity)
            }
            Err(e) => {
                Err(anyhow::anyhow!("error getting enclave identity: {}", e))
            }
        }
    }

    pub fn get_pcs_certificate(&self, ca_type: CertificateAuthority) -> anyhow::Result<Vec<u8>> {
        let pcs_certificate_pda = Pubkey::find_program_address(
            &[b"pcs_cert", ca_type.common_name().as_bytes()],
            &self.program_id
        ).0;

        let result = self.rpc_client.get_account(&pcs_certificate_pda);
        match result {
            Ok(account) => {
                // Skip Anchor's 8-byte discriminator and create a cursor
                // We use cursor to avoid the trailing padding bytes
                let mut cursor = Cursor::new(&account.data[8..]);
                let pcs_certificate = PcsCertificate::deserialize_reader(&mut cursor)?;
                Ok(pcs_certificate.cert_data)
            }
            Err(e) => {
                Err(anyhow::anyhow!("error getting pcs certificate: {}", e))
            }
        }

    }
}
