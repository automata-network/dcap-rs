<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_Black%20Text%20with%20Color%20Logo.png">
    <img src="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png" width="50%">
  </picture>
</div>

# Automata DCAP Rust Library
[![Automata On Chain PCCS](https://img.shields.io/badge/Power%20By-Automata-orange.svg)](https://github.com/automata-network)

Intel Data Center Attestation Primitives Quote Verification Library (DCAP QVL) implemented in pure Rust. 

This library is currently integrated into a RiscZero Guest Program that provides users the option to attest DCAP quotes directly on-chain, by publishing and verifying ZK SNARK proofs in the [AutomataDCAPAttestation](https://github.com/automata-network/automata-dcap-attestation) contract.

To try out the demo of the DCAP RiscZero Program, we recommend checking out the [DCAP Bonsai CLI Demo](https://github.com/automata-network/dcap-bonsai-cli).

This library supports verification of the following quotes:
-   V3 SGX Quotes
-   V4 TDX and SGX Quotes

## Usage

To use dcap-rs, add the following to `Cargo.toml`:

```
[dependencies]
dcap-rs = { git = "https://github.com/automata-network/dcap-rs.git" }
```

### RiscZero Accelerated Crates

This library can be compiled with the acclerated `p256` crate, to optimize the cycle costs for ECDSA Verification in the RiscZero Guest program. Check out this [repo](https://github.com/automata-network/RustCrypto-elliptic-curves) and [doc](https://thias-organization.gitbook.io/p256-documentation) to learn more about the accelerated `p256` crate.

To fully optimize your Guest program, make sure to:
- turn off the default feature, and enable the `accelerated` feature
- include the following patch statements in `Cargo.toml`:

```
[dependencies]
dcap-rs = { git = "https://github.com/automata-network/dcap-rs.git" , default-features = false, features = ["accelerated"] }

[patch.crates-io]
sha2 = { git = "https://github.com/risc0/RustCrypto-hashes", tag = "sha2-v0.10.6-risczero.0" }
crypto-bigint = { git = "https://github.com/risc0/RustCrypto-crypto-bigint", tag = "v0.5.2-risczero.0" }
```

---

## Contributing

**Before You Contribute**:
* **Raise an Issue**: If you find a bug or wish to suggest a feature, please open an issue first to discuss it. Detail the bug or feature so we understand your intention.  
* **Pull Requests (PR)**: Before submitting a PR, ensure:  
    * Your contribution successfully builds.
    * It includes tests, if applicable.

## License

Apache License
