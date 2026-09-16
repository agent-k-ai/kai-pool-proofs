// SPDX-License-Identifier: Apache-2.0
//! Runtime prover selection for the volume hosts.
//!
//! `PROVER_BACKEND` selects the SP1 prover. The value must be explicit:
//! an unrecognised value is an error, never a silent CPU fallback, because a
//! silent fallback would prove on the CPU and miss a race deadline with no
//! diagnostic.
//!
//! This module needs the `cuda` feature of the `sp1-sdk` dependency. The host
//! manifest of this branch enables it.

use sp1_sdk::{env::EnvProver, ProverClient};

/// The accepted `PROVER_BACKEND` values.
pub const ACCEPTED: &str = "cpu, cuda";

/// The prover that the environment selects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Cpu,
    Cuda,
}

/// Parses a `PROVER_BACKEND` value. `None` means the variable is unset.
pub fn parse(value: Option<&str>) -> Result<Backend, String> {
    match value {
        None | Some("cpu") => Ok(Backend::Cpu),
        Some("cuda") => Ok(Backend::Cuda),
        Some(other) => Err(format!(
            "PROVER_BACKEND \"{other}\" is not accepted; accepted values: {ACCEPTED} (default cpu)"
        )),
    }
}

/// Validates `PROVER_BACKEND` and returns the selection. Call this before any
/// output directory or proving work so a bad value fails fast.
pub fn backend() -> Result<Backend, String> {
    let raw = std::env::var("PROVER_BACKEND").ok();
    parse(raw.as_deref())
}

/// Builds the prover that `PROVER_BACKEND` selects.
pub async fn build_prover() -> Result<EnvProver, String> {
    match backend()? {
        Backend::Cpu => Ok(EnvProver::Cpu(ProverClient::builder().cpu().build().await)),
        Backend::Cuda => Ok(EnvProver::Cuda(ProverClient::builder().cuda().build().await)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_selects_cpu() {
        assert_eq!(parse(None), Ok(Backend::Cpu));
    }

    #[test]
    fn cpu_selects_cpu() {
        assert_eq!(parse(Some("cpu")), Ok(Backend::Cpu));
    }

    #[test]
    fn cuda_selects_cuda() {
        assert_eq!(parse(Some("cuda")), Ok(Backend::Cuda));
    }

    #[test]
    fn unknown_value_is_rejected_and_names_the_value_and_the_set() {
        for bad in ["GPU", "", "CUDA", "cuda ", "gpu", "mock", "true"] {
            let err = parse(Some(bad)).expect_err("an unknown value must be rejected");
            assert!(
                err.contains(&format!("\"{bad}\"")),
                "the error must name the value: {err}"
            );
            assert!(
                err.contains(ACCEPTED),
                "the error must name the accepted set: {err}"
            );
        }
    }
}
