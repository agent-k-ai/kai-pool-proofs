#![allow(dead_code)]
use kai_volume_core::{Address, Hash, VolumeJournalV1, VolumeTermsV1, VolumeVenueV1, U256};
use serde_json::Value;
pub fn vectors() -> Value {
    serde_json::from_str(include_str!("../../test-vectors/abi-vectors.json")).unwrap()
}
pub fn real() -> Value {
    serde_json::from_str(include_str!("../../test-vectors/nitro-117903561.json")).unwrap()
}
pub fn bytes(value: &Value) -> Vec<u8> {
    hex(value.as_str().unwrap())
}
pub fn hex(value: &str) -> Vec<u8> {
    let value = value.strip_prefix("0x").unwrap();
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}
pub fn hash(v: &Value) -> Hash {
    bytes(v).try_into().unwrap()
}
pub fn address(v: &Value) -> Address {
    bytes(v).try_into().unwrap()
}
pub fn uint(v: &Value) -> U256 {
    U256::from_be_bytes(hash(v))
}
pub fn number(v: &Value) -> u64 {
    v.as_u64()
        .unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
}
pub fn venue(v: &Value) -> VolumeVenueV1 {
    VolumeVenueV1 {
        kind: number(&v["kind"]).try_into().unwrap(),
        account: address(&v["account"]),
        account_code_hash: hash(&v["accountCodeHash"]),
        currency0: address(&v["currency0"]),
        currency1: address(&v["currency1"]),
        fee: number(&v["fee"]).try_into().unwrap(),
        tick_spacing: v["tickSpacing"].as_i64().unwrap().try_into().unwrap(),
        hooks: address(&v["hooks"]),
        hook_code_hash: hash(&v["hookCodeHash"]),
        pool_id: hash(&v["poolId"]),
        quote_asset: address(&v["quoteAsset"]),
        min_notional: uint(&v["minNotional"]),
    }
}
pub fn terms(v: &Value) -> VolumeTermsV1 {
    VolumeTermsV1 {
        domain: hash(&v["domain"]),
        rules_hash: hash(&v["rulesHash"]),
        proof_method_id: hash(&v["proofMethodId"]),
        chain_id: number(&v["chainId"]),
        controller: address(&v["controller"]),
        adapter: address(&v["adapter"]),
        pool: address(&v["pool"]),
        race_id: uint(&v["raceId"]),
        header_format: number(&v["headerFormat"]).try_into().unwrap(),
        entrant_count: number(&v["entrantCount"]).try_into().unwrap(),
        entrants: std::array::from_fn(|i| address(&v["entrants"][i])),
        entrants_hash: hash(&v["entrantsHash"]),
        venues: std::array::from_fn(|i| venue(&v["venues"][i])),
        start_block: number(&v["startBlock"]),
        snapshot_block: number(&v["snapshotBlock"]),
        betting_cutoff: number(&v["bettingCutoff"]),
        confirmation_blocks: number(&v["confirmationBlocks"]),
        quiet_blocks: number(&v["quietBlocks"]),
        submission_deadline: number(&v["submissionDeadline"]),
        terminal_expiry: number(&v["terminalExpiry"]),
        history: address(&v["history"]),
        history_code_hash: hash(&v["historyCodeHash"]),
        history_window: number(&v["historyWindow"]),
        wrapped_native: address(&v["wrappedNative"]),
        wrapped_native_code_hash: hash(&v["wrappedNativeCodeHash"]),
        quote_asset: address(&v["quoteAsset"]),
        quote_decimals: number(&v["quoteDecimals"]).try_into().unwrap(),
        collateral: address(&v["collateral"]),
        collateral_decimals: number(&v["collateralDecimals"]).try_into().unwrap(),
        economic_policy_hash: hash(&v["economicPolicyHash"]),
        proof_suite_hash: hash(&v["proofSuiteHash"]),
        sp1_verifier: address(&v["sp1Verifier"]),
        sp1_verifier_code_hash: hash(&v["sp1VerifierCodeHash"]),
        circuit_identity: hash(&v["circuitIdentity"]),
    }
}
pub fn journal(v: &Value) -> VolumeJournalV1 {
    VolumeJournalV1 {
        domain: hash(&v["domain"]),
        terms_hash: hash(&v["termsHash"]),
        proof_suite_hash: hash(&v["proofSuiteHash"]),
        beneficiary: address(&v["beneficiary"]),
        coverage_mask: number(&v["coverageMask"]).try_into().unwrap(),
        from_exclusive: number(&v["fromExclusive"]),
        to_inclusive: number(&v["toInclusive"]),
        before_hash: hash(&v["beforeHash"]),
        end_hash: hash(&v["endHash"]),
        volume_quote: std::array::from_fn(|i| uint(&v["volumeQuote"][i])),
        qualifying_swap_count: std::array::from_fn(|i| uint(&v["qualifyingSwapCount"][i])),
    }
}
