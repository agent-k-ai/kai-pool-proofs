# Releases

## 0.1.0-node.20260912g

- Correct EIP-1559 preflight to permit clipping the priority fee by the max-fee
  cap. Require maxFeePerGas to cover the base fee; the priority cap is checked
  independently. Preserve the validated f host and original guest identities.

## 0.1.0-node.20260912f

- Import exact public support e3fc644 and reviewed range 9a12b81 histories.
- Add separate SP1 node context/store, bounded resumable capture/proof scheduling,
  real pinned CPU host integration and fresh final verification.
- Import final generated protocol-7 ABI/compiler artifacts and implement exact
  own-wallet EIP-1559, canonical acceptance, permissionless closure and earned
  payment reconciliation.
- Preserve original chunk/range guest identities. Correct prover VERSION d -> e
  to match its unchanged workspace; version changed host package separately as f.
- Document original proof scope, current capture/contract/bootstrap gates and
  source build with explicit local prerequisites. No publication/deployment or
  full-window/live acceptance is claimed by local validation.
