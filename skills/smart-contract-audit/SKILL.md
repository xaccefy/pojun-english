---
name: smart-contract-audit
description: Use when the target includes Solidity/smart contracts, Web3 DApps or on-chain asset systems — common contract vulnerabilities (reentrancy/oracle/permissions/signatures), audit tooling (slither/mythril), on-chain verification and impact determination.
tags:
  cwe: [CWE-682, CWE-367, CWE-284, CWE-347]
  attack: [T1195]
  class: [blockchain, solidity, smart-contract, web3]
---

# Smart Contract Audit Cheat Sheet

## High-frequency vulnerabilities

| Vulnerability | Characteristics | Verification |
|---|---|---|
| Reentrancy | Transfers before updating state; external call without a lock | Build an attacker contract, reproduce with a local mainnet fork |
| Missing access control | Missing `onlyOwner`, `initialize` can be called repeatedly | Call the restricted function directly and see whether it succeeds |
| Oracle manipulation | Spot price used for collateral pricing | Reason out / locally reproduce a flash-loan price-manipulation path |
| Signature replay | No nonce/chain ID/contract address | Use the same signature twice |
| Unauthorized transfer | `transferFrom` missing an allowance check | Reproduce locally |
| Integer issues | No SafeMath (old Solidity), precision loss | Boundary-value testing |
| Predictable randomness | `block.timestamp/blockhash` used for randomness | Reproduce locally |
| delegatecall | Proxy pattern storage-layout collision / arbitrary address | Compare storage slots |

## Toolchain

- `slither .` (fast static): reentrancy-eth, arbitrary-send, controlled-delegatecall;
- `mythril analyze` (symbolic execution, slow);
- `forge test` (local fork reproduction, most trustworthy);
- Decompiling on-chain contracts: etherscan source → `heimdall`/`panoramix` when there is none.

## On-chain verification (read-only)

- Read the contract: `cast call <addr> "balanceOf(address)(uint256)" <user>`;
- Events and transactions: `cast logs`/block explorer;
- Unauthenticated reads of on-chain data are not a vulnerability (the chain is public anyway); focus on **contract business logic that anyone can abuse**.

## DApp / Web3 frontend

- Private keys/mnemonics hard-coded (frontend bundle) — record a fact immediately;
- RPC endpoints unauthenticated / arbitrary `eth_sendRawTransaction`;
- Signature phishing (`eth_sign` on arbitrary messages), `permit` authorization abuse;
- The contract address the frontend calls does not match the audit target (proxy upgrade).

## Boundaries

- Verify only on testnets or a local fork; on mainnet only make read-only calls;
- Do not send any transaction that moves assets;
- Write the reproduction script and transaction hash into the evidence.
