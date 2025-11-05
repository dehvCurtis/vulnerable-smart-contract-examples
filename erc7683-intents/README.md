# ERC-7683 Cross-Chain Intent Vulnerable Contracts

This directory contains **intentionally vulnerable** ERC-7683 cross-chain intent contracts for testing SolidityDefend detectors.

## ⚠️ WARNING
**DO NOT DEPLOY THESE CONTRACTS TO MAINNET OR USE IN PRODUCTION**

These contracts contain critical vulnerabilities for educational and testing purposes.

---

## Test Contracts

### 1. VulnerableNonceManagement.sol
**Detector:** `intent-nonce-management`

**Vulnerabilities:**
- ❌ No nonce tracking or validation
- ❌ Missing `usedNonces` mapping
- ❌ Allows replay attacks (same intent can be filled multiple times)
- ❌ Intent hash doesn't include nonce

**Expected Detections:**
- Missing nonce storage
- Missing nonce validation in fill functions
- Replay attack vulnerability

---

### 2. VulnerableSignatureReplay.sol
**Detector:** `intent-signature-replay`

**Vulnerabilities:**
- ❌ No chainId validation in signature
- ❌ Missing EIP-712 domain separator with chainId
- ❌ Allows cross-chain signature replay
- ❌ Intent hash doesn't include chainId

**Expected Detections:**
- Missing chainId in intent structure
- Missing chainId validation
- Cross-chain replay vulnerability
- Missing EIP-712 domain separator

**Exploit:** Sign intent on Ethereum, replay on Polygon with same signature

---

### 3. VulnerableSettlementValidation.sol
**Detector:** `intent-settlement-validation`

**Vulnerabilities:**
- ❌ No deadline validation in settle()
- ❌ No minimum output amount validation
- ❌ No validation of fill instructions
- ❌ Missing slippage protection
- ❌ Batch settlement without length checks
- ❌ No per-intent validation in batch

**Expected Detections:**
- Missing deadline validation
- Missing output amount validation
- Missing fill instruction validation
- Unsafe batch processing

**Exploits:**
- Settle expired intents
- Provide less output than promised (slippage)
- Send to wrong destination address
- DOS entire batch with one failing intent

---

### 4. VulnerableSolverManipulation.sol
**Detector:** `intent-solver-manipulation`

**Vulnerabilities:**
- ❌ No solver whitelist or authentication
- ❌ No solver staking/bonding requirements
- ❌ Allows solver front-running
- ❌ No minimum bid validation
- ❌ Priority fee creates MEV opportunities
- ❌ No slashing for misbehavior
- ❌ Partial fills can grief users
- ❌ No fair ordering mechanism

**Expected Detections:**
- Missing solver authentication
- Missing solver staking
- Front-running vulnerabilities
- MEV extraction opportunities
- Griefing via partial fills

**Exploits:**
- Malicious solver fills intents
- Front-run legitimate solvers
- Sandwich attack user intents
- Partial fill 1% to block others
- Extract MEV via priority fees

---

## Testing with SolidityDefend

### Test Individual Detectors

```bash
# Test nonce management detector
soliditydefend /Users/pwner/Git/vulnerable-smart-contract-examples/erc7683-intents/VulnerableNonceManagement.sol \
  --detector intent-nonce-management

# Test signature replay detector
soliditydefend /Users/pwner/Git/vulnerable-smart-contract-examples/erc7683-intents/VulnerableSignatureReplay.sol \
  --detector intent-signature-replay

# Test settlement validation detector
soliditydefend /Users/pwner/Git/vulnerable-smart-contract-examples/erc7683-intents/VulnerableSettlementValidation.sol \
  --detector intent-settlement-validation

# Test solver manipulation detector
soliditydefend /Users/pwner/Git/vulnerable-smart-contract-examples/erc7683-intents/VulnerableSolverManipulation.sol \
  --detector intent-solver-manipulation
```

### Test All ERC7683 Detectors

```bash
# Scan all contracts with all intent detectors
soliditydefend /Users/pwner/Git/vulnerable-smart-contract-examples/erc7683-intents/ \
  --detector intent-nonce-management \
  --detector intent-signature-replay \
  --detector intent-settlement-validation \
  --detector intent-solver-manipulation
```

### Test Entire Directory

```bash
# Run all detectors on all contracts
soliditydefend /Users/pwner/Git/vulnerable-smart-contract-examples/erc7683-intents/
```

---

## Expected Results

Each contract should trigger its corresponding detector(s):

| Contract | Detector | Expected Findings |
|----------|----------|------------------|
| VulnerableNonceManagement.sol | intent-nonce-management | High (3-5 findings) |
| VulnerableSignatureReplay.sol | intent-signature-replay | Critical (4-6 findings) |
| VulnerableSettlementValidation.sol | intent-settlement-validation | High (6-8 findings) |
| VulnerableSolverManipulation.sol | intent-solver-manipulation | High (10-14 findings) |

---

## ERC-7683 Background

ERC-7683 defines a standard for **cross-chain intents** - user-signed messages expressing desired outcomes across chains without specifying exact execution paths.

**Key Components:**
- **Intent:** User's signed message with desired outcome
- **Solver:** Off-chain entity that fulfills intents
- **Settler Contract:** On-chain contract that validates and settles
- **Cross-Chain Execution:** Intent executed across multiple chains

**Security Critical Areas:**
1. **Nonce Management** - Prevent replay attacks
2. **Signature Validation** - Prevent cross-chain replays
3. **Settlement Validation** - Ensure correct fulfillment
4. **Solver Incentives** - Prevent manipulation and MEV

---

## References

- [ERC-7683 Specification](https://eips.ethereum.org/EIPS/eip-7683)
- [UniswapX Intent System](https://uniswap.org/whitepaper-uniswapx.pdf)
- [Across Protocol v3](https://docs.across.to/)
- [Intent-Based Architecture Risks](https://www.paradigm.xyz/2023/06/intents)

---

**Created for:** SolidityDefend ERC-7683 Detector Testing
**Date:** 2025-11-05
**Status:** Testing Ready ✅
