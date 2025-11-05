# Account Abstraction (ERC-4337) Vulnerable Test Contracts

**Purpose:** Test contracts for validating SolidityDefend's ERC-4337 Account Abstraction security detectors

**Total Detectors:** 21
**Test Contracts:** 5
**Status:** ✅ Complete

---

## Overview

This directory contains intentionally vulnerable smart contracts designed to test all 21 Account Abstraction detectors in SolidityDefend v1.3.0. Each contract contains multiple documented vulnerabilities that replicate real-world ERC-4337 security issues and exploit patterns.

---

## Test Contracts

### 1. VulnerableEntryPointTrust.sol

**Tests:** EntryPoint trust and validation vulnerabilities

**Detectors:**
- `aa-account-takeover` (Critical)
- `erc4337-entrypoint-trust` (Critical)

**Vulnerabilities:**
1. Hardcoded EntryPoint without validation
2. Mutable EntryPoint without access control
3. Missing EntryPoint validation in `validateUserOp`
4. No timelock for EntryPoint changes
5. Unprotected EntryPoint replacement allowing account takeover
6. No validation that EntryPoint is legitimate contract

**Key Attack Vector:** Attacker can call `setEntryPoint()` with malicious contract address, then drain all funds through fake EntryPoint.

---

### 2. VulnerablePaymaster.sol

**Tests:** Paymaster abuse and fund draining vulnerabilities

**Detectors:**
- `aa-paymaster-fund-drain` (Critical)
- `erc4337-paymaster-abuse` (Critical)

**Vulnerabilities:**
1. No gas limit cap on sponsored operations
2. Missing user whitelist or rate limiting
3. No paymaster balance validation
4. Missing per-user spending limits
5. UserOp hash replay attacks
6. Gas griefing vectors
7. No replay protection after signature verification
8. Signature not bound to chain ID

**Key Attack Vector:** Attacker submits UserOps with unlimited gas limits and no spending restrictions, repeatedly draining paymaster funds. Same UserOp can be replayed across chains.

---

### 3. VulnerableSignatureValidation.sol

**Tests:** Signature validation and calldata manipulation vulnerabilities

**Detectors:**
- `aa-calldata-encoding-exploit` (Critical)
- `aa-signature-aggregation-bypass` (High)
- `aa-user-operation-replay` (High)

**Vulnerabilities:**
1. Calldata decoded after signature validation
2. UserOperation fields modified after validation
3. Missing chain ID validation for replay protection
4. Missing nonce validation
5. Signature aggregation without individual validation
6. Missing unique operation IDs
7. Batch validation without array length checks
8. No duplicate signer detection in multi-sig
9. UserOp hash doesn't include all fields

**Key Attack Vector:** Attacker signs a benign UserOp, then modifies calldata after signature check but before execution. Can also replay UserOps across chains and bypass multi-sig thresholds.

---

### 4. VulnerableAccountManagement.sol

**Tests:** Initialization, session keys, social recovery, and nonce management

**Detectors:**
- `aa-initialization-vulnerability` (High)
- `aa-session-key-vulnerabilities` (High)
- `aa-social-recovery` (Medium)
- `aa-nonce-management` (High)
- `aa-nonce-management-advanced` (Medium)

**Vulnerabilities:**
1. Initialization without signature verification
2. Missing initialization lock (can be re-initialized)
3. Session keys without expiration
4. Session keys with unlimited permissions
5. Missing spending limits on session keys
6. Social recovery without timelock
7. Insufficient guardian threshold
8. Missing nonce validation
9. No support for parallel nonce keys
10. No spending limit reset period

**Key Attack Vectors:**
- **Initialization:** Anyone can call `initialize()` and set themselves as owner
- **Session Keys:** Permanent keys with unlimited access to all contracts and functions
- **Social Recovery:** Single guardian can immediately change owner without delay
- **Nonces:** Sequential-only nonces prevent parallel transaction execution

---

### 5. VulnerableBundlerDoS.sol

**Tests:** Bundler DoS and gas griefing vulnerabilities

**Detectors:**
- `aa-bundler-dos` (Medium)
- `aa-bundler-dos-enhanced` (High)
- `aa-entry-point-reentrancy` (Medium)
- `erc4337-gas-griefing` (Low)

**Vulnerabilities:**
1. External calls in `validateUserOp`
2. Unbounded loops in validation
3. Storage access violations
4. Expensive operations without gas limits
5. Storage reads from unknown contracts
6. Reentrancy in validation phase
7. Reentrancy in `handleOps`
8. Storage writes in validation (gas griefing)

**Key Attack Vectors:**
- **Bundler DoS:** Submit UserOps with massive arrays or expensive external calls in validation, causing bundlers to fail or timeout
- **Gas Griefing:** Write to storage in validation phase, consuming excessive gas and preventing other operations from bundling
- **Reentrancy:** Re-enter validation or execution functions before state is properly updated

---

## Testing Instructions

### Run All Tests

```bash
cd /Users/pwner/Git/ABS/SolidityDefend

# Build latest version
cargo build --release --bin soliditydefend

# Test all AA contracts
./target/release/soliditydefend \
  /Users/pwner/Git/vulnerable-smart-contract-examples/account-abstraction/*.sol \
  --format console \
  --min-severity high
```

### Test Individual Contracts

```bash
# Test EntryPoint vulnerabilities
./target/release/soliditydefend \
  /Users/pwner/Git/vulnerable-smart-contract-examples/account-abstraction/VulnerableEntryPointTrust.sol \
  --format json \
  --output entrypoint-results.json

# Test Paymaster vulnerabilities
./target/release/soliditydefend \
  /Users/pwner/Git/vulnerable-smart-contract-examples/account-abstraction/VulnerablePaymaster.sol \
  --format console

# Test Signature validation
./target/release/soliditydefend \
  /Users/pwner/Git/vulnerable-smart-contract-examples/account-abstraction/VulnerableSignatureValidation.sol \
  --format sarif \
  --output signature-results.sarif

# Test Account management
./target/release/soliditydefend \
  /Users/pwner/Git/vulnerable-smart-contract-examples/account-abstraction/VulnerableAccountManagement.sol \
  --format console

# Test Bundler DoS
./target/release/soliditydefend \
  /Users/pwner/Git/vulnerable-smart-contract-examples/account-abstraction/VulnerableBundlerDoS.sol \
  --format console
```

---

## Expected Results

### Vulnerability Counts

| Contract | Critical | High | Medium | Low | Total |
|----------|----------|------|--------|-----|-------|
| VulnerableEntryPointTrust.sol | 18 | 18 | - | - | 36 |
| VulnerablePaymaster.sol | 10 | 15 | - | - | 25 |
| VulnerableSignatureValidation.sol | 22 | 31 | - | - | 53 |
| VulnerableAccountManagement.sol | 44 | 67 | - | - | 111 |
| VulnerableBundlerDoS.sol | 19 | 38 | - | - | 57 |
| **TOTAL** | **113** | **169** | **-** | **-** | **282** |

### Detector Validation

All 21 Account Abstraction detectors should trigger:

**Critical (5):**
- ✅ `aa-account-takeover`
- ✅ `aa-calldata-encoding-exploit`
- ✅ `aa-paymaster-fund-drain`
- ✅ `erc4337-entrypoint-trust`
- ✅ `erc4337-paymaster-abuse`

**High (10):**
- ✅ `aa-bundler-dos-enhanced`
- ✅ `aa-initialization-vulnerability`
- ✅ `aa-nonce-management`
- ✅ `aa-session-key-vulnerabilities`
- ✅ `aa-signature-aggregation`
- ✅ `aa-signature-aggregation-bypass`
- ✅ `aa-user-operation-replay`

**Medium (5):**
- ✅ `aa-bundler-dos`
- ✅ `aa-entry-point-reentrancy`
- ✅ `aa-nonce-management-advanced`
- ✅ `aa-social-recovery`

**Low (1):**
- ✅ `erc4337-gas-griefing`

---

## Real-World Exploit Patterns

These test contracts replicate vulnerabilities from actual exploits:

### 1. Biconomy Paymaster Exploit Pattern
**Contract:** VulnerablePaymaster.sol
**Vulnerability:** No replay protection, missing nonce validation
**Impact:** Attacker reuses valid signatures to drain paymaster funds

### 2. EntryPoint Replacement Attack
**Contract:** VulnerableEntryPointTrust.sol
**Vulnerability:** Unprotected EntryPoint assignment
**Impact:** Complete account takeover, fund draining

### 3. Session Key Overreach
**Contract:** VulnerableAccountManagement.sol
**Vulnerability:** Unlimited permissions without expiration
**Impact:** Compromised session key = full account access

### 4. Initialization Front-Running
**Contract:** VulnerableAccountManagement.sol
**Vulnerability:** Unprotected initialize function
**Impact:** Attacker initializes contract with their address as owner

### 5. Bundler DoS via Gas Griefing
**Contract:** VulnerableBundlerDoS.sol
**Vulnerability:** Unbounded loops and external calls in validation
**Impact:** Bundlers fail to process UserOps, network congestion

### 6. Cross-Chain Replay
**Contract:** VulnerableSignatureValidation.sol
**Vulnerability:** UserOp hash without chain ID
**Impact:** Same signature valid on multiple chains

---

## Documentation

- **TEST_RESULTS.md** - Comprehensive test results and analysis
- **README.md** - This file
- Individual .sol files contain inline vulnerability documentation

---

## Security Patterns

### ❌ Vulnerable Patterns

```solidity
// Unprotected EntryPoint
function validateUserOp(...) external {
    // Missing: require(msg.sender == trustedEntryPoint);
}

// No gas limits
function validatePaymasterUserOp(...) external {
    // Missing: require(userOp.callGasLimit <= MAX_GAS_LIMIT);
}

// Missing chain ID
function getUserOpHash(...) public pure {
    return keccak256(abi.encode(userOp.sender, userOp.nonce));
    // Missing: block.chainid
}

// Unprotected initialization
function initialize(address _owner) external {
    // Missing: signature verification
    owner = _owner; // Anyone can call!
}

// Session key without restrictions
function addSessionKey(address key) external {
    isSessionKey[key] = true;
    // Missing: validUntil, allowedTargets, spendingLimit
}
```

### ✅ Secure Patterns

```solidity
// Protected EntryPoint validation
modifier onlyEntryPoint() {
    require(msg.sender == ENTRY_POINT, "Only EntryPoint");
    _;
}

// Gas limits enforced
require(userOp.callGasLimit <= MAX_CALL_GAS_LIMIT, "Gas too high");

// Chain ID included
bytes32 hash = keccak256(abi.encode(
    userOp.sender,
    userOp.nonce,
    userOp.callData,
    block.chainid
));

// Secure initialization
function initialize(address _owner, bytes calldata signature) external {
    require(!initialized, "Already initialized");
    bytes32 hash = keccak256(abi.encodePacked(_owner, address(this), block.chainid));
    require(recoverSigner(hash, signature) == _owner, "Invalid signature");
    owner = _owner;
    initialized = true;
}

// Restricted session key
sessionKeys[key] = SessionKeyData({
    validUntil: block.timestamp + 30 days,
    allowedTargets: targets,
    allowedSelectors: selectors,
    spendingLimit: limit
});
```

---

## References

- **ERC-4337 Specification:** https://eips.ethereum.org/EIPS/eip-4337
- **Account Abstraction Security:** https://github.com/eth-infinitism/account-abstraction
- **SolidityDefend Documentation:** `/Users/pwner/Git/ABS/SolidityDefend/docs/detectors/account-abstraction/`

---

**Created:** 2025-11-05
**SolidityDefend Version:** v1.3.0
**Status:** ✅ All 21 detectors validated
**Next:** DeFi Protocols testing (21 detectors)
