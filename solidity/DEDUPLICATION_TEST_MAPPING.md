# Multi-Scanner Deduplication Test Mapping

This document maps which scanners should detect which vulnerabilities in the test contracts for Phase 3 deduplication testing.

## Test Contract 1: Reentrancy.sol

**File**: `Reentrancy.sol`
**Vulnerability Location**: Line 24 in `VulnerableBank.withdraw()`
**Vulnerability Type**: Classic Reentrancy Attack

### Expected Scanner Detections:

| Scanner | Detector ID | Pattern Code | Confidence |
|---------|-------------|--------------|------------|
| **Slither** | `reentrancy-eth` | BVD-SOL-REE-001 | High |
| **Aderyn** | `reentrancy` | BVD-SOL-REE-001 | High |
| **Semgrep** | `solidity-security/reentrancy` | BVD-SOL-REE-001 | Medium |

**Expected Deduplication**:
- 3 findings should be created (one per scanner)
- 1 deduplication group should be created
- Confidence level: "exact" (all 3 scanners agree)
- Scanner count: 3
- Canonical finding: Slither (highest confidence + first alphabetically)

**Vulnerability Code Snippet**:
```solidity
// VULNERABILITY: External call before state update
(bool success, ) = msg.sender.call{value: amount}("");
require(success, "Transfer failed");

// State update happens too late
balances[msg.sender] = 0;
```

---

## Test Contract 2: AccessControl.sol

**File**: `AccessControl.sol`
**Vulnerability Location**: Line 27 in `VulnerableWallet.withdrawAll()`
**Vulnerability Type**: tx.origin Authentication

### Expected Scanner Detections:

| Scanner | Detector ID | Pattern Code | Confidence |
|---------|-------------|--------------|------------|
| **Slither** | `tx-origin` | BVD-SOL-ACC-007 | High |
| **Solhint** | `avoid-tx-origin` | BVD-SOL-ACC-007 | Medium |

**Expected Deduplication**:
- 2 findings should be created (one per scanner)
- 1 deduplication group should be created
- Confidence level: "high" (2 scanners agree)
- Scanner count: 2
- Canonical finding: Slither (higher confidence)

**Vulnerability Code Snippet**:
```solidity
// VULNERABILITY: Uses tx.origin instead of msg.sender
require(tx.origin == owner, "Not owner");
payable(_recipient).transfer(address(this).balance);
```

---

## Test Contract 3: UncheckedCall.sol

**File**: `UncheckedCall.sol`
**Vulnerability Locations**: Lines 23, 33, 42
**Vulnerability Type**: Unchecked Low-Level Call Return Values

### Expected Scanner Detections (Line 23):

| Scanner | Detector ID | Pattern Code | Confidence |
|---------|-------------|--------------|------------|
| **Slither** | `unchecked-lowlevel` | BVD-SOL-ERR-001 | Medium |
| **Aderyn** | `unchecked-return-value` | BVD-SOL-ERR-001 | Medium |

**Expected Deduplication**:
- 2 findings for line 23 (one per scanner)
- 1 finding for line 33 (Slither: unchecked-send)
- 1 finding for line 42 (Slither: unchecked-lowlevel in loop)
- 1 deduplication group for line 23 (Slither + Aderyn)
- Confidence level: "high" (2 scanners agree on line 23)
- Scanner count: 2

**Vulnerability Code Snippet (Line 23)**:
```solidity
// VULNERABILITY: Return value not checked
_recipient.call{value: _amount}("");
// If the call fails, the user loses their balance!
```

---

## Summary

### Total Expected Findings:
- **Reentrancy.sol**: 3 findings → 1 dedup group (3 scanners)
- **AccessControl.sol**: 2 findings → 1 dedup group (2 scanners)
- **UncheckedCall.sol**: 4 findings → 1 dedup group for line 23 (2 scanners), 2 unique findings

### Total Expected Deduplication Groups: 3

### Deduplication Accuracy Metrics:
- **Exact match** (3 scanners): 1 group (reentrancy)
- **High confidence** (2 scanners): 2 groups (tx-origin, unchecked-call)
- **Unique findings** (1 scanner): 2 findings (unchecked-send on line 33, unchecked-lowlevel on line 42)

### Canonical Finding Selection Criteria:
1. Highest severity (critical > high > medium > low)
2. If severity equal: Highest confidence
3. If confidence equal: First alphabetically by scanner_id

---

## Test Validation Checklist

- [ ] Run all 3 contracts through Slither, Aderyn, Semgrep, Solhint
- [ ] Verify expected detector IDs are present
- [ ] Verify deduplication groups created correctly
- [ ] Verify canonical finding selection logic
- [ ] Verify fingerprint matching (code_hash, location_hash)
- [ ] Verify scanner_count accurate
- [ ] Verify confidence_level calculation
- [ ] Document any unmapped detectors

---

## Notes

- These mappings are based on the vulnerability_patterns.json database
- Actual detector IDs may vary slightly between scanner versions
- Some scanners may detect additional related vulnerabilities (e.g., state-change-after-call)
- Deduplication uses fingerprint matching (code_hash + location_hash + pattern_id)
