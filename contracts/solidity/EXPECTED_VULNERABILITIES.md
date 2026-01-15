# Expected Vulnerabilities Documentation

**Purpose**: This document maps each vulnerable contract to its expected vulnerabilities for SolidityDefend validation testing.

**Test Date**: 2025-11-02
**SolidityDefend Version**: 1.2.0
**Total Contracts**: 11

---

## 1. Reentrancy.sol

### Contracts:
- `VulnerableBank`
- `ReentrancyAttacker`

### Expected Vulnerabilities:

#### VulnerableBank
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Reentrancy** | Critical | `withdraw()` function | External call before state update - `msg.sender.call{value: amount}("")` at line 24 before `balances[msg.sender] = 0` at line 28 |
| **Unchecked External Call** | High | `withdraw()` function | Uses low-level `.call()` with value transfer |

**Expected Detectors to Trigger:**
- `reentrancy` - Classic reentrancy pattern (state update after external call)
- `unchecked-call` or `external-call-handling` - Low-level call with value

#### ReentrancyAttacker
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Malicious Reentrancy Pattern** | Info | `receive()` fallback | Re-enters `withdraw()` during callback |

**Notes:**
- This is the classic DAO reentrancy vulnerability pattern
- SolidityDefend should detect the vulnerable withdraw pattern in VulnerableBank

---

## 2. AccessControl.sol

### Contracts:
- `VulnerableWallet`
- `PhishingAttacker`
- `VulnerableAuction`

### Expected Vulnerabilities:

#### VulnerableWallet
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Missing Access Control** | Critical | `changeOwner()` function | Public function allows anyone to become owner (line 19) |
| **tx.origin Authentication** | Critical | `withdrawAll()` function | Uses `tx.origin == owner` instead of `msg.sender` (line 27) |
| **Unprotected Initialize** | Critical | `initialize()` function | Can be called by anyone to change owner (line 34) |
| **Arbitrary Delegatecall** | Critical | `execute()` function | Anyone can execute delegatecall to arbitrary address (line 42) |

**Expected Detectors to Trigger:**
- `missing-access-modifiers` or `unprotected-function` - changeOwner() missing access control
- `tx-origin-usage` - Use of tx.origin for authentication
- `unprotected-initialization` - Missing initialization guard
- `arbitrary-delegatecall` or `unsafe-delegatecall` - Unprotected delegatecall to user-supplied address

#### VulnerableAuction
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Missing Access Control** | Critical | `endAuction()` function | Anyone can end the auction (line 95) |
| **Missing Access Control** | Critical | `setBeneficiary()` function | Anyone can change beneficiary (line 101) |

**Expected Detectors to Trigger:**
- `missing-access-modifiers` - Both functions should have owner-only restriction

---

## 3. IntegerOverflow.sol

### Contracts:
- `VulnerableToken` (Solidity 0.7.6)
- `UncheckedOverflow` (Solidity 0.8.0+)

### Expected Vulnerabilities:

#### VulnerableToken
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Integer Overflow** | Critical | `transfer()` function | `balances[_to] += _amount` can overflow (line 27) |
| **Integer Overflow** | Critical | `batchTransfer()` function | `count * _value` can overflow (line 34) |
| **Integer Underflow** | Critical | `withdrawReward()` function | `balances[msg.sender] -= _reward` can underflow (line 46) |

**Expected Detectors to Trigger:**
- `integer-overflow` - Arithmetic operations without SafeMath in Solidity 0.7.6
- `batch-transfer-overflow` - Specific batchTransfer vulnerability

**Note:** Uses Solidity 0.7.6 without automatic overflow checks

#### UncheckedOverflow
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Unchecked Block Overflow** | High | `unsafeMultiply()` function | `amount * multiplier` in unchecked block (line 65) |
| **Unchecked Block Underflow** | High | `vulnerableWithdraw()` function | `balances[msg.sender] -= amount` in unchecked block (line 72) |

**Expected Detectors to Trigger:**
- `unchecked-arithmetic` - Use of unchecked blocks with arithmetic
- `unsafe-unchecked-math` - Potentially unsafe unchecked operations

---

## 4. UncheckedCall.sol

### Contracts:
- `VulnerablePayment`
- `VulnerableIntegration`
- `MaliciousReceiver`

### Expected Vulnerabilities:

#### VulnerablePayment
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Unchecked Call Return** | High | `withdrawUnchecked()` function | `_recipient.call{value: _amount}("")` return not checked (line 23) |
| **Unchecked Send Return** | High | `withdrawWithSend()` function | `_recipient.send(_amount)` return not checked (line 33) |
| **Unchecked Batch Calls** | High | `batchPayout()` function | Loop with unchecked `.call()` returns (line 42) |

**Expected Detectors to Trigger:**
- `unchecked-call` - Low-level call without checking return value
- `unchecked-send` - send() without checking boolean return
- `unchecked-external-call` - Any external call without proper validation

#### VulnerableIntegration
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Unchecked External Call** | High | `claimReward()` function | `externalContract.executeAction(msg.sender)` return not checked (line 69) |

**Expected Detectors to Trigger:**
- `unchecked-call` - External contract call without return validation

---

## 5. TimestampDependence.sol

### Contracts:
- `VulnerableLottery`
- `VulnerableTimelock`
- `VulnerableRandomness`

### Expected Vulnerabilities:

#### VulnerableLottery
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Weak Randomness** | Critical | `drawWinner()` function | Uses `block.timestamp` and `block.difficulty` for random (line 34) |
| **Timestamp Manipulation** | Medium | Multiple locations | Relies on `block.timestamp` for logic |

**Expected Detectors to Trigger:**
- `weak-randomness` or `predictable-randomness` - Using block variables for randomness
- `timestamp-dependence` - Critical logic depends on block.timestamp

#### VulnerableTimelock
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Timestamp Dependence** | Medium | `withdraw()` function | Access control via `block.timestamp >= lockTime[msg.sender]` (line 61) |
| **Timestamp Manipulation** | High | `emergencyWithdraw()` function | Uses `block.timestamp % 2 == 0` for access (line 71) |

**Expected Detectors to Trigger:**
- `timestamp-dependence` - Security logic based on timestamp
- `block-timestamp-manipulation` - Miner-manipulatable conditions

#### VulnerableRandomness
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Weak Randomness** | Critical | `generateRandomNumber()` function | Predictable random using block vars (line 87-92) |

**Expected Detectors to Trigger:**
- `weak-randomness` - All block variables are predictable
- `bad-randomness` - Using keccak256 with predictable inputs

---

## 6. DelegateCall.sol

### Contracts:
- `VulnerableProxy`
- `MaliciousImplementation`
- `VulnerableWallet`
- `MaliciousLibrary`
- `VulnerableRegistry`
- `MaliciousLogic`
- `UninitializedProxy`

### Expected Vulnerabilities:

#### VulnerableProxy
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Unprotected Delegatecall** | Critical | `forward()` function | Public delegatecall to implementation (line 24) |
| **Arbitrary Delegatecall** | Critical | `execute()` function | User controls target address for delegatecall (line 31) |

**Expected Detectors to Trigger:**
- `unsafe-delegatecall` - Unprotected delegatecall
- `arbitrary-delegatecall` - User-controlled delegatecall target
- `delegatecall-in-loop` - If detector checks for this pattern

#### VulnerableWallet
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Storage Collision** | Critical | `withdraw()` function | Delegatecall with potential storage mismatch (line 76) |
| **Unprotected Delegatecall** | Critical | `fallback()` function | Forwards all calls via delegatecall (line 84) |

**Expected Detectors to Trigger:**
- `unsafe-delegatecall` - Delegatecall to library without storage checks
- `fallback-delegatecall` - Fallback forwarding via delegatecall

#### VulnerableRegistry
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Selfdestruct via Delegatecall** | Critical | `executeLogic()` function | Logic contract could destroy this contract (line 125) |

**Expected Detectors to Trigger:**
- `unsafe-delegatecall` - Could execute selfdestruct in context

#### UninitializedProxy
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Unprotected Initialization** | Critical | `initialize()` function | Can be called by anyone (line 157) |

**Expected Detectors to Trigger:**
- `unprotected-initialization` - Missing access control on initialize

---

## 7. DenialOfService.sol

### Contracts:
- `VulnerableAuction`
- `VulnerableDistributor`
- `VulnerableRegistry`
- `VulnerablePaymentSplitter`
- `MaliciousBidder`

### Expected Vulnerabilities:

#### VulnerableAuction
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **DoS by Failed Transfer** | High | `bid()` function | Refund via transfer can be blocked (line 20) |

**Expected Detectors to Trigger:**
- `dos-by-failed-transfer` - transfer() can be exploited for DoS
- `push-over-pull` - Should use withdrawal pattern

#### VulnerableDistributor
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Unbounded Loop DoS** | High | `distributeRewards()` function | Loop over unbounded array (line 46, 50) |
| **Gas Limit DoS** | High | `distributeRewards()` function | Can exceed block gas limit |

**Expected Detectors to Trigger:**
- `unbounded-loop` or `gas-griefing` - Loop over dynamic array
- `dos-unbounded-operation` - Unbounded gas consumption

#### VulnerableRegistry
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Array Deletion DoS** | Medium | `reset()` function | Deleting large array consumes massive gas (line 73) |
| **Unbounded Loop** | Medium | `getUserCount()` function | Reads entire array (line 84) |

**Expected Detectors to Trigger:**
- `costly-loop` - Expensive loop operations
- `unbounded-loop` - Loop without gas consideration

#### VulnerablePaymentSplitter
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **DoS by Revert** | High | `splitPayment()` function | One revert blocks all payments (line 110) |

**Expected Detectors to Trigger:**
- `dos-by-failed-call` - Single failure stops entire operation

---

## 8. FrontRunning.sol

### Contracts:
- `VulnerablePuzzle`
- `VulnerableDEX`
- `VulnerableICO`
- `VulnerableERC20`

### Expected Vulnerabilities:

#### VulnerablePuzzle
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Front-Running** | High | `submitSolution()` function | Solution visible in mempool (line 23) |

**Expected Detectors to Trigger:**
- `front-running` or `transaction-ordering-dependence` - Mempool visibility
- `mev-extractable-value` - MEV opportunity

#### VulnerableDEX
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Transaction Ordering** | High | `swapAforB()` function | Price can change between submission and mining (line 56) |
| **MEV Sandwich** | High | `swapAforB()` function | Vulnerable to sandwich attacks |

**Expected Detectors to Trigger:**
- `mev-extractable-value` - MEV sandwich opportunity
- `transaction-ordering-dependence` - Order affects price

#### VulnerableICO
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Price Front-Running** | High | `updatePrice()`/`buyTokens()` | Owner can front-run buys with price change (line 92, 98) |

**Expected Detectors to Trigger:**
- `front-running` - Price manipulation before user transaction
- `transaction-ordering-dependence` - Order affects outcome

#### VulnerableERC20
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Approval Front-Running** | Medium | `approve()` function | Classic approve race condition (line 125) |

**Expected Detectors to Trigger:**
- `approve-race-condition` - ERC20 approval front-running
- `unsafe-approve` - Should use increaseAllowance pattern

---

## 9. SignatureReplay.sol

### Contracts:
- `VulnerableMetaTransaction`
- `VulnerableVoucherSystem`
- `VulnerableSignatureChecker`
- `VulnerableCrossChain`

### Expected Vulnerabilities:

#### VulnerableMetaTransaction
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Signature Replay** | Critical | `metaTransfer()` function | No nonce, signature can be reused (line 19) |
| **Missing Nonce** | Critical | `metaTransfer()` function | No replay protection mechanism |

**Expected Detectors to Trigger:**
- `signature-replay` - Missing nonce or timestamp
- `missing-nonce` - No replay protection

#### VulnerableVoucherSystem
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Cross-Contract Replay** | Critical | `redeemVoucher()` function | No contract address in signature (line 68) |

**Expected Detectors to Trigger:**
- `signature-replay` - Missing contract binding
- `cross-contract-replay` - Signature works on multiple contracts

#### VulnerableSignatureChecker
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Signature Malleability** | Medium | `executeWithSignature()` function | ECDSA signature can be modified (s -> -s) (line 118) |

**Expected Detectors to Trigger:**
- `signature-malleability` - ECDSA malleability not prevented
- `ecrecover-issues` - Should validate s value range

#### VulnerableCrossChain
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Missing Chain ID** | Critical | `executeMetaTransaction()` function | No chain ID in signature (line 161) |

**Expected Detectors to Trigger:**
- `missing-chain-id` - Signature can be replayed across chains
- `cross-chain-replay` - No EIP-712 domain separator

---

## 10. ShortAddress.sol

### Contracts:
- `VulnerableToken`
- `VulnerableExchange`
- `VulnerableMultisig`
- `VulnerableAirdrop`

### Expected Vulnerabilities:

#### VulnerableToken
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Short Address Attack** | Medium | `transfer()` function | No address length validation (line 30) |
| **Short Address Attack** | Medium | `batchTransfer()` function | No validation on address array (line 43) |
| **Batch Transfer Overflow** | Critical | `batchTransfer()` function | `_value * count` can overflow (line 45-46) |

**Expected Detectors to Trigger:**
- `short-address` - Missing address validation
- `batch-transfer-overflow` - Arithmetic overflow in batch transfer

#### VulnerableExchange
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Missing Zero Address Check** | Medium | `deposit()` function | No check for zero address (line 69) |
| **Missing Array Length Check** | Medium | `batchDeposit()` function | Arrays assumed same length (line 88) |
| **Missing Address Validation** | Medium | `transferBetweenUsers()` function | No checks on addresses (line 94) |

**Expected Detectors to Trigger:**
- `missing-zero-address-check` - No zero address validation
- `array-length-mismatch` - Unchecked array lengths
- `missing-input-validation` - General input validation issues

#### VulnerableMultisig
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Missing Array Validation** | High | Constructor | No validation on owners array (line 116) |
| **Missing Signature Validation** | High | `execute()` function | No validation on signatures length (line 129) |

**Expected Detectors to Trigger:**
- `missing-input-validation` - Missing array validation
- `insufficient-signature-validation` - Incomplete signature checks

#### VulnerableAirdrop
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Missing Parameter Validation** | High | `claimTokens()` function | No validation on recipient or amount (line 154) |

**Expected Detectors to Trigger:**
- `missing-zero-address-check` - No recipient validation
- `missing-input-validation` - No amount validation

---

## 11. UninitializedStorage.sol

### Contracts:
- `VulnerableStorage`
- `VulnerableArray`
- `VulnerableVisibility`
- `StorageCollision`
- `VulnerableMapping`
- `VulnerableArrayDeletion`

### Expected Vulnerabilities:

#### VulnerableStorage
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Uninitialized Storage Pointer** | Critical | `addUser()` function | Memory struct may point to storage slot 0 (line 33-35) |
| **Missing Array Bounds Check** | High | `updateUser()` function | No bounds checking on array index (line 45) |

**Expected Detectors to Trigger:**
- `uninitialized-storage` - Uninitialized struct (historical)
- `array-bounds-check` - Missing index validation

#### VulnerableArray
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Storage Pointer Issues** | Medium | `processItems()` function | Storage pointer in loop (line 75) |

**Expected Detectors to Trigger:**
- `storage-array-loop` - Storage access in loop

#### VulnerableVisibility
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Missing Visibility** | Medium | State variables | No explicit visibility modifiers (line 91-92) |
| **Public Sensitive Function** | Medium | `resetSecret()` function | Should be internal/private (line 109) |

**Expected Detectors to Trigger:**
- `missing-visibility` - Missing explicit visibility
- `public-sensitive-function` - Exposed sensitive function

#### StorageCollision
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Storage Collision** | Critical | `createTransaction()` function | Uninitialized pointer risk (line 136-138) |

**Expected Detectors to Trigger:**
- `uninitialized-storage` - Classic vulnerability pattern

#### VulnerableMapping
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Incomplete Deletion** | Medium | `deleteUser()` function | Delete doesn't clear nested mappings (line 167) |

**Expected Detectors to Trigger:**
- `delete-nested-mapping` - Nested mapping not cleared
- `incomplete-state-cleanup` - Partial state deletion

#### VulnerableArrayDeletion
| Vulnerability | Severity | Location | Description |
|---------------|----------|----------|-------------|
| **Array Gap on Delete** | Low | `deleteValue()` function | Delete creates gap, doesn't remove element (line 198) |

**Expected Detectors to Trigger:**
- `array-deletion-gap` - Using delete on array element
- `inefficient-array-deletion` - Should use pop or swap pattern

---

## Summary Statistics

### Vulnerability Categories:

| Category | Count | Contracts Affected |
|----------|-------|-------------------|
| **Access Control** | 7 | AccessControl.sol, DelegateCall.sol |
| **Reentrancy** | 1 | Reentrancy.sol |
| **Integer Overflow/Underflow** | 5 | IntegerOverflow.sol |
| **Unchecked Returns** | 5 | UncheckedCall.sol |
| **Timestamp Dependence** | 5 | TimestampDependence.sol |
| **Delegatecall Issues** | 6 | DelegateCall.sol |
| **Denial of Service** | 6 | DenialOfService.sol |
| **Front-Running/MEV** | 6 | FrontRunning.sol |
| **Signature Issues** | 6 | SignatureReplay.sol |
| **Input Validation** | 9 | ShortAddress.sol |
| **Storage Issues** | 8 | UninitializedStorage.sol |

### Severity Distribution:

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 32 | 50% |
| High | 22 | 34% |
| Medium | 10 | 16% |
| Low | 1 | <1% |

### Detection Priority:

**Must Detect (Critical):**
- Reentrancy attacks
- Missing access control
- Arbitrary delegatecall
- tx.origin authentication
- Signature replay attacks
- Integer overflow/underflow (Solidity < 0.8.0)
- Weak randomness
- Storage collision

**Should Detect (High):**
- Unchecked external calls
- DoS vulnerabilities
- Front-running opportunities
- Unprotected initialization
- Missing input validation

**Nice to Detect (Medium/Low):**
- Timestamp dependence
- Inefficient patterns
- Missing visibility modifiers
- Array deletion gaps

---

## Testing Methodology

### For Each Contract:

1. **Run SolidityDefend:**
   ```bash
   soliditydefend /path/to/Contract.sol --format json > results/Contract.json
   ```

2. **Extract Findings:**
   - Parse JSON output
   - Map detector IDs to vulnerability types
   - Check severity levels

3. **Compare with Expected:**
   - Did it find all critical vulnerabilities?
   - Are there false positives?
   - Are there false negatives?

4. **Calculate Metrics:**
   - Detection Rate: (Detected / Expected) * 100%
   - Precision: True Positives / (True Positives + False Positives)
   - Recall: True Positives / (True Positives + False Negatives)

### Success Criteria:

- ✅ **Detection Rate ≥ 80%** for critical vulnerabilities
- ✅ **False Positive Rate < 20%** (detector accuracy)
- ✅ **No False Negatives** for classic vulnerabilities (reentrancy, access control)

---

**Last Updated:** 2025-11-02
**Next Steps:** Run SolidityDefend against all contracts and validate detection accuracy
