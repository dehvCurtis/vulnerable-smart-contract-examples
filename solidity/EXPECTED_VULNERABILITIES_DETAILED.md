# Expected Vulnerabilities Catalog - Detailed

**Version:** 1.1
**Last Updated:** 2025-11-03
**Purpose:** Comprehensive documentation of expected vulnerabilities with line numbers and detector mappings

---

## Overview

This document catalogs **69 distinct vulnerability patterns** across **11 purposefully vulnerable Solidity contracts**. Each vulnerability is documented with:
- Exact line numbers
- Severity rating
- Expected detector ID
- Code pattern description

### Summary Statistics

| Contract | Expected Vulns | Primary Category | Solidity Version |
|----------|---------------|------------------|------------------|
| AccessControl.sol | 6 | Access Control | 0.8.0 |
| DelegateCall.sol | 8 | Delegatecall Issues | 0.8.0 |
| DenialOfService.sol | 7 | DoS Patterns | 0.8.0 |
| FrontRunning.sol | 7 | Front-Running | 0.8.0 |
| IntegerOverflow.sol | 5 | Integer Arithmetic | 0.7.6 |
| Reentrancy.sol | 1 | Reentrancy | 0.8.0 |
| ShortAddress.sol | 7 | Input Validation | 0.8.0 |
| SignatureReplay.sol | 7 | Signature Security | 0.8.0 |
| TimestampDependence.sol | 6 | Timestamp/Randomness | 0.8.0 |
| UncheckedCall.sol | 3 | Unchecked Returns | 0.8.0 |
| UninitializedStorage.sol | 8 | Storage Issues | 0.7.6 |
| **Total** | **69** | - | - |

---

## 1. AccessControl.sol (6 vulnerabilities)

### 1.1 Missing Access Control on changeOwner()
```
Line: 19-22
Severity: Critical
Contract: VulnerableWallet
Function: changeOwner(address _newOwner)
Pattern: Public state-changing function without access control
Expected Detector: missing-access-modifier
```
**Description:** Anyone can call this function and become the contract owner.

### 1.2 tx.origin Authentication
```
Line: 25-29
Severity: Critical
Contract: VulnerableWallet
Function: withdrawAll(address _recipient)
Pattern: require(tx.origin == owner)
Expected Detector: tx-origin-authentication
```
**Description:** Uses tx.origin instead of msg.sender, enabling phishing attacks.

### 1.3 Unprotected Initialization
```
Line: 34-39
Severity: High
Contract: VulnerableWallet
Function: initialize(address _owner)
Pattern: Public initialize without protection
Expected Detector: unprotected-initialization, aa-initialization-vulnerability
```
**Description:** Initialization function can be called by anyone.

### 1.4 Dangerous Delegatecall
```
Line: 42-47
Severity: Critical
Contract: VulnerableWallet
Function: execute(address _target, bytes memory _data)
Pattern: _target.delegatecall(_data) where _target is user-controlled
Expected Detector: dangerous-delegatecall
```
**Description:** Allows arbitrary delegatecall without access control.

### 1.5 Missing Access Control on endAuction()
```
Line: 95-98
Severity: Critical
Contract: VulnerableAuction
Function: endAuction()
Pattern: Public function triggering fund transfer without access control
Expected Detector: missing-access-modifier
```
**Description:** Anyone can end the auction and trigger fund transfer.

### 1.6 Missing Access Control on setBeneficiary()
```
Line: 101-104
Severity: Critical
Contract: VulnerableAuction
Function: setBeneficiary(address _beneficiary)
Pattern: Critical parameter modification without protection
Expected Detector: missing-access-modifier
```
**Description:** Anyone can change the beneficiary address.

---

## 2. DelegateCall.sol (8 vulnerabilities)

### 2.1 Unprotected Delegatecall in forward()
```
Line: 21-26
Severity: Critical
Contract: VulnerableProxy
Function: forward(bytes memory _data)
Pattern: implementation.delegatecall(_data) without access control
Expected Detector: dangerous-delegatecall
```

### 2.2 Delegatecall to User-Supplied Address
```
Line: 29-33
Severity: Critical
Contract: VulnerableProxy
Function: execute(address _target, bytes memory _data)
Pattern: _target.delegatecall(_data) where both target and data are user-controlled
Expected Detector: dangerous-delegatecall
```

### 2.3 Storage Collision in VulnerableWallet
```
Line: 73-80
Severity: High
Contract: VulnerableWallet
Function: withdraw(uint256 _amount)
Pattern: Delegatecall to library with different storage layout
Expected Detector: storage-collision, dangerous-delegatecall
```

### 2.4 Delegatecall in Fallback Function
```
Line: 82-86
Severity: Critical
Contract: VulnerableWallet
Fallback function with delegatecall
Expected Detector: dangerous-delegatecall
```

### 2.5 Selfdestruct via Delegatecall
```
Line: 124-127
Severity: Critical
Contract: VulnerableRegistry
Function: executeLogic(bytes memory _data)
Pattern: Delegatecall to contract that can selfdestruct
Expected Detector: dangerous-delegatecall, selfdestruct-vulnerability
```

### 2.6 Uninitialized Proxy Constructor
```
Line: 150-154
Severity: High
Contract: UninitializedProxy
Constructor doesn't properly initialize
Expected Detector: aa-initialization-vulnerability
```

### 2.7 Unprotected Proxy Initialize
```
Line: 157-161
Severity: High
Contract: UninitializedProxy
Function: initialize(address _owner)
Expected Detector: unprotected-initialization
```

### 2.8 Fallback Delegatecall Pattern
```
Line: 163-166
Severity: High
Contract: UninitializedProxy
Fallback with delegatecall
Expected Detector: dangerous-delegatecall
```

---

## 3. DenialOfService.sol (7 vulnerabilities)

### 3.1 DoS by Failed Transfer
```
Line: 15-25
Severity: High
Contract: VulnerableAuction
Function: bid()
Pattern: payable(currentLeader).transfer(currentBid) before state update
Expected Detector: dos-failed-transfer, push-over-pull-pattern
```
**Description:** Malicious receiver can block all future bids by rejecting refund.

### 3.2 Unbounded Loop - distributeRewards()
```
Line: 42-54
Severity: High
Contract: VulnerableDistributor
Function: distributeRewards()
Pattern: for loop over shareholders.length without bound
Expected Detector: unbounded-loop, dos-unbounded-operation
```

### 3.3 Unbounded Loop - reset()
```
Line: 72-78
Severity: Medium
Contract: VulnerableRegistry
Function: reset()
Pattern: for loop over users.length for deletion
Expected Detector: unbounded-loop, costly-loop-in-function
```

### 3.4 Unbounded Loop - getUserCount()
```
Line: 81-90
Severity: Medium
Contract: VulnerableRegistry
Function: getUserCount()
Pattern: for loop over entire users array in view function
Expected Detector: unbounded-loop
```

### 3.5 Transfer in Loop - distributeRewards()
```
Line: 50-53
Severity: High
Contract: VulnerableDistributor
Pattern: transfer() inside loop
Expected Detector: dos-failed-transfer
```

### 3.6 Transfer in Loop - splitPayment()
```
Line: 105-112
Severity: High
Contract: VulnerablePaymentSplitter
Function: splitPayment()
Pattern: transfer() in loop without error handling
Expected Detector: dos-failed-transfer
```

### 3.7 DoS by External Contract
```
Line: 109-111
Severity: High
Contract: VulnerablePaymentSplitter
Pattern: One malicious recipient can block all payments
Expected Detector: dos-failed-transfer, external-call-in-loop
```

---

## 4. FrontRunning.sol (7 vulnerabilities)

### 4.1 Front-Running in submitSolution()
```
Line: 23-31
Severity: High
Contract: VulnerablePuzzle
Function: submitSolution(string memory _solution)
Pattern: Solution visible in mempool before confirmation
Expected Detector: mev-extractable-value, front-running-vulnerability
```

### 4.2 Transaction Ordering - DEX Swap
```
Line: 56-69
Severity: High
Contract: VulnerableDEX
Function: swapAforB(uint256 _tokenAAmount, uint256 _minTokenBAmount)
Pattern: Price calculation vulnerable to front-running
Expected Detector: mev-extractable-value, transaction-ordering-dependence
```

### 4.3 Slippage Vulnerability
```
Line: 62
Severity: Medium
Contract: VulnerableDEX
Pattern: Slippage check can be gamed
Expected Detector: mev-toxic-flow-exposure
```

### 4.4 Price Manipulation Front-Running
```
Line: 92-96
Severity: High
Contract: VulnerableICO
Function: updatePrice(uint256 _newPrice)
Pattern: Owner can front-run buyTokens transactions
Expected Detector: front-running-vulnerability, transaction-ordering-dependence
```

### 4.5 Price Change Without Protection
```
Line: 98-106
Severity: Medium
Contract: VulnerableICO
Function: buyTokens(uint256 _amount)
Pattern: Price might change between submission and execution
Expected Detector: transaction-ordering-dependence
```

### 4.6 ERC20 Approve Race Condition
```
Line: 125-134
Severity: Medium
Contract: VulnerableERC20
Function: approve(address _spender, uint256 _amount)
Pattern: Standard ERC20 approve race (N → M allows N+M withdrawal)
Expected Detector: erc20-approve-race, front-running-vulnerability
```

### 4.7 MEV Extractable Value
```
Line: Multiple functions
Severity: Medium to High
Pattern: Publicly visible profitable transactions
Expected Detector: mev-extractable-value
```

---

## 5. IntegerOverflow.sol (5 vulnerabilities)

### 5.1 Addition Overflow (Solidity 0.7.6)
```
Line: 22-28
Severity: Critical
Contract: VulnerableToken (0.7.6)
Function: transfer(address _to, uint256 _amount)
Pattern: balances[_to] += _amount without overflow check
Expected Detector: integer-overflow, arithmetic-overflow
```

### 5.2 Batch Transfer Overflow (BeautyChain)
```
Line: 31-41
Severity: Critical
Contract: VulnerableToken (0.7.6)
Function: batchTransfer(address[] memory _receivers, uint256 _value)
Pattern: uint256 amount = count * _value (can overflow)
Expected Detector: batch-transfer-overflow, integer-overflow
```
**Note:** This is the famous BeautyChain vulnerability that caused $1B in losses.

### 5.3 Subtraction Underflow
```
Line: 44-47
Severity: Critical
Contract: VulnerableToken (0.7.6)
Function: withdrawReward(uint256 _reward)
Pattern: balances[msg.sender] -= _reward without check
Expected Detector: integer-underflow, arithmetic-underflow
```

### 5.4 Unchecked Block Multiplication
```
Line: 62-67
Severity: High
Contract: UncheckedOverflow (0.8.0+)
Function: unsafeMultiply(uint256 amount, uint256 multiplier)
Pattern: unchecked { return amount * multiplier; }
Expected Detector: unchecked-arithmetic, integer-overflow
```

### 5.5 Unchecked Block Underflow
```
Line: 69-75
Severity: High
Contract: UncheckedOverflow (0.8.0+)
Function: vulnerableWithdraw(uint256 amount)
Pattern: unchecked { balances[msg.sender] -= amount; }
Expected Detector: unchecked-arithmetic, integer-underflow
```

---

## 6. Reentrancy.sol (1 vulnerability)

### 6.1 Classic Reentrancy
```
Line: 19-29
Severity: Critical
Contract: VulnerableBank
Function: withdraw()
Pattern: msg.sender.call{value: amount}("") before balances[msg.sender] = 0
Expected Detector: classic-reentrancy, reentrancy-vulnerability
```
**Description:** Violates checks-effects-interactions pattern, enabling reentrancy attack.

---

## 7. ShortAddress.sol (7 vulnerabilities)

### 7.1 Short Address Attack - transfer()
```
Line: 30-40
Severity: Medium
Contract: VulnerableToken
Function: transfer(address _to, uint256 _value)
Pattern: No msg.data.length validation
Expected Detector: short-address-attack
```

### 7.2 Batch Transfer Without Validation
```
Line: 43-58
Severity: Medium
Contract: VulnerableToken
Function: batchTransfer(address[] memory _receivers, uint256 _value)
Pattern: No validation on address array or input length
Expected Detector: short-address-attack, batch-transfer-overflow
```

### 7.3 Missing Zero Address Check - deposit()
```
Line: 69-73
Severity: Low
Contract: VulnerableExchange
Function: deposit(address _token, uint256 _amount)
Pattern: No check for _token == address(0)
Expected Detector: missing-zero-address-check
```

### 7.4 Missing Zero Address Check - withdraw()
```
Line: 76-80
Severity: Low
Contract: VulnerableExchange
Function: withdraw(address _token, uint256 _amount)
Pattern: No address validation
Expected Detector: missing-zero-address-check
```

### 7.5 Array Length Mismatch
```
Line: 83-91
Severity: Medium
Contract: VulnerableExchange
Function: batchDeposit(address[] memory _tokens, uint256[] memory _amounts)
Pattern: Assumes arrays have same length, no validation
Expected Detector: array-length-mismatch
```

### 7.6 Missing Address Validation - transferBetweenUsers()
```
Line: 94-104
Severity: Medium
Contract: VulnerableExchange
Function: transferBetweenUsers(...)
Pattern: No checks on zero address or same address
Expected Detector: missing-zero-address-check, input-validation-missing
```

### 7.7 Missing Signatures Validation
```
Line: 121-138
Severity: High
Contract: VulnerableMultisig
Function: execute(...)
Pattern: No validation that signatures array is properly formed
Expected Detector: input-validation-missing, missing-array-length-check
```

---

## 8. SignatureReplay.sol (7 vulnerabilities)

### 8.1 Signature Replay - No Nonce
```
Line: 19-34
Severity: Critical
Contract: VulnerableMetaTransaction
Function: metaTransfer(...)
Pattern: Signature verification without nonce
Expected Detector: signature-replay, missing-nonce
```

### 8.2 Cross-Contract Signature Replay
```
Line: 68-82
Severity: High
Contract: VulnerableVoucherSystem
Function: redeemVoucher(...)
Pattern: Signature doesn't include contract address
Expected Detector: signature-replay, cross-contract-replay
```

### 8.3 Signature Malleability
```
Line: 113-134
Severity: Medium
Contract: VulnerableSignatureChecker
Function: executeWithSignature(...)
Pattern: ecrecover without malleability check (s value not validated)
Expected Detector: signature-malleability, ecdsa-malleability
```

### 8.4 Missing Chain ID
```
Line: 161-179
Severity: High
Contract: VulnerableCrossChain
Function: executeMetaTransaction(...)
Pattern: Signature without chain ID can be replayed on different chains
Expected Detector: signature-replay, missing-chain-id
```

### 8.5 Incomplete Replay Protection
```
Line: 158-179
Severity: Medium
Contract: VulnerableCrossChain
Pattern: Has nonce but no contract address in signature
Expected Detector: signature-replay
```

### 8.6 ecrecover Without Validation
```
Line: 40-43, 89-91, etc.
Severity: Low to Medium
Pattern: ecrecover can return address(0) on error, not validated
Expected Detector: ecrecover-zero-address, signature-validation-missing
```

### 8.7 Signature Reuse - Voucher System
```
Line: 68-82
Severity: High
Contract: VulnerableVoucherSystem
Pattern: User-based nonce instead of global replay protection
Expected Detector: signature-replay
```

---

## 9. TimestampDependence.sol (6 vulnerabilities)

### 9.1 Timestamp for Control Flow
```
Line: 24, 30
Severity: Medium
Contract: VulnerableLottery
Pattern: require(block.timestamp < lotteryEndTime)
Expected Detector: timestamp-manipulation
```

### 9.2 Weak Randomness - keccak256 with Block Variables
```
Line: 34
Severity: Critical
Contract: VulnerableLottery
Function: drawWinner()
Pattern: keccak256(abi.encodePacked(block.timestamp, block.difficulty))
Expected Detector: timestamp-manipulation, weak-randomness
```

### 9.3 Time-Based Access Control
```
Line: 58-65
Severity: Medium
Contract: VulnerableTimelock
Function: withdraw()
Pattern: require(block.timestamp >= lockTime[msg.sender])
Expected Detector: timestamp-manipulation
```

### 9.4 Modulo on block.timestamp
```
Line: 71
Severity: Medium
Contract: VulnerableTimelock
Function: emergencyWithdraw()
Pattern: block.timestamp % 2 == 0
Expected Detector: timestamp-manipulation, weak-randomness
```

### 9.5 Predictable Randomness
```
Line: 87-92
Severity: Critical
Contract: VulnerableRandomness
Function: generateRandomNumber()
Pattern: keccak256 with block.timestamp, block.difficulty, block.number, msg.sender
Expected Detector: weak-randomness, timestamp-manipulation
```

### 9.6 Block Variables for Game Outcome
```
Line: 98-108
Severity: Critical
Contract: VulnerableRandomness
Function: playGame()
Pattern: Financial outcome based on weak randomness
Expected Detector: weak-randomness
```

---

## 10. UncheckedCall.sol (3 vulnerabilities)

### 10.1 Unchecked Low-Level Call
```
Line: 18-25
Severity: High
Contract: VulnerablePayment
Function: withdrawUnchecked(address payable _recipient, uint256 _amount)
Pattern: _recipient.call{value: _amount}("") without checking return value
Expected Detector: unchecked-external-call, unchecked-low-level-call
```

### 10.2 Unchecked send()
```
Line: 28-34
Severity: High
Contract: VulnerablePayment
Function: withdrawWithSend(address payable _recipient, uint256 _amount)
Pattern: _recipient.send(_amount) without checking return value
Expected Detector: unchecked-send
```

### 10.3 Unchecked Call in Loop
```
Line: 37-44
Severity: High
Contract: VulnerablePayment
Function: batchPayout(...)
Pattern: Loop with unchecked external calls
Expected Detector: unchecked-external-call
```

---

## 11. UninitializedStorage.sol (8 vulnerabilities)

### 11.1 Uninitialized Storage Pointer (Historical)
```
Line: 33-40
Severity: Medium (Historical - pre-0.5.0)
Contract: VulnerableStorage
Function: addUser(...)
Pattern: User memory newUser (uninitialized)
Expected Detector: uninitialized-storage-pointer (may not detect in 0.7.6+)
```

### 11.2 Missing Array Bounds Check
```
Line: 44-48
Severity: High
Contract: VulnerableStorage
Function: updateUser(uint256 _index, address _addr)
Pattern: users[_index] without bounds checking
Expected Detector: array-bounds-check, missing-bounds-check
```

### 11.3 Storage Pointer in Loop
```
Line: 72-79
Severity: Low
Contract: VulnerableArray
Function: processItems()
Pattern: Storage pointer manipulation in loop
Expected Detector: storage-manipulation-in-loop
```

### 11.4 Default Visibility (Historical)
```
Line: 91-96
Severity: Low (Historical - pre-0.5.0)
Contract: VulnerableVisibility
Pattern: State variables without explicit visibility
Expected Detector: missing-visibility-modifier
```

### 11.5 Storage Collision (Historical)
```
Line: 136-142
Severity: Medium (Historical)
Contract: StorageCollision
Function: createTransaction(...)
Pattern: Uninitialized storage struct
Expected Detector: storage-collision, uninitialized-storage-pointer
```

### 11.6 Delete Mapping Doesn't Clear Nested Mappings
```
Line: 166-170
Severity: Medium
Contract: VulnerableMapping
Function: deleteUser()
Pattern: delete users[msg.sender] with nested mapping
Expected Detector: delete-nested-mapping, incomplete-state-cleanup
```

### 11.7 Array Delete Creates Gap
```
Line: 194-199
Severity: Low
Contract: VulnerableArrayDeletion
Function: deleteValue(uint256 _index)
Pattern: delete values[_index] creates gap in array
Expected Detector: array-delete-gap, improper-array-deletion
```

### 11.8 Accessing Deleted Array Elements
```
Line: 202-205
Severity: Low
Contract: VulnerableArrayDeletion
Function: getValue(uint256 _index)
Pattern: Returns 0 for deleted elements
Expected Detector: deleted-element-access
```

---

## Testing Methodology

For each contract:
1. Run: `soliditydefend <contract>.sol --format json`
2. Compare detections against expected vulnerabilities
3. Calculate detection rate: (detected / expected) × 100%
4. Identify false negatives (missed vulnerabilities)
5. Identify false positives (unexpected detections)

---

**Document Version:** 1.1
**Maintained By:** Security Testing Team
**Last Updated:** 2025-11-03
