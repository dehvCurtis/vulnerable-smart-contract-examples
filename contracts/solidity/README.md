# Vulnerable Smart Contract Examples

This repository contains intentionally vulnerable Solidity smart contracts for educational and security testing purposes. **DO NOT deploy these contracts to production networks.**

## Purpose

These contracts demonstrate common vulnerabilities found in smart contracts to help developers:
- Understand security risks in smart contract development
- Learn how to identify vulnerabilities during code reviews
- Practice security testing and exploitation techniques
- Develop secure coding practices

## Vulnerability Inventory

### 1. Reentrancy.sol
**Primary Vulnerabilities:**
- **Reentrancy Attack**: External calls made before state updates allow attackers to recursively call functions and drain funds
- **State Update After External Call**: Balance updates occur after the external transfer, violating the Checks-Effects-Interactions pattern

**Contracts:**
- `VulnerableBank`: Allows reentrancy in `withdraw()` function
- `ReentrancyAttacker`: Example exploit contract demonstrating the attack

**Key Vulnerable Functions:**
- `VulnerableBank.withdraw()` (Reentrancy.sol:18)

---

### 2. IntegerOverflow.sol
**Primary Vulnerabilities:**
- **Integer Overflow/Underflow**: Arithmetic operations can overflow or underflow in Solidity < 0.8.0
- **Unchecked Block Abuse**: Using `unchecked` blocks in Solidity 0.8.0+ bypasses automatic overflow protection
- **Batch Transfer Overflow**: Multiplication overflow in batch operations

**Contracts:**
- `VulnerableToken`: Demonstrates overflow vulnerabilities in older Solidity versions
- `UncheckedOverflow`: Shows how unchecked blocks can introduce vulnerabilities in Solidity 0.8.0+

**Key Vulnerable Functions:**
- `VulnerableToken.batchTransfer()` (IntegerOverflow.sol:31)
- `VulnerableToken.withdrawReward()` (IntegerOverflow.sol:41)
- `UncheckedOverflow.unsafeMultiply()` (IntegerOverflow.sol:58)

---

### 3. AccessControl.sol
**Primary Vulnerabilities:**
- **Missing Access Control**: Critical functions lack proper authorization checks
- **tx.origin Authentication**: Using `tx.origin` instead of `msg.sender` enables phishing attacks
- **Unprotected Initialization**: Initialization functions can be called by anyone
- **Unrestricted Delegatecall**: Arbitrary code execution through delegatecall

**Contracts:**
- `VulnerableWallet`: Multiple access control issues
- `PhishingAttacker`: Exploits tx.origin vulnerability
- `VulnerableAuction`: Missing access control on critical functions

**Key Vulnerable Functions:**
- `VulnerableWallet.changeOwner()` (AccessControl.sol:17)
- `VulnerableWallet.withdrawAll()` (AccessControl.sol:23)
- `VulnerableWallet.execute()` (AccessControl.sol:37)
- `VulnerableAuction.endAuction()` (AccessControl.sol:75)

---

### 4. UncheckedCall.sol
**Primary Vulnerabilities:**
- **Unchecked Return Values**: Low-level calls (.call, .send) return values are not checked
- **Silent Failures**: Failed external calls don't revert the transaction
- **State Inconsistency**: State changes persist even when transfers fail

**Contracts:**
- `VulnerablePayment`: Doesn't check return values of external calls
- `VulnerableIntegration`: Assumes external contract calls always succeed
- `MaliciousReceiver`: Exploits unchecked call vulnerability

**Key Vulnerable Functions:**
- `VulnerablePayment.withdrawUnchecked()` (UncheckedCall.sol:20)
- `VulnerablePayment.withdrawWithSend()` (UncheckedCall.sol:29)
- `VulnerablePayment.batchPayout()` (UncheckedCall.sol:38)

---

### 5. TimestampDependence.sol
**Primary Vulnerabilities:**
- **Timestamp Manipulation**: Using `block.timestamp` for critical logic (miners can manipulate ±15 seconds)
- **Weak Randomness**: Generating random numbers from predictable block variables
- **Time-Based Access Control**: Security mechanisms relying on block.timestamp

**Contracts:**
- `VulnerableLottery`: Uses block.timestamp for random winner selection
- `VulnerableTimelock`: Relies on block.timestamp for fund locking
- `VulnerableRandomness`: Generates predictable random numbers

**Key Vulnerable Functions:**
- `VulnerableLottery.drawWinner()` (TimestampDependence.sol:26)
- `VulnerableTimelock.withdraw()` (TimestampDependence.sol:49)
- `VulnerableRandomness.generateRandomNumber()` (TimestampDependence.sol:74)

---

### 6. DenialOfService.sol
**Primary Vulnerabilities:**
- **DoS by Refusing Payment**: Malicious contracts reject payments, blocking operations
- **Unbounded Loops**: Gas limit exceeded by iterating over large arrays
- **External Call DoS**: One failing external call blocks entire operation
- **Block Gas Limit**: Operations that grow unbounded can exceed block gas limit

**Contracts:**
- `VulnerableAuction`: Refund mechanism can be blocked by refusing payment
- `VulnerableDistributor`: Unbounded loop can exceed gas limit
- `VulnerableRegistry`: Array operations can exceed block gas limit
- `MaliciousBidder`: Exploits auction by refusing refunds

**Key Vulnerable Functions:**
- `VulnerableAuction.bid()` (DenialOfService.sol:14)
- `VulnerableDistributor.distributeRewards()` (DenialOfService.sol:35)
- `VulnerablePaymentSplitter.splitPayment()` (DenialOfService.sol:84)

---

### 7. FrontRunning.sol
**Primary Vulnerabilities:**
- **Transaction Ordering Dependence**: Transaction order affects outcomes
- **Mempool Visibility**: Solutions and parameters visible before confirmation
- **Front-Running**: Attackers can see and front-run profitable transactions
- **ERC20 Approve Race Condition**: Changing allowances can be exploited

**Contracts:**
- `VulnerablePuzzle`: Solutions visible in mempool before confirmation
- `VulnerableDEX`: Price manipulation through transaction ordering
- `VulnerableICO`: Price changes can front-run user purchases
- `VulnerableERC20`: Approve/transferFrom race condition

**Key Vulnerable Functions:**
- `VulnerablePuzzle.submitSolution()` (FrontRunning.sol:21)
- `VulnerableDEX.swapAforB()` (FrontRunning.sol:48)
- `VulnerableERC20.approve()` (FrontRunning.sol:102)

---

### 8. DelegateCall.sol
**Primary Vulnerabilities:**
- **Unprotected Delegatecall**: Anyone can execute delegatecall with arbitrary data
- **Storage Collision**: Different storage layouts cause variable corruption
- **Selfdestruct via Delegatecall**: Contract can be destroyed through delegatecall
- **Uninitialized Proxy**: Proxy contracts without proper initialization

**Contracts:**
- `VulnerableProxy`: Unprotected delegatecall to any contract
- `MaliciousImplementation`: Exploits delegatecall to change owner
- `VulnerableWallet`: Storage collision vulnerability
- `MaliciousLibrary`: Different storage layout corrupts wallet state

**Key Vulnerable Functions:**
- `VulnerableProxy.forward()` (DelegateCall.sol:19)
- `VulnerableProxy.execute()` (DelegateCall.sol:26)
- `VulnerableWallet.withdraw()` (DelegateCall.sol:61)

---

### 9. SignatureReplay.sol
**Primary Vulnerabilities:**
- **Signature Replay**: Valid signatures can be reused multiple times
- **Cross-Contract Replay**: Signatures work across different contract instances
- **Missing Nonce**: No replay protection mechanism
- **Signature Malleability**: ECDSA signatures can be modified while remaining valid
- **Missing Chain ID**: Signatures can be replayed across different blockchain networks

**Contracts:**
- `VulnerableMetaTransaction`: No nonce or replay protection
- `VulnerableVoucherSystem`: Signatures work across contract copies
- `VulnerableSignatureChecker`: Vulnerable to signature malleability
- `VulnerableCrossChain`: Missing chain ID allows cross-chain replay

**Key Vulnerable Functions:**
- `VulnerableMetaTransaction.metaTransfer()` (SignatureReplay.sol:20)
- `VulnerableVoucherSystem.redeemVoucher()` (SignatureReplay.sol:55)
- `VulnerableSignatureChecker.executeWithSignature()` (SignatureReplay.sol:90)

---

### 10. ShortAddress.sol
**Primary Vulnerabilities:**
- **Short Address Attack**: Insufficient address length validation
- **Missing Input Validation**: No zero-address checks
- **Array Length Mismatch**: Assumes arrays have matching lengths
- **Missing Parameter Validation**: No validation on critical parameters

**Contracts:**
- `VulnerableToken`: No address length or zero-address validation
- `VulnerableExchange`: Missing validation on addresses and arrays
- `VulnerableMultisig`: No validation on signature array
- `VulnerableAirdrop`: No parameter validation for airdrops

**Key Vulnerable Functions:**
- `VulnerableToken.transfer()` (ShortAddress.sol:25)
- `VulnerableExchange.batchDeposit()` (ShortAddress.sol:55)
- `VulnerableAirdrop.claimTokens()` (ShortAddress.sol:118)

---

### 11. UninitializedStorage.sol
**Primary Vulnerabilities:**
- **Uninitialized Storage Pointers**: Storage pointers default to slot 0 in older Solidity versions
- **Storage Collision**: Improper struct usage overwrites critical state variables
- **Delete Mapping Caveat**: Deleting structs with mappings doesn't clear the mappings
- **Array Deletion Gaps**: Deleting array elements creates gaps rather than removing items
- **Default Visibility**: Missing visibility modifiers can expose sensitive functions

**Contracts:**
- `VulnerableStorage`: Uninitialized storage pointer issues
- `VulnerableArray`: Storage pointer problems in loops
- `VulnerableMapping`: Mapping deletion doesn't clear nested mappings
- `VulnerableArrayDeletion`: Array deletion leaves gaps

**Key Vulnerable Functions:**
- `VulnerableStorage.addUser()` (UninitializedStorage.sol:29)
- `VulnerableMapping.deleteUser()` (UninitializedStorage.sol:93)
- `VulnerableArrayDeletion.deleteValue()` (UninitializedStorage.sol:136)

---

## Testing and Educational Use

### Recommended Tools for Testing
- **Remix IDE**: Browser-based Solidity IDE for quick testing
- **Hardhat**: Ethereum development environment for comprehensive testing
- **Foundry**: Fast Solidity testing framework
- **Slither**: Static analysis tool to detect vulnerabilities
- **Mythril**: Security analysis tool for EVM bytecode
- **Echidna**: Fuzzing tool for Ethereum smart contracts

### How to Use These Examples

1. **Study the Code**: Read the contracts and understand why they're vulnerable
2. **Identify Vulnerabilities**: Try to spot the issues before reading the comments
3. **Write Exploits**: Create attacker contracts to exploit the vulnerabilities
4. **Fix the Issues**: Modify the contracts to eliminate the vulnerabilities
5. **Test Thoroughly**: Verify that fixes actually prevent the exploits

### Deployment Warning

**IMPORTANT**: These contracts are intentionally vulnerable and should NEVER be deployed to:
- Ethereum Mainnet
- Any production network
- Networks with real financial value

Only use these contracts on:
- Local test networks (Hardhat, Ganache)
- Public testnets (Goerli, Sepolia) for educational purposes
- Private test environments

## Prevention Best Practices

### General Security Guidelines

1. **Follow Checks-Effects-Interactions Pattern**: Update state before external calls
2. **Use OpenZeppelin Contracts**: Leverage audited, community-tested libraries
3. **Implement Access Control**: Use modifiers like `onlyOwner`, role-based access
4. **Validate Inputs**: Check for zero addresses, array lengths, parameter ranges
5. **Use ReentrancyGuard**: Protect functions from reentrancy attacks
6. **Avoid Predictable Randomness**: Use oracles like Chainlink VRF for randomness
7. **Check Return Values**: Always verify success of external calls
8. **Use SafeMath (pre-0.8.0)**: Prevent integer overflow/underflow
9. **Limit Loop Iterations**: Avoid unbounded loops that can exceed gas limits
10. **Implement Circuit Breakers**: Add pause functionality for emergencies
11. **Use Latest Solidity Version**: Benefit from built-in security improvements
12. **Get Professional Audits**: Have contracts reviewed by security experts

### Secure Coding Patterns

```solidity
// Good: Checks-Effects-Interactions pattern
function withdraw(uint256 amount) public {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    balances[msg.sender] -= amount;  // Effect: Update state first
    (bool success, ) = msg.sender.call{value: amount}("");  // Interaction: External call last
    require(success, "Transfer failed");
}

// Good: ReentrancyGuard
contract SecureBank is ReentrancyGuard {
    function withdraw() public nonReentrant {
        // Protected from reentrancy
    }
}

// Good: Access control
modifier onlyOwner() {
    require(msg.sender == owner, "Not owner");
    _;
}

// Good: Input validation
function transfer(address to, uint256 amount) public {
    require(to != address(0), "Zero address");
    require(amount > 0, "Invalid amount");
    // ... rest of function
}
```

## References and Learning Resources

- [Solidity Documentation](https://docs.soliditylang.org/)
- [OpenZeppelin Contracts](https://docs.openzeppelin.com/contracts/)
- [ConsenSys Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [SWC Registry](https://swcregistry.io/) - Smart Contract Weakness Classification
- [Ethereum Security Guides](https://ethereum.org/en/developers/docs/smart-contracts/security/)
- [Secureum Bootcamp](https://secureum.substack.com/)

## License

MIT License - Use for educational purposes only.

## Disclaimer

These contracts are provided for educational purposes only. The authors are not responsible for any misuse of these examples. Always conduct thorough security audits before deploying smart contracts to production environments.
