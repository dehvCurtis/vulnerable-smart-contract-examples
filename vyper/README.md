# Vulnerable Vyper Smart Contract Examples

This repository contains intentionally vulnerable Vyper smart contracts for educational and security testing purposes. **DO NOT deploy these contracts to production networks.**

## About Vyper

Vyper is a pythonic smart contract language that aims to be more secure than Solidity by design. It achieves this through:
- No inline assembly
- No function overloading
- No recursive calling
- No infinite loops
- Bounds and overflow checking by default

However, Vyper contracts can still have vulnerabilities. This collection demonstrates common security issues that can occur even with Vyper's safety features.

## Purpose

These contracts demonstrate vulnerabilities specific to Vyper development to help developers:
- Understand security risks unique to Vyper
- Learn differences between Solidity and Vyper vulnerabilities
- Practice secure Vyper coding patterns
- Develop security testing skills for Vyper contracts

## Vulnerability Inventory

### 1. reentrancy.vy
**Primary Vulnerabilities:**
- **Reentrancy Attack**: Vyper does NOT automatically prevent reentrancy; external calls before state updates are dangerous
- **State Update After External Call**: Using `send()` before updating balances violates Checks-Effects-Interactions
- **Missing Reentrancy Guard**: No protection mechanism against recursive calls

**Key Vulnerable Functions:**
- `withdraw()` (reentrancy.vy:18) - External call before state update

**Vyper-Specific Notes:**
- Unlike some assumptions, Vyper does not prevent reentrancy by default
- The `@nonreentrant` decorator must be explicitly used
- `send()` can trigger fallback functions that re-enter

**How to Fix:**
```python
@external
@nonreentrant("lock")
def withdraw():
    amount: uint256 = self.balances[msg.sender]
    assert amount > 0
    self.balances[msg.sender] = 0  # Update state first
    send(msg.sender, amount)
```

---

### 2. access_control.vy
**Primary Vulnerabilities:**
- **Missing Access Control**: Critical functions lack authorization checks
- **tx.origin Authentication**: Using `tx.origin` enables phishing attacks
- **Unprotected Initialization**: Multiple or unauthorized initialization possible
- **Missing State Validation**: No checks on current state before transitions

**Key Vulnerable Functions:**
- `change_owner()` (access_control.vy:18) - No access control
- `withdraw_all()` (access_control.vy:26) - tx.origin vulnerability
- `initialize()` (access_control.vy:33) - No initialization guard
- `emergency_withdraw()` (access_control.vy:49) - No access control

**Vyper-Specific Notes:**
- Vyper doesn't have modifiers like Solidity; use internal functions for checks
- Must explicitly implement access control patterns
- No built-in owner/admin patterns

**How to Fix:**
```python
@internal
def _only_owner():
    assert msg.sender == self.owner, "Not owner"

@external
def change_owner(new_owner: address):
    self._only_owner()
    self.owner = new_owner
```

---

### 3. raw_call.vy
**Primary Vulnerabilities:**
- **Unchecked raw_call**: Return values from `raw_call` not verified
- **User-Controlled Targets**: Arbitrary contract calls with user-supplied addresses
- **Ignoring Failures**: Call failures don't revert transactions
- **Missing Gas Limits**: User-controlled gas amounts can cause issues

**Key Vulnerable Functions:**
- `withdraw_unchecked()` (raw_call.vy:24) - Unchecked raw_call return value
- `withdraw_ignored_return()` (raw_call.vy:35) - State updated before checking success
- `execute_arbitrary()` (raw_call.vy:49) - User controls target and data
- `batch_transfer()` (raw_call.vy:58) - Silent failures in loop

**Vyper-Specific Notes:**
- `raw_call()` is Vyper's low-level call mechanism
- Must explicitly check return values
- Different from Solidity's `.call()` syntax but same dangers

**How to Fix:**
```python
@external
def withdraw_secure(recipient: address, amount: uint256):
    assert self.balances[msg.sender] >= amount
    self.balances[msg.sender] -= amount
    success: bool = raw_call(recipient, b"", value=amount)
    assert success, "Transfer failed"
```

---

### 4. integer_issues.vy
**Primary Vulnerabilities:**
- **Division Rounding**: Integer division truncates, causing precision loss
- **Order of Operations**: Wrong operation order loses precision
- **Percentage Calculation Errors**: Dividing before multiplying loses accuracy
- **Compound Interest Failures**: Integer arithmetic can't handle compound calculations

**Key Vulnerable Functions:**
- `division_rounding()` (integer_issues.vy:28) - Truncation loses funds
- `distribute_equally()` (integer_issues.vy:37) - Rounding locks funds
- `percentage_calculation()` (integer_issues.vy:52) - Wrong operation order
- `fee_calculation()` (integer_issues.vy:73) - Multiple precision loss points

**Vyper-Specific Notes:**
- Vyper has built-in overflow protection (unlike Solidity pre-0.8.0)
- However, rounding and precision issues still exist
- No native decimal type; must use fixed-point arithmetic patterns
- Consider using libraries or multiplying by powers of 10

**How to Fix:**
```python
# Multiply before dividing to maintain precision
def percentage_calculation(amount: uint256, percentage: uint256) -> uint256:
    assert percentage <= 100
    return (amount * percentage) / 100  # Correct order

# Or use basis points for better precision
def calculate_with_basis_points(amount: uint256, bps: uint256) -> uint256:
    return (amount * bps) / 10000
```

---

### 5. timestamp_dependence.vy
**Primary Vulnerabilities:**
- **Timestamp Manipulation**: `block.timestamp` can be manipulated by miners (±15 seconds)
- **Weak Randomness**: Using block variables for random number generation
- **Predictable Outcomes**: All block data is known before transaction confirmation
- **Time-Based Access Control**: Security mechanisms relying on timestamps

**Key Vulnerable Functions:**
- `draw_winner()` (timestamp_dependence.vy:30) - Timestamp-based randomness
- `withdraw_locked()` (timestamp_dependence.vy:63) - Timestamp for security
- `generate_random()` (timestamp_dependence.vy:96) - Predictable random numbers
- `play_game()` (timestamp_dependence.vy:114) - Predictable game outcome

**Vyper-Specific Notes:**
- Vyper exposes `block.timestamp`, `block.difficulty`, `block.number`
- All equally manipulable or predictable
- Use Chainlink VRF or commit-reveal for randomness
- Never use block variables for security-critical randomness

**How to Fix:**
```python
# Use commit-reveal pattern
commits: public(HashMap[address, bytes32])

@external
def commit(commitment: bytes32):
    self.commits[msg.sender] = commitment

@external
def reveal(value: uint256, salt: bytes32):
    assert keccak256(concat(convert(value, bytes32), salt)) == self.commits[msg.sender]
    # Process reveal...
```

---

### 6. denial_of_service.vy
**Primary Vulnerabilities:**
- **DoS by Refusing Payment**: Malicious contracts reject payments, blocking operations
- **Unbounded Loops**: Iteration over growing arrays can exceed gas limits
- **Block Gas Limit**: Operations that grow with state can become impossible
- **External Call Dependencies**: One failing call blocks entire operation

**Key Vulnerable Functions:**
- `bid()` (denial_of_service.vy:14) - Refund can be blocked
- `distribute_rewards()` (denial_of_service.vy:31) - Unbounded loops
- `reset()` (denial_of_service.vy:55) - Block gas limit issue
- `split_payment()` (denial_of_service.vy:87) - One recipient blocks all

**Vyper-Specific Notes:**
- Vyper's `send()` doesn't revert on failure (returns False instead)
- Must explicitly check return value
- Vyper's `for` loops have maximum iteration limits
- DynamicArray has size limits but can still cause gas issues

**How to Fix:**
```python
# Use pull pattern instead of push
pending_withdrawals: public(HashMap[address, uint256])

@external
@payable
def bid():
    if self.current_leader != empty(address):
        # Don't send directly, let them withdraw
        self.pending_withdrawals[self.current_leader] += self.current_bid
    self.current_leader = msg.sender
    self.current_bid = msg.value

@external
def withdraw():
    amount: uint256 = self.pending_withdrawals[msg.sender]
    self.pending_withdrawals[msg.sender] = 0
    send(msg.sender, amount)
```

---

### 7. front_running.vy
**Primary Vulnerabilities:**
- **Mempool Visibility**: Transaction parameters visible before confirmation
- **Transaction Ordering**: Higher gas price = earlier execution
- **Price Manipulation**: Front-runners can manipulate prices before victim's transaction
- **Approve Race Condition**: Changing approvals can be front-run

**Key Vulnerable Functions:**
- `submit_solution()` (front_running.vy:17) - Solution visible in mempool
- `swap_a_for_b()` (front_running.vy:47) - Price manipulation vulnerability
- `buy_tokens()` (front_running.vy:84) - Price can change before execution
- `approve()` (front_running.vy:97) - Approve race condition

**Vyper-Specific Notes:**
- Front-running is blockchain-level issue, not language-specific
- Same vulnerabilities as Solidity
- Commit-reveal pattern works well in Vyper
- Consider using `increase_allowance()` / `decrease_allowance()` patterns

**How to Fix:**
```python
# Commit-reveal pattern
commits: public(HashMap[address, bytes32])

@external
def commit(commitment: bytes32):
    self.commits[msg.sender] = commitment
    # Must wait at least 1 block before revealing

@external
def reveal(solution: String[100], salt: String[32]):
    commitment: bytes32 = keccak256(concat(solution, salt))
    assert self.commits[msg.sender] == commitment
    # Process solution...

# For DEX: Use deadline and slippage protection
@external
def swap_with_protection(
    token_a_amount: uint256,
    min_token_b: uint256,
    deadline: uint256
):
    assert block.timestamp <= deadline, "Expired"
    token_b_amount: uint256 = self.get_swap_amount(token_a_amount)
    assert token_b_amount >= min_token_b, "Slippage too high"
    # Execute swap...
```

---

### 8. input_validation.vy
**Primary Vulnerabilities:**
- **Missing Zero Address Checks**: Functions accept zero address
- **Array Length Mismatch**: Assumes arrays have matching lengths
- **Missing Bounds Checks**: No validation on numeric parameters
- **No Duplicate Checking**: Same value can be added multiple times

**Key Vulnerable Functions:**
- `deposit()` (input_validation.vy:14) - No token address validation
- `transfer()` (input_validation.vy:31) - No zero address check
- `batch_transfer()` (input_validation.vy:43) - Array length mismatch
- `set_fee()` (input_validation.vy:72) - No upper bound check

**Vyper-Specific Notes:**
- Vyper has `empty(address)` to check for zero address
- Array bounds checked automatically but logic errors still possible
- Must explicitly validate all inputs
- Type safety helps but doesn't catch all issues

**How to Fix:**
```python
@external
def transfer(to: address, amount: uint256):
    assert to != empty(address), "Zero address"
    assert to != self, "Cannot transfer to contract"
    assert amount > 0, "Invalid amount"
    assert self.balances[msg.sender] >= amount, "Insufficient balance"

    self.balances[msg.sender] -= amount
    self.balances[to] += amount

@external
def batch_transfer(recipients: DynArray[address, 100], amounts: DynArray[uint256, 100]):
    assert len(recipients) == len(amounts), "Length mismatch"
    assert len(recipients) > 0, "Empty arrays"

    for i in range(100):
        if i >= len(recipients):
            break
        assert recipients[i] != empty(address), "Zero address"
        # Process transfer...
```

---

### 9. external_calls.vy
**Primary Vulnerabilities:**
- **Unchecked Transfer Returns**: ERC20 transfers can fail silently
- **Untrusted Oracle Data**: External price feeds not validated
- **Missing Contract Validation**: No checks if address is actually a contract
- **Reentrancy via Callbacks**: External calls allow re-entrance

**Key Vulnerable Functions:**
- `deposit_token()` (external_calls.vy:30) - Doesn't check transferFrom return
- `withdraw_token()` (external_calls.vy:39) - Doesn't verify transfer success
- `get_token_price()` (external_calls.vy:52) - Trusts oracle without validation
- `execute_callback()` (external_calls.vy:102) - Callback reentrancy vulnerability

**Vyper-Specific Notes:**
- Vyper interfaces assume correct implementation
- Must use `assert` on return values from external calls
- No automatic checks on interface calls
- Consider using `@nonreentrant` decorator

**How to Fix:**
```python
@external
def deposit_token_secure(token: address, amount: uint256):
    # Check return value explicitly
    success: bool = ERC20(token).transferFrom(msg.sender, self, amount)
    assert success, "Transfer failed"
    self.balances[msg.sender] += amount

@external
@nonreentrant("lock")
def execute_callback(target: address, data: Bytes[1024]):
    assert target != self, "Cannot callback to self"
    response: Bytes[32] = raw_call(target, data, max_outsize=32)
```

---

### 10. uninitialized_storage.vy
**Primary Vulnerabilities:**
- **Incomplete Initialization**: Constructor doesn't initialize all state
- **Multiple Initialization**: Initialization can be called multiple times
- **Default Value Confusion**: Relying on default zero values incorrectly
- **State Transition Errors**: Improper state machine implementation

**Key Vulnerable Functions:**
- `initialize()` (uninitialized_storage.vy:24) - Can be called multiple times
- `set_config()` (uninitialized_storage.vy:94) - Partial initialization
- `check_amount()` (uninitialized_storage.vy:102) - Uses uninitialized max_amount
- `activate()` (uninitialized_storage.vy:117) - No state validation

**Vyper-Specific Notes:**
- Vyper structs must have all fields initialized
- HashMap values default to zero
- Enums start at 0 by default
- Use `__init__` for initialization, not separate functions

**How to Fix:**
```python
@external
def __init__():
    # Initialize everything in constructor
    self.owner = msg.sender
    self.initialized = True
    self.total_supply = 1000000
    self.config = Config({
        min_amount: 100,
        max_amount: 1000000,
        fee_percentage: 100,
        enabled: True
    })

# If you must have separate initialization:
@external
def initialize(initial_owner: address):
    assert not self.initialized, "Already initialized"
    assert msg.sender == self.owner, "Not owner"
    assert initial_owner != empty(address), "Invalid owner"

    self.owner = initial_owner
    self.initialized = True
```

---

## Testing and Educational Use

### Recommended Tools for Vyper Testing
- **Ape Framework**: Modern Vyper development framework
- **Brownie**: Python-based development framework for Vyper
- **Foundry**: Can compile Vyper with vyper plugin
- **Titanoboa**: Vyper interpreter for testing
- **Slither**: Static analysis (supports Vyper)
- **Mythril**: Security analysis for EVM bytecode

### Compiling Vyper Contracts

```bash
# Install Vyper
pip install vyper

# Compile a contract
vyper contract.vy

# Compile with optimization
vyper -f bytecode contract.vy
```

### How to Use These Examples

1. **Study the Code**: Understand why each contract is vulnerable
2. **Compare with Solidity**: Note differences in vulnerability patterns
3. **Write Exploits**: Create attacker contracts to demonstrate vulnerabilities
4. **Fix the Issues**: Rewrite contracts securely
5. **Test Thoroughly**: Verify fixes prevent exploits

### Deployment Warning

**CRITICAL**: These contracts are intentionally vulnerable and should NEVER be deployed to:
- Ethereum Mainnet
- Any production network
- Networks with real financial value

Only use these contracts on:
- Local test networks (Hardhat, Ganache, Anvil)
- Public testnets (Goerli, Sepolia) for educational purposes
- Private test environments

## Prevention Best Practices

### Vyper-Specific Security Guidelines

1. **Use @nonreentrant Decorator**: Always protect functions with external calls
```python
@external
@nonreentrant("lock")
def withdraw():
    # Safe from reentrancy
```

2. **Implement Access Control Patterns**: Use internal helper functions
```python
@internal
def _only_owner():
    assert msg.sender == self.owner
```

3. **Validate All Inputs**: Check addresses, bounds, array lengths
```python
assert to != empty(address)
assert amount > 0
assert len(recipients) == len(amounts)
```

4. **Check External Call Returns**: Always verify success
```python
success: bool = raw_call(target, data, value=amount)
assert success, "Call failed"
```

5. **Avoid Block Variables for Randomness**: Use Chainlink VRF or commit-reveal
```python
# BAD
random: uint256 = block.timestamp % 100

# GOOD - Use Chainlink VRF or commit-reveal
```

6. **Use Pull Over Push Pattern**: Let users withdraw instead of sending
```python
pending: public(HashMap[address, uint256])

@external
def withdraw():
    amount: uint256 = self.pending[msg.sender]
    self.pending[msg.sender] = 0
    send(msg.sender, amount)
```

7. **Initialize in Constructor**: Use `__init__` for initialization
```python
@external
def __init__(owner: address):
    self.owner = owner
    self.initialized = True
```

8. **Validate State Transitions**: Check current state before transitions
```python
@external
def activate():
    assert self.state == State.PENDING, "Invalid state"
    self.state = State.ACTIVE
```

9. **Be Careful with Division**: Multiply before dividing
```python
# GOOD
result: uint256 = (amount * percentage) / 100

# BAD - loses precision
result: uint256 = (amount / 100) * percentage
```

10. **Use DynArray Carefully**: Be aware of gas costs with large arrays
```python
# Consider pagination or pull patterns for large datasets
```

### Secure Coding Patterns

```python
# @version ^0.3.0

# Good: Comprehensive contract template
owner: public(address)
paused: public(bool)
reentrancy_lock: bool

@external
def __init__():
    self.owner = msg.sender
    self.paused = False

@internal
def _only_owner():
    assert msg.sender == self.owner, "Not owner"

@internal
def _when_not_paused():
    assert not self.paused, "Paused"

@external
def pause():
    self._only_owner()
    self.paused = True

@external
@nonreentrant("lock")
def secure_withdraw(amount: uint256):
    self._when_not_paused()
    assert amount > 0, "Invalid amount"
    assert self.balances[msg.sender] >= amount, "Insufficient balance"

    # Checks-Effects-Interactions
    self.balances[msg.sender] -= amount

    success: bool = raw_call(msg.sender, b"", value=amount)
    assert success, "Transfer failed"
```

## Vyper vs Solidity Security Differences

### Vulnerabilities Vyper Prevents:
- **No Integer Overflow** (built-in checks, unlike Solidity < 0.8.0)
- **No Delegatecall** (removed entirely from Vyper)
- **No Inline Assembly** (reduces complexity and bugs)
- **No Modifier Reentrancy** (simpler to reason about)
- **Bounds Checking** (automatic array bounds checks)

### Vulnerabilities Still Present:
- **Reentrancy** (must use `@nonreentrant`)
- **Access Control** (must implement explicitly)
- **External Call Failures** (must check returns)
- **Front-Running** (blockchain-level issue)
- **Timestamp Dependence** (block variable manipulation)
- **Integer Precision Loss** (rounding, division truncation)

## References and Learning Resources

- [Vyper Documentation](https://docs.vyperlang.org/)
- [Vyper by Example](https://vyper-by-example.org/)
- [Ape Framework](https://docs.apeworx.io/)
- [Titanoboa - Vyper Interpreter](https://github.com/vyperlang/titanoboa)
- [Smart Contract Security Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [SWC Registry](https://swcregistry.io/)
- [Vyper Security Considerations](https://docs.vyperlang.org/en/stable/security-considerations.html)

## License

MIT License - Use for educational purposes only.

## Disclaimer

These contracts are provided for educational and security research purposes only. The authors are not responsible for any misuse of these examples. Never deploy vulnerable contracts to production environments. Always conduct thorough security audits before deploying smart contracts that handle real value.
