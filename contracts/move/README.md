# Vulnerable Move Smart Contract Examples

This repository contains intentionally vulnerable Move modules for educational and security testing purposes. **DO NOT deploy these modules to production networks.**

## About Move

Move is a resource-oriented programming language originally developed for the Diem blockchain (formerly Libra) and now used by:
- **Aptos**: A Layer 1 blockchain using Move
- **Sui**: A Layer 1 blockchain with modified Move dialect
- **Other blockchains**: Various projects adopting Move

### Move's Safety Features

Move was designed with security in mind:
- **Resource Safety**: Resources cannot be copied or dropped
- **Linear Types**: Ensures resources are properly handled
- **No Reentrancy**: By design, reentrancy is not possible
- **Strong Type System**: Compile-time type checking prevents many bugs
- **Formal Verification**: Designed to be formally verifiable
- **No Inline Assembly**: Eliminates low-level manipulation risks

### However, Vulnerabilities Still Exist

Despite Move's safety features, vulnerabilities can occur through:
- Logic errors in access control
- Missing authorization checks
- Improper resource handling
- Integer arithmetic issues
- Timestamp manipulation
- Uninitialized state usage

## Purpose

These modules demonstrate Move-specific security vulnerabilities to help developers:
- Understand security risks in Move development
- Learn differences from EVM security models
- Practice secure coding patterns for Move
- Develop security auditing skills for Move programs

## Vulnerability Inventory

### 1. missing_signer_check.move
**Primary Vulnerabilities:**
- **Missing Signer Verification**: Functions fail to verify caller is authorized
- **Ownership Bypass**: Anyone can operate on others' resources
- **Unauthorized Withdrawals**: Funds can be stolen without proper authorization

**Key Vulnerable Functions:**
- `withdraw()` (missing_signer_check.move:33) - No verification caller owns vault
- `change_owner()` (missing_signer_check.move:49) - No ownership check before transfer
- `deposit()` (missing_signer_check.move:25) - Weak authorization logic

**Vulnerability Details:**
```move
// VULNERABLE: No check that caller owns the vault
public entry fun withdraw(account: &signer, vault_owner: address, amount: u64)
acquires Vault {
    let vault = borrow_global_mut<Vault>(vault_owner);
    vault.balance = vault.balance - amount;
    // Anyone can drain anyone's vault!
}

// SECURE: Verify ownership
public entry fun withdraw_secure(account: &signer, amount: u64)
acquires Vault {
    let account_addr = signer::address_of(account);
    let vault = borrow_global_mut<Vault>(account_addr);
    assert!(vault.owner == account_addr, ERROR_NOT_OWNER);
    // Now safe
}
```

**Exploit Scenario:**
1. Alice creates vault with 100 APT
2. Bob calls `withdraw(bob_signer, alice_address, 100)`
3. No check that Bob owns Alice's vault
4. Alice's funds transferred to Bob

**Impact:** Complete fund theft, unauthorized state changes

---

### 2. missing_capability_check.move
**Primary Vulnerabilities:**
- **Missing Capability Verification**: Admin capabilities not properly checked
- **Weak Authorization**: Checks existence but not ownership
- **Privilege Escalation**: Unauthorized users can perform admin operations

**Key Vulnerable Functions:**
- `add_user_vulnerable()` (missing_capability_check.move:34) - No capability check
- `privileged_operation_vulnerable()` (missing_capability_check.move:70) - Weak capability validation
- `change_admin_vulnerable()` (missing_capability_check.move:55) - No authorization at all

**Move's Capability Pattern:**
```move
// Define capability
struct AdminCap has key, store {
    admin_address: address,
}

// SECURE: Require capability as parameter
public fun privileged_op(_admin_cap: &AdminCap) {
    // By requiring AdminCap, caller MUST have it
    // This is the most secure pattern
}

// SECURE: Check capability ownership
public entry fun privileged_op_secure(admin: &signer)
acquires AdminCap {
    let admin_addr = signer::address_of(admin);
    assert!(exists<AdminCap>(admin_addr), ERROR_NOT_ADMIN);
    let cap = borrow_global<AdminCap>(admin_addr);
    assert!(cap.admin_address == admin_addr, ERROR_INVALID_CAP);
}
```

**Exploit Scenario:**
1. Admin initializes system with AdminCap
2. Attacker calls admin function without capability
3. Function doesn't check for capability
4. Attacker gains admin privileges

**Impact:** Complete protocol takeover, unauthorized admin actions

---

### 3. integer_overflow.move
**Primary Vulnerabilities:**
- **Overflow DoS**: Large values cause transaction aborts
- **Underflow Errors**: Insufficient balance checks cause failures
- **Precision Loss**: Integer division truncates, losing value
- **Multiplication Overflow**: Large calculations overflow

**Key Vulnerable Functions:**
- `deposit_vulnerable()` (integer_overflow.move:29) - Overflow causes abort
- `calculate_reward_vulnerable()` (integer_overflow.move:51) - Multiplication overflow
- `distribute_reward_vulnerable()` (integer_overflow.move:61) - Division loses precision
- `apply_fee_vulnerable()` (integer_overflow.move:73) - Multiple overflow points

**Move's Overflow Behavior:**
```move
// Move checks overflow at runtime:
// - Addition, subtraction, multiplication checked
// - Overflow causes transaction to ABORT
// - But this can be exploited for DoS

const MAX_U64: u64 = 18446744073709551615;

// VULNERABLE: Overflow causes abort
balance.amount = balance.amount + amount;  // Aborts if overflow

// SECURE: Check before operation
assert!(MAX_U64 - balance.amount >= amount, E_OVERFLOW);
balance.amount = balance.amount + amount;

// PRECISION LOSS:
// WRONG: Divide first
let user_share = user_stake / total_stake;  // = 0 if user_stake < total_stake
let reward = total_pool * user_share;       // = 0

// CORRECT: Multiply first
let reward = (total_pool * user_stake) / total_stake;
```

**Exploit Scenarios:**
1. **DoS via Overflow**: User has balance near MAX_U64, deposit causes overflow and abort
2. **Precision Loss**: User stakes 10 in pool of 1M, gets 0 reward due to rounding
3. **Multiplication Overflow**: Large balance * multiplier overflows, blocking withdrawals

**Impact:** DoS, loss of rewards, stuck funds

---

### 4. timestamp_dependence.move
**Primary Vulnerabilities:**
- **Timestamp Manipulation**: Validators can manipulate timestamps
- **Predictable Randomness**: Using timestamp for random selection
- **Weak Time Locks**: Timestamp-based access control bypassable
- **Auction Manipulation**: Timestamp checks allow unfair advantages

**Key Vulnerable Functions:**
- `draw_winner()` (timestamp_dependence.move:32) - Timestamp-based randomness
- `withdraw_timelock()` (timestamp_dependence.move:50) - Timestamp security
- `place_bid()` (timestamp_dependence.move:75) - Manipulable deadline
- `generate_random_vulnerable()` (timestamp_dependence.move:100) - Predictable random

**Timestamp Manipulation:**
```move
// VULNERABLE: Timestamp for randomness
let random_index = (timestamp::now_seconds() % num_participants) as u64;
let winner = *vector::borrow(&lottery.participants, random_index);
// Validator can manipulate timestamp to influence winner!

// VULNERABLE: Timestamp for security
assert!(current_time >= timelock.locked_until, ERROR);
// Validator can advance timestamp to bypass lock

// BETTER: Use Aptos Randomness API or commit-reveal
```

**Exploit Scenarios:**
1. **Lottery Manipulation**: Validator adjusts timestamp to make themselves win
2. **Timelock Bypass**: User who is validator advances timestamp to withdraw early
3. **Auction Extension**: Validator moves timestamp back to keep auction open

**Impact:** Unfair advantages, security bypass, loss of randomness

**Best Practices:**
- Never use timestamps for randomness
- Use Aptos Randomness API (when available)
- Use commit-reveal schemes for fairness
- Timestamps OK for non-critical time tracking only

---

### 5. unsafe_resource_handling.move
**Primary Vulnerabilities:**
- **Resource Loss**: Resources destroyed without extracting value
- **Unauthorized Resource Moves**: Moving resources without ownership checks
- **DoS via Existing Resources**: Creating resources at addresses already occupied
- **Option Handling Errors**: Extracting from None without checks

**Key Vulnerable Functions:**
- `merge_vaults_vulnerable()` (unsafe_resource_handling.move:29) - No ownership check
- `close_vault_vulnerable()` (unsafe_resource_handling.move:50) - Value lost
- `withdraw_from_container_vulnerable()` (unsafe_resource_handling.move:68) - No None check
- `extract_twice_vulnerable()` (unsafe_resource_handling.move:79) - Double extraction

**Move's Resource Safety:**
```move
// Move enforces:
// 1. Resources cannot be copied (no 'copy' ability)
// 2. Resources cannot be dropped (no 'drop' ability)
// 3. Must be explicitly moved or destroyed

struct Coin has store {
    value: u64,
}

// VULNERABLE: Value lost
public entry fun destroy_vulnerable() acquires Vault {
    let vault = move_from<Vault>(account_addr);
    let Vault { coins, owner: _ } = vault;
    // coins dropped here - value lost!
}

// SECURE: Extract value first
public entry fun destroy_secure() acquires Vault {
    let vault = move_from<Vault>(account_addr);
    let Vault { coins, owner: _ } = vault;
    let value = coins.value;  // Extract value
    // Return or transfer value
}
```

**Exploit Scenarios:**
1. **DoS**: Attacker creates vault for victim, victim cannot create theirs
2. **Theft**: Attacker merges victim's vault without ownership check
3. **Loss**: User closes vault, coins destroyed, value lost forever

**Impact:** Permanent fund loss, DoS, unauthorized transfers

---

### 6. global_storage_manipulation.move
**Primary Vulnerabilities:**
- **Missing Access Control**: Anyone can modify global state
- **Race Conditions**: Multiple operations on shared state
- **Missing Existence Checks**: Accessing storage that may not exist
- **Admin Bypass**: Weak admin verification

**Key Vulnerable Functions:**
- `update_config_vulnerable()` (global_storage_manipulation.move:26) - No admin check
- `transfer_vulnerable()` (global_storage_manipulation.move:37) - Race conditions
- `pause_vulnerable()` (global_storage_manipulation.move:127) - Anyone can pause
- `admin_set_balance_vulnerable()` (global_storage_manipulation.move:91) - Breaks invariants

**Global Storage in Move:**
```move
// VULNERABLE: No access control
public entry fun update_config_vulnerable(account: &signer, new_fee: u64)
acquires GlobalConfig {
    let config = borrow_global_mut<GlobalConfig>(@module_address);
    config.fee_percentage = new_fee;  // Anyone can change fees!
}

// SECURE: Check admin
public entry fun update_config_secure(admin: &signer, new_fee: u64)
acquires GlobalConfig {
    let admin_addr = signer::address_of(admin);
    let config = borrow_global_mut<GlobalConfig>(@module_address);
    assert!(config.admin == admin_addr, ERROR_NOT_ADMIN);
    config.fee_percentage = new_fee;
}
```

**Exploit Scenarios:**
1. **Config Manipulation**: Attacker changes fee to 99%, users pay excessive fees
2. **Pause Attack**: Attacker pauses protocol, all users locked out
3. **Balance Manipulation**: Admin sets attacker's balance to max, drains protocol

**Impact:** Protocol takeover, DoS, fund theft

---

### 7. missing_initialization.move
**Primary Vulnerabilities:**
- **Reinitialization**: Configs can be initialized multiple times
- **Uninitialized Usage**: State used before proper initialization
- **Admin Takeover**: Reinitialization changes admin
- **Two-Step Race**: Multi-step initialization race conditions

**Key Vulnerable Functions:**
- `initialize_vulnerable()` (missing_initialization.move:24) - No exists check
- `reinitialize_vulnerable()` (missing_initialization.move:80) - Allows reinitialization
- `init_step2_vulnerable()` (missing_initialization.move:67) - No authorization
- `use_config_vulnerable()` (missing_initialization.move:53) - No init check

**Initialization Patterns:**
```move
// VULNERABLE: Can be called multiple times
public entry fun initialize_vulnerable(account: &signer, value: u64) {
    move_to(account, Config {
        admin: signer::address_of(account),
        initialized: true,
        value,
    });
    // If Config already exists, this fails, but logic is unclear
}

// SECURE: Check before initialization
public entry fun initialize_secure(account: &signer, value: u64) {
    let account_addr = signer::address_of(account);
    assert!(!exists<Config>(account_addr), E_ALREADY_INITIALIZED);
    move_to(account, Config {
        admin: account_addr,
        initialized: true,
        value,
    });
}
```

**Exploit Scenarios:**
1. **Admin Takeover**: Attacker reinitializes config, becomes admin
2. **State Reset**: Important values reset to zero via reinitialization
3. **Race Condition**: Attacker completes step 2 of initialization before legitimate admin

**Impact:** Complete protocol takeover, data loss, fund theft

**Real-World Examples:**
- Wormhole ($325M): Initialization issue
- Multiple DeFi exploits: Reinitialization vulnerabilities

---

### 8. type_confusion.move
**Primary Vulnerabilities:**
- **Fake Coin Types**: Accepting any coin type without validation
- **Type Parameter Errors**: Wrong type parameters causing failures
- **Unwrapped Type Confusion**: Type wrapping without validation
- **Pool Type Mismatches**: Creating pools with invalid type combinations

**Key Vulnerable Functions:**
- `create_vault()` (type_confusion.move:22) - No coin type validation
- `create_pool()` (type_confusion.move:77) - Accepts any types
- `wrap_coin()` (type_confusion.move:51) - No type verification

**Move's Type Safety:**
```move
// Move has strong type safety:
// - Generics checked at compile time
// - Type parameters must match exactly
// - No runtime type casting

// VULNERABLE: Accepts any coin type
public entry fun create_vault<CoinType>(account: &signer, amount: u64) {
    let coins = coin::withdraw<CoinType>(account, amount);
    move_to(account, Vault<CoinType> { coins, owner });
    // Attacker could use FakeCoin type!
}

// SECURE: Whitelist approved types
struct CoinMetadata<phantom CoinType> has key {
    verified: bool,
}

public entry fun create_vault_secure<CoinType>(account: &signer, amount: u64)
acquires CoinMetadata {
    assert!(exists<CoinMetadata<CoinType>>(@module), ERROR);
    let metadata = borrow_global<CoinMetadata<CoinType>>(@module);
    assert!(metadata.verified, ERROR);
    // Now safe to create vault
}
```

**Exploit Scenarios:**
1. **Fake Coin**: Attacker creates FakeCoin, creates vault with it
2. **Type Reversal**: User swaps with reversed type parameters, transaction fails
3. **Wrapped Confusion**: User wraps one type, tries to unwrap as different type

**Impact:** Accounting errors, stuck funds, poor UX

**Note:** Move's type system catches most type confusion at compile time, making it much safer than dynamically typed languages.

---

## Testing and Educational Use

### Recommended Tools for Move Development

**Development Frameworks:**
- **Aptos CLI**: Official Aptos development tool
- **Move Prover**: Formal verification tool
- **Sui CLI**: For Sui Move development

**Testing Tools:**
- **Move Unit Tests**: Built-in testing framework
- **Aptos Framework**: Standard library with test utilities
- **Move Prover**: Formal specification and verification

**Security Tools:**
- **Move Prover**: Formal verification of Move code
- **Aptos Labs Audits**: Security review resources
- **Community Tools**: Various static analysis tools

### Building and Testing Move Modules

```bash
# Install Aptos CLI
curl -fsSL "https://aptos.dev/scripts/install_cli.py" | python3

# Initialize Move project
aptos move init --name my_project

# Compile Move modules
aptos move compile

# Run tests
aptos move test

# Deploy to devnet
aptos move publish --network devnet

# Run Move Prover
aptos move prove
```

### Move Project Structure

```
my_project/
├── Move.toml           # Package manifest
├── sources/            # Move source files
│   └── module.move
└── tests/              # Test files
    └── module_test.move
```

### Move.toml Example

```toml
[package]
name = "MyProject"
version = "0.0.1"

[dependencies]
AptosFramework = { git = "https://github.com/aptos-labs/aptos-core.git", subdir = "aptos-move/framework/aptos-framework", rev = "main" }

[addresses]
my_addr = "_"
```

### Deployment Warning

**CRITICAL**: These modules are intentionally vulnerable and should NEVER be deployed to:
- Aptos Mainnet
- Sui Mainnet
- Any production network
- Networks with real financial value

Only use these modules on:
- Local Move development environment
- Aptos Devnet / Sui Testnet
- Private test networks

## Prevention Best Practices

### Move-Specific Security Guidelines

1. **Always Verify Signers**
```move
let account_addr = signer::address_of(account);
assert!(account_addr == expected_owner, ERROR_NOT_AUTHORIZED);
```

2. **Use Capability Pattern**
```move
struct AdminCap has key { admin: address }

public entry fun admin_function(admin: &signer)
acquires AdminCap {
    let admin_addr = signer::address_of(admin);
    assert!(exists<AdminCap>(admin_addr), ERROR_NOT_ADMIN);
}

// Or even better - require capability as parameter
public fun admin_function_with_cap(_cap: &AdminCap) {
    // Caller must have AdminCap
}
```

3. **Check Resource Existence**
```move
assert!(!exists<Resource>(addr), E_ALREADY_EXISTS);
assert!(exists<Resource>(addr), E_NOT_FOUND);
```

4. **Use Checked Arithmetic**
```move
const MAX_U64: u64 = 18446744073709551615;

assert!(MAX_U64 - balance >= amount, E_OVERFLOW);
balance = balance + amount;
```

5. **Prevent Reinitialization**
```move
struct Config has key {
    initialized: bool,
    // ... fields
}

public entry fun initialize(account: &signer) {
    assert!(!exists<Config>(addr), E_ALREADY_INITIALIZED);
    move_to(account, Config { initialized: true, ... });
}
```

6. **Validate Coin Types**
```move
struct ApprovedCoin<phantom CoinType> has key {
    approved: bool,
}

public entry fun use_coin<CoinType>()
acquires ApprovedCoin {
    assert!(exists<ApprovedCoin<CoinType>>(@module), ERROR);
}
```

7. **Extract Value Before Destroying Resources**
```move
let Resource { value, field } = resource;
// Use value before it's dropped
```

8. **Avoid Timestamps for Security**
```move
// BAD: Timestamp for randomness
let random = timestamp::now_seconds() % 100;

// GOOD: Use randomness API or commit-reveal
```

9. **Check Global Storage Access**
```move
public entry fun update_config(admin: &signer)
acquires Config {
    assert!(exists<Config>(@module), E_NOT_INITIALIZED);
    let config = borrow_global_mut<Config>(@module);
    assert!(config.admin == signer::address_of(admin), E_NOT_ADMIN);
}
```

10. **Use Move Prover**
```move
spec module {
    pragma verify = true;
}

spec withdraw {
    ensures balance_after == balance_before - amount;
}
```

### Secure Move Module Template

```move
module my_addr::secure_template {
    use std::signer;

    const E_NOT_AUTHORIZED: u64 = 1;
    const E_NOT_INITIALIZED: u64 = 2;
    const E_ALREADY_INITIALIZED: u64 = 3;
    const E_INSUFFICIENT_BALANCE: u64 = 4;

    /// Capability for admin operations
    struct AdminCap has key {
        admin: address,
    }

    /// Main resource with initialization flag
    struct Vault has key {
        initialized: bool,
        owner: address,
        balance: u64,
    }

    /// Initialize with proper checks
    public entry fun initialize(account: &signer, initial_balance: u64) {
        let account_addr = signer::address_of(account);

        // CHECK: Not already initialized
        assert!(!exists<Vault>(account_addr), E_ALREADY_INITIALIZED);

        // Initialize
        move_to(account, Vault {
            initialized: true,
            owner: account_addr,
            balance: initial_balance,
        });

        // Grant admin capability
        move_to(account, AdminCap {
            admin: account_addr,
        });
    }

    /// Withdraw with all necessary checks
    public entry fun withdraw(account: &signer, amount: u64)
    acquires Vault {
        let account_addr = signer::address_of(account);

        // CHECK: Vault exists
        assert!(exists<Vault>(account_addr), E_NOT_INITIALIZED);

        let vault = borrow_global_mut<Vault>(account_addr);

        // CHECK: Initialized
        assert!(vault.initialized, E_NOT_INITIALIZED);

        // CHECK: Ownership
        assert!(vault.owner == account_addr, E_NOT_AUTHORIZED);

        // CHECK: Sufficient balance
        assert!(vault.balance >= amount, E_INSUFFICIENT_BALANCE);

        // Perform operation
        vault.balance = vault.balance - amount;
    }

    /// Admin operation with capability check
    public entry fun admin_operation(admin: &signer)
    acquires AdminCap {
        let admin_addr = signer::address_of(admin);

        // CHECK: Admin capability exists
        assert!(exists<AdminCap>(admin_addr), E_NOT_AUTHORIZED);

        let admin_cap = borrow_global<AdminCap>(admin_addr);

        // CHECK: Valid admin
        assert!(admin_cap.admin == admin_addr, E_NOT_AUTHORIZED);

        // Perform admin operation
    }
}
```

## Move Security vs. EVM/Solana

### What Move Prevents (vs EVM):
- **Reentrancy**: Not possible by design
- **Integer Overflow**: Runtime checks (but can abort)
- **Type Confusion**: Strong type system catches at compile time
- **Delegatecall Issues**: No delegatecall in Move
- **Storage Collision**: Resources namespaced by type

### What Move Doesn't Prevent:
- **Missing Authorization**: Must explicitly check signers
- **Logic Errors**: Incorrect business logic
- **Timestamp Manipulation**: Same as other blockchains
- **DoS via Overflow**: Overflow causes abort
- **Reinitialization**: Must explicitly prevent

### Move vs Solana:
- **No PDAs**: Move doesn't have PDA concept
- **Different Account Model**: Resources stored at addresses
- **No Rent**: Resources don't have rent requirements
- **Simpler Model**: No complex account validation

## Common Move Vulnerabilities Summary

| Vulnerability | Severity | Difficulty | Prevention |
|---------------|----------|------------|------------|
| Missing Signer Check | Critical | Easy | Always verify signer::address_of() |
| Missing Capability | Critical | Easy | Use capability pattern |
| Integer Overflow | High | Easy | Check bounds before operations |
| Timestamp Dependence | Medium | Easy | Avoid for security/randomness |
| Resource Mishandling | High | Medium | Extract value before dropping |
| Global Storage Issues | High | Medium | Verify access control |
| Reinitialization | Critical | Easy | Check exists before move_to |
| Type Confusion | Low | Hard | Whitelist approved types |

## Real-World Move Exploits

While Move is newer and has had fewer exploits than EVM, vulnerabilities have been found:
- **Various DeFi protocols**: Missing authorization checks
- **NFT platforms**: Reinitialization issues
- **Token contracts**: Integer overflow DoS
- **Governance modules**: Capability bypass attempts

## References and Learning Resources

**Official Documentation:**
- [Move Book](https://move-language.github.io/move/)
- [Aptos Documentation](https://aptos.dev/)
- [Sui Documentation](https://docs.sui.io/)
- [Move Prover Documentation](https://github.com/move-language/move/tree/main/language/move-prover)

**Security Resources:**
- [Move Security Guidelines](https://aptos.dev/guides/move-guides/move-security-guidelines/)
- [Aptos Security Best Practices](https://aptos.dev/guides/system-integrators-guide/#security-best-practices)
- [Move Prover Tutorial](https://github.com/move-language/move/blob/main/language/move-prover/doc/user/prover-guide.md)

**Learning Materials:**
- [Move Tutorial](https://github.com/move-language/move/tree/main/language/documentation/tutorial)
- [Move by Example](https://move-book.com/)
- [Aptos Learn](https://learn.aptoslabs.com/)
- [Sui Move by Example](https://examples.sui.io/)

**Developer Tools:**
- [Aptos CLI](https://aptos.dev/cli-tools/aptos-cli-tool/install-aptos-cli)
- [Sui CLI](https://docs.sui.io/build/install)
- [Move Playground](https://playground.move-language.org/)

## Contributing

These examples are for educational purposes. Contributions that add new vulnerability patterns or improve existing examples are welcome.

## License

MIT License - Use for educational and security research purposes only.

## Disclaimer

These Move modules are provided for educational and security research purposes only. The authors are not responsible for any misuse of these examples. Never deploy vulnerable code to production environments. Always conduct thorough security audits and consider using the Move Prover for formal verification before deploying Move modules that handle real value.

## Acknowledgments

These examples are inspired by:
- Move language design principles
- Real-world Move security findings
- Aptos and Sui security guidelines
- Community contributions to Move security
- Lessons learned from EVM and Solana security
