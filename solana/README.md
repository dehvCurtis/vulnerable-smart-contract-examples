# Vulnerable Solana Program Examples

This repository contains intentionally vulnerable Solana programs (smart contracts) for educational and security testing purposes. **DO NOT deploy these programs to production networks.**

## About Solana Programs

Solana programs (smart contracts) are written in Rust and have unique security considerations compared to EVM-based chains:
- Account-based model (not storage-based like EVM)
- Programs are stateless; state is stored in separate accounts
- PDAs (Program Derived Addresses) for deterministic addresses
- CPI (Cross-Program Invocation) for inter-program calls
- Rent requirements for account persistence
- Different attack vectors than Ethereum

## Purpose

These programs demonstrate common security vulnerabilities in Solana development to help developers:
- Understand Solana-specific security risks
- Learn secure coding patterns for Solana
- Practice security analysis and penetration testing
- Develop auditing skills for Solana programs

## Vulnerability Inventory

### 1. missing_signer_check.rs
**Primary Vulnerabilities:**
- **Missing Signer Verification**: Program fails to check if required accounts are signers
- **Unauthorized Transactions**: Anyone can modify data or transfer funds without authorization
- **Authority Bypass**: Critical operations executed without proper authentication

**Key Vulnerable Code:**
- `process_instruction()` (missing_signer_check.rs:25) - No `is_signer` check on user_account

**Vulnerability Details:**
```rust
// VULNERABLE: No check
let user_account = next_account_info(accounts_iter)?;
**user_account.try_borrow_mut_lamports()? -= amount;

// SECURE: Add signer check
if !user_account.is_signer {
    return Err(ProgramError::MissingRequiredSignature);
}
```

**Exploit Scenario:**
1. Attacker creates transaction with victim's account (without victim's signature)
2. Program doesn't verify account is a signer
3. Attacker drains victim's funds

**Impact:** Complete loss of funds, unauthorized state changes

---

### 2. missing_owner_check.rs
**Primary Vulnerabilities:**
- **No Owner Verification**: Program doesn't verify accounts are owned by expected program
- **Fake Account Data**: Attackers can pass accounts with malicious data
- **Account Substitution**: Wrong accounts accepted as valid

**Key Vulnerable Code:**
- `process_instruction()` (missing_owner_check.rs:25) - Missing owner check on vault_account

**Vulnerability Details:**
```rust
// VULNERABLE: No owner check
let vault_account = next_account_info(accounts_iter)?;
let vault_data = VaultData::try_from_slice(&vault_account.data.borrow())?;

// SECURE: Add owner check
if vault_account.owner != program_id {
    return Err(ProgramError::IncorrectProgramId);
}
```

**Exploit Scenario:**
1. Attacker creates their own account with fake data
2. Sets authority field to attacker's address
3. Passes fake account to vulnerable program
4. Program doesn't check owner, accepts fake data
5. Attacker withdraws funds using their fake account

**Impact:** Unauthorized access, data manipulation, fund theft

**Real-World Examples:**
- Wormhole Bridge hack ($325M) - Similar account validation issues

---

### 3. arbitrary_cpi.rs
**Primary Vulnerabilities:**
- **User-Controlled CPI Target**: Users can specify which program to invoke
- **Arbitrary Program Invocation**: Can call malicious or unintended programs
- **Unchecked Instruction Data**: User controls data passed to invoked program

**Key Vulnerable Code:**
- `process_instruction()` (arbitrary_cpi.rs:26) - User-controlled target program

**Vulnerability Details:**
```rust
// VULNERABLE: User controls target_program
let instruction = Instruction {
    program_id: *target_program.key,  // User-controlled!
    accounts: vec![...],
    data: instruction_data.to_vec(),  // User-controlled!
};
invoke(&instruction, &[...])?;

// SECURE: Whitelist allowed programs
const ALLOWED_PROGRAMS: &[Pubkey] = &[system_program::ID];
if !ALLOWED_PROGRAMS.contains(target_program.key) {
    return Err(ProgramError::InvalidInstructionData);
}
```

**Exploit Scenarios:**
1. **System Program Drain**: Invoke System Program to transfer user's SOL to attacker
2. **Malicious Program**: Call attacker's program with user's signature
3. **Account Closure**: Close critical accounts, losing data

**Impact:** Complete program compromise, fund theft, data loss

---

### 4. pda_issues.rs
**Primary Vulnerabilities:**
- **No PDA Derivation Verification**: Doesn't verify PDAs are correctly derived
- **PDA Substitution**: Attackers can pass PDAs with different seeds
- **Missing Bump Validation**: Accepts non-canonical bump seeds
- **Authorization Bypass**: Wrong PDAs can bypass access controls

**Key Vulnerable Code:**
- `process_instruction()` (pda_issues.rs:25) - No PDA derivation check

**Vulnerability Details:**
```rust
// VULNERABLE: Accepts any PDA without verification
let pda_account = next_account_info(accounts_iter)?;

// SECURE: Derive and verify PDA
let (expected_pda, bump) = Pubkey::find_program_address(
    &[b"user_data", user_account.key.as_ref()],
    program_id
);
if expected_pda != *pda_account.key {
    return Err(ProgramError::InvalidSeeds);
}
```

**Exploit Scenario:**
1. Legitimate user has PDA derived from standard seeds
2. Attacker creates PDA with malicious seeds
3. Sets owner field in fake PDA to victim's address
4. Program doesn't verify derivation, accepts fake PDA
5. Attacker bypasses authorization checks

**Impact:** Authorization bypass, fund theft, privilege escalation

---

### 5. reinitialization.rs
**Primary Vulnerabilities:**
- **No Initialization Flag**: Missing check if account is already initialized
- **State Reset**: Attackers can reinitialize accounts, resetting state
- **Ownership Takeover**: Reinitialization allows changing authority
- **Data Loss**: Existing data overwritten on reinitialization

**Key Vulnerable Code:**
- `initialize()` (reinitialization.rs:28) - No reinitialization check

**Vulnerability Details:**
```rust
// VULNERABLE: No check for existing initialization
pub struct VaultConfig {
    pub authority: Pubkey,
    pub total_deposited: u64,
}

// SECURE: Add is_initialized flag
pub struct VaultConfigSecure {
    pub is_initialized: bool,  // Add this!
    pub authority: Pubkey,
    pub total_deposited: u64,
}

// Then check it
if existing_config.is_initialized {
    return Err(ProgramError::AccountAlreadyInitialized);
}
```

**Exploit Scenario:**
1. User initializes vault with 100 SOL deposited
2. Attacker calls initialize again
3. Authority changed to attacker
4. total_deposited reset to 0
5. Attacker now controls vault with user's 100 SOL

**Impact:** Complete takeover, fund theft, data loss

**Real-World Examples:**
- Wormhole ($325M) - Initialization issue
- Cashio ($52M) - Reinitialization vulnerability

---

### 6. type_confusion.rs
**Primary Vulnerabilities:**
- **No Type Discriminator**: Accounts lack unique type identifiers
- **Account Type Confusion**: Different account types with similar layouts
- **Field Misinterpretation**: Fields interpreted as wrong type
- **Authorization Bypass**: Wrong account type can bypass checks

**Key Vulnerable Code:**
- `withdraw_user()` (type_confusion.rs:31) - No type discrimination
- `admin_action()` (type_confusion.rs:69) - Same issue

**Vulnerability Details:**
```rust
// VULNERABLE: No discriminator
pub struct UserAccount {
    pub owner: Pubkey,
    pub balance: u64,
    pub rewards: u64,
}

// SECURE: Add discriminator
const USER_ACCOUNT_DISCRIMINATOR: u64 = 0x1111111111111111;
pub struct UserAccountSecure {
    pub discriminator: u64,
    pub owner: Pubkey,
    pub balance: u64,
    pub rewards: u64,
}

// Verify discriminator
if user_data.discriminator != USER_ACCOUNT_DISCRIMINATOR {
    return Err(ProgramError::InvalidAccountData);
}
```

**Exploit Scenario:**
1. Attacker passes AdminAccount where UserAccount expected
2. AdminAccount.admin_level field interpreted as UserAccount.rewards
3. If admin_level = 1000, appears as 1000 rewards
4. Attacker withdraws more than they should

**Impact:** Fund theft, privilege escalation, logic bypass

**Note:** Anchor framework automatically adds discriminators

---

### 7. arithmetic_errors.rs
**Primary Vulnerabilities:**
- **Integer Overflow**: Unchecked additions can overflow
- **Integer Underflow**: Unchecked subtractions can underflow
- **Precision Loss**: Division before multiplication loses precision
- **Reward Calculation Errors**: Wrong operation order in complex math

**Key Vulnerable Code:**
- `stake()` (arithmetic_errors.rs:35) - Unchecked addition
- `calculate_rewards()` (arithmetic_errors.rs:59) - Multiple issues
- `vulnerable_transfer()` (arithmetic_errors.rs:97) - Underflow risk

**Vulnerability Details:**
```rust
// VULNERABLE: Unchecked arithmetic
pool_data.total_staked += amount;  // Can overflow
**from_account.try_borrow_mut_lamports()? -= amount;  // Can underflow

// SECURE: Use checked arithmetic
pool_data.total_staked = pool_data.total_staked
    .checked_add(amount)
    .ok_or(ProgramError::ArithmeticOverflow)?;

if **from_account.lamports.borrow() < amount {
    return Err(ProgramError::InsufficientFunds);
}
**from_account.try_borrow_mut_lamports()? -= amount;
```

**Exploit Scenarios:**
1. **Overflow Attack**: Stake u64::MAX - 100, then stake 200 more → wraps to 99
2. **Underflow Attack**: Transfer more than balance → wraps to huge number
3. **Precision Loss**: User with small stake gets 0 rewards due to division truncation

**Impact:** Incorrect calculations, fund manipulation, reward theft

---

### 8. account_data_matching.rs
**Primary Vulnerabilities:**
- **No Relationship Verification**: Doesn't verify accounts have expected relationships
- **Account Substitution**: Can pass wrong accounts that pass basic checks
- **Missing Cross-Reference Checks**: Doesn't validate data fields match passed accounts

**Key Vulnerable Code:**
- `process_instruction()` (account_data_matching.rs:28) - Multiple missing checks

**Vulnerability Details:**
```rust
// VULNERABLE: Doesn't verify relationships
let user_profile = UserProfile::try_from_slice(&user_profile_account.data.borrow())?;
let escrow_data = EscrowAccount::try_from_slice(&escrow_account.data.borrow())?;
// No check that user_profile.escrow_account == *escrow_account.key
// No check that escrow_data.beneficiary == *beneficiary_account.key

// SECURE: Verify all relationships
if user_profile.escrow_account != *escrow_account.key {
    return Err(ProgramError::InvalidAccountData);
}
if escrow_data.beneficiary != *beneficiary_account.key {
    return Err(ProgramError::InvalidAccountData);
}
```

**Exploit Scenario:**
1. User has profile pointing to EscrowA with 100 SOL
2. Victim has EscrowB with 1000 SOL, ready to release
3. Attacker passes: User's profile + Victim's EscrowB + Attacker's wallet
4. Program doesn't verify escrow matches profile
5. Victim's 1000 SOL sent to attacker

**Impact:** Fund theft through account substitution

---

### 9. rent_exemption.rs
**Primary Vulnerabilities:**
- **No Rent Exemption Check**: Doesn't verify accounts have enough lamports
- **Account Garbage Collection**: Accounts can be deleted by runtime
- **Draining Below Minimum**: Withdrawals leave accounts with insufficient funds
- **Permanent Data Loss**: State lost when accounts are garbage collected

**Key Vulnerable Code:**
- `initialize()` (rent_exemption.rs:28) - No rent check
- `withdraw_all()` (rent_exemption.rs:53) - Drains below minimum

**Vulnerability Details:**
```rust
// VULNERABLE: No rent exemption check
let user_data_account = next_account_info(accounts_iter)?;
// Initialize without checking if rent-exempt

// Withdraw all lamports
let balance = **user_data_account.lamports.borrow();
**user_data_account.try_borrow_mut_lamports()? = 0;

// SECURE: Check rent exemption
let rent = Rent::get()?;
if !rent.is_exempt(user_data_account.lamports(), user_data_account.data_len()) {
    return Err(ProgramError::AccountNotRentExempt);
}

// Only withdraw excess above minimum
let min_balance = rent.minimum_balance(user_data_account.data_len());
let withdrawable = balance.checked_sub(min_balance)
    .ok_or(ProgramError::InsufficientFunds)?;
```

**What is Rent on Solana:**
- Solana charges rent for storing account data
- Accounts with >= 2 years of rent are "rent-exempt"
- Non-exempt accounts are garbage collected
- Rent exemption threshold depends on data size
- Current rate: ~0.00000348 SOL per byte per year

**Exploit Scenario:**
1. Attacker creates account with insufficient lamports
2. Program initializes without rent check
3. Runtime garbage collects account
4. User's data permanently lost

**Impact:** Data loss, broken program state, unusable accounts

---

## Testing and Educational Use

### Recommended Tools for Solana Development

**Development Frameworks:**
- **Anchor**: High-level framework with built-in security features
- **Native Rust**: solana-program crate for low-level development
- **Seahorse**: Python-based Solana framework

**Testing Tools:**
- **solana-test-validator**: Local validator for testing
- **solana-program-test**: Unit testing framework
- **Bankrun**: Fast program testing
- **Trdelnik**: Fuzzing framework for Solana

**Security Tools:**
- **Sec3**: Automated security scanner
- **Soteria**: Static analyzer for Solana programs
- **Xray**: Runtime verification tool

### Building and Testing

```bash
# Install Rust and Solana CLI
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sh -c "$(curl -sSfL https://release.solana.com/stable/install)"

# Build a program
cargo build-bpf

# Deploy to local validator
solana-test-validator
solana program deploy /path/to/program.so

# Run tests
cargo test-bpf
```

### Using Anchor Framework

```bash
# Install Anchor
cargo install --git https://github.com/coral-xyz/anchor avm --locked --force
avm install latest
avm use latest

# Create new project
anchor init my_project

# Build
anchor build

# Test
anchor test
```

### Deployment Warning

**CRITICAL**: These programs are intentionally vulnerable and should NEVER be deployed to:
- Solana Mainnet Beta
- Any production network
- Networks with real financial value

Only use these programs on:
- Local test validator (solana-test-validator)
- Solana Devnet (for educational purposes only)
- Private test environments

## Prevention Best Practices

### Solana-Specific Security Guidelines

1. **Always Verify Signers**
```rust
if !account.is_signer {
    return Err(ProgramError::MissingRequiredSignature);
}
```

2. **Check Account Ownership**
```rust
if account.owner != program_id {
    return Err(ProgramError::IncorrectProgramId);
}
```

3. **Validate PDA Derivation**
```rust
let (expected_pda, bump) = Pubkey::find_program_address(seeds, program_id);
if expected_pda != *pda_account.key {
    return Err(ProgramError::InvalidSeeds);
}
```

4. **Prevent Reinitialization**
```rust
pub struct MyAccount {
    pub is_initialized: bool,  // Add this flag
    // ... other fields
}

if account.is_initialized {
    return Err(ProgramError::AccountAlreadyInitialized);
}
```

5. **Use Type Discriminators**
```rust
pub struct MyAccount {
    pub discriminator: u64,  // Unique type identifier
    // ... other fields
}

if account.discriminator != EXPECTED_DISCRIMINATOR {
    return Err(ProgramError::InvalidAccountData);
}
```

6. **Use Checked Arithmetic**
```rust
let result = a.checked_add(b)
    .ok_or(ProgramError::ArithmeticOverflow)?;
```

7. **Verify Account Relationships**
```rust
if profile.linked_account != *passed_account.key {
    return Err(ProgramError::InvalidAccountData);
}
```

8. **Ensure Rent Exemption**
```rust
let rent = Rent::get()?;
if !rent.is_exempt(account.lamports(), account.data_len()) {
    return Err(ProgramError::AccountNotRentExempt);
}
```

9. **Whitelist CPI Targets**
```rust
const ALLOWED_PROGRAMS: &[Pubkey] = &[system_program::ID];
if !ALLOWED_PROGRAMS.contains(target_program.key) {
    return Err(ProgramError::InvalidInstructionData);
}
```

10. **Use Anchor Framework**
- Anchor provides automatic checks for many vulnerabilities
- Built-in discriminators, initialization checks, constraints
- Simpler and safer than raw Solana programs

### Secure Anchor Example

```rust
use anchor_lang::prelude::*;

#[program]
pub mod secure_program {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.amount = amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,                          // Ensures not already initialized
        payer = authority,              // Specifies who pays
        space = 8 + 32 + 8,            // Discriminator + fields
        seeds = [b"vault", authority.key().as_ref()],  // PDA derivation
        bump                            // Canonical bump
    )]
    pub vault: Account<'info, Vault>,  // Automatic owner check
    #[account(mut)]
    pub authority: Signer<'info>,      // Automatic signer check
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub amount: u64,
}
```

## Common Solana Vulnerabilities Summary

| Vulnerability | Impact | Difficulty | Anchor Prevents? |
|---------------|--------|------------|------------------|
| Missing Signer Check | Critical | Easy | Yes (Signer<>) |
| Missing Owner Check | Critical | Easy | Yes (Account<>) |
| Arbitrary CPI | Critical | Medium | Partial |
| PDA Issues | High | Medium | Yes (seeds, bump) |
| Reinitialization | Critical | Easy | Yes (init) |
| Type Confusion | High | Medium | Yes (discriminator) |
| Arithmetic Errors | High | Easy | No (use checked math) |
| Account Matching | High | Medium | Yes (constraints) |
| Rent Exemption | Medium | Easy | Yes (automatic) |

## Differences from EVM Security

### Unique to Solana:
- **Account Model**: State in accounts, not contract storage
- **PDAs**: Deterministic addresses without private keys
- **Rent**: Accounts need minimum balance or get deleted
- **Parallel Processing**: Read/write locks on accounts
- **No Reentrancy**: Different execution model

### Similar to EVM:
- Integer overflow/underflow (though Rust has better defaults)
- Authorization/access control issues
- Precision loss in arithmetic
- External call risks (CPI vs. external calls)

## Real-World Solana Exploits

1. **Wormhole Bridge (2022)**: $325M - Initialization issue
2. **Cashio (2022)**: $52M - Reinitialization vulnerability
3. **Crema Finance (2022)**: $9M - Missing signer check
4. **Slope Wallet (2022)**: $8M - Private key logging
5. **Nirvana Finance (2022)**: $3.5M - Pricing oracle manipulation

## References and Learning Resources

**Official Documentation:**
- [Solana Docs](https://docs.solana.com/)
- [Solana Program Library](https://spl.solana.com/)
- [Anchor Book](https://book.anchor-lang.com/)
- [Anchor Documentation](https://www.anchor-lang.com/)

**Security Resources:**
- [Solana Security Best Practices](https://github.com/solana-labs/solana/blob/master/docs/src/developing/security.md)
- [Sealevel Attacks](https://github.com/coral-xyz/sealevel-attacks) - Vulnerability examples
- [Neodyme Blog](https://blog.neodyme.io/) - Security research
- [Sec3 Blog](https://www.sec3.dev/blog) - Audit findings

**Learning Materials:**
- [Solana Cookbook](https://solanacookbook.com/)
- [Solana Development Course](https://www.soldev.app/)
- [Anchor by Example](https://examples.anchor-lang.com/)
- [Solana Security Workshop](https://workshop.neodyme.io/)

## Contributing

These examples are for educational purposes. If you find additional vulnerability patterns or have improvements, contributions are welcome for educational purposes only.

## License

MIT License - Use for educational and security research purposes only.

## Disclaimer

These programs are provided for educational and security research purposes only. The authors are not responsible for any misuse of these examples. Never deploy vulnerable programs to production environments. Always conduct thorough security audits and use secure frameworks like Anchor when developing production Solana programs. Real funds should never be used with these examples.

## Acknowledgments

These examples are inspired by:
- Real-world Solana exploits and post-mortems
- Neodyme's Sealevel Attacks repository
- Solana security audits and disclosures
- Anchor framework security features
- Community contributions to Solana security
