/*
 * VULNERABLE MOVE MODULE - DO NOT USE IN PRODUCTION
 *
 * Integer Overflow/Underflow Vulnerabilities
 *
 * While Move has runtime checks for overflow, this module demonstrates
 * scenarios where overflow/underflow can still cause issues through
 * logical errors and unchecked arithmetic.
 */

module vulnerable::integer_overflow {
    use std::signer;

    const MAX_U64: u64 = 18446744073709551615;

    const E_OVERFLOW: u64 = 1;
    const E_UNDERFLOW: u64 = 2;
    const E_INSUFFICIENT_BALANCE: u64 = 3;

    struct Balance has key {
        amount: u64,
    }

    struct RewardPool has key {
        total_staked: u64,
        reward_per_token: u64,
        last_update: u64,
    }

    /// Initialize balance
    public entry fun initialize(account: &signer) {
        move_to(account, Balance {
            amount: 0,
        });
    }

    /// VULNERABLE: Addition without overflow check in logic
    public entry fun deposit_vulnerable(account: &signer, amount: u64)
    acquires Balance {
        let account_addr = signer::address_of(account);

        if (!exists<Balance>(account_addr)) {
            move_to(account, Balance { amount: 0 });
        };

        let balance = borrow_global_mut<Balance>(account_addr);

        // VULNERABILITY: While Move checks overflow at runtime,
        // if amount + balance.amount > MAX_U64, this aborts
        // But the function doesn't handle this gracefully
        // An attacker can DoS by causing overflow
        balance.amount = balance.amount + amount;
    }

    /// VULNERABLE: Subtraction can cause abort if insufficient
    public entry fun withdraw_vulnerable(account: &signer, amount: u64)
    acquires Balance {
        let account_addr = signer::address_of(account);
        let balance = borrow_global_mut<Balance>(account_addr);

        // VULNERABILITY: If amount > balance.amount, this aborts
        // But no check before subtraction = poor error handling
        // Could be exploited to DoS the function
        balance.amount = balance.amount - amount;
    }

    /// VULNERABLE: Multiplication overflow in reward calculation
    public entry fun calculate_reward_vulnerable(account: &signer, staked_amount: u64, multiplier: u64): u64 {
        // VULNERABILITY: If staked_amount * multiplier > MAX_U64, aborts
        // Attacker can provide large values to cause DoS
        // Should check: if multiplier > MAX_U64 / staked_amount, error

        let reward = staked_amount * multiplier;
        reward
    }

    /// VULNERABLE: Division precision loss
    public entry fun distribute_reward_vulnerable(
        total_pool: u64,
        user_stake: u64,
        total_stake: u64
    ): u64 {
        // VULNERABILITY: Integer division loses precision
        // If user_stake < total_stake, user_share might be 0
        // User loses their reward due to rounding

        let user_share = user_stake / total_stake;  // WRONG: divide first
        let reward = total_pool * user_share;
        reward
    }

    /// VULNERABLE: Percentage calculation overflow
    public entry fun apply_fee_vulnerable(amount: u64, fee_bps: u64): u64 {
        // fee_bps is in basis points (1 bps = 0.01%)

        // VULNERABILITY: amount * fee_bps can overflow
        // If amount is large, multiplication overflows
        let fee = (amount * fee_bps) / 10000;
        amount - fee
    }

    /// VULNERABLE: Time-based calculation overflow
    public entry fun calculate_interest_vulnerable(
        principal: u64,
        rate_per_second: u64,
        duration: u64
    ): u64 {
        // VULNERABILITY: Multiple overflows possible
        // 1. rate_per_second * duration can overflow
        // 2. principal * interest_rate can overflow

        let interest_rate = rate_per_second * duration;
        let interest = principal * interest_rate / 10000;
        principal + interest
    }

    /// SECURE VERSION: Checked arithmetic
    public entry fun deposit_secure(account: &signer, amount: u64)
    acquires Balance {
        let account_addr = signer::address_of(account);

        if (!exists<Balance>(account_addr)) {
            move_to(account, Balance { amount: 0 });
        };

        let balance = borrow_global_mut<Balance>(account_addr);

        // CHECK: Verify no overflow before addition
        assert!(MAX_U64 - balance.amount >= amount, E_OVERFLOW);

        balance.amount = balance.amount + amount;
    }

    /// SECURE VERSION: Checked subtraction
    public entry fun withdraw_secure(account: &signer, amount: u64)
    acquires Balance {
        let account_addr = signer::address_of(account);
        let balance = borrow_global_mut<Balance>(account_addr);

        // CHECK: Verify sufficient balance
        assert!(balance.amount >= amount, E_INSUFFICIENT_BALANCE);

        balance.amount = balance.amount - amount;
    }

    /// SECURE VERSION: Checked multiplication
    public fun calculate_reward_secure(staked_amount: u64, multiplier: u64): u64 {
        // CHECK: Verify no overflow
        if (multiplier > 0) {
            assert!(staked_amount <= MAX_U64 / multiplier, E_OVERFLOW);
        };

        staked_amount * multiplier
    }

    /// SECURE VERSION: Correct order of operations
    public fun distribute_reward_secure(
        total_pool: u64,
        user_stake: u64,
        total_stake: u64
    ): u64 {
        // CORRECT: Multiply first, then divide
        // This minimizes precision loss

        // CHECK: Prevent division by zero
        assert!(total_stake > 0, 4);

        // CHECK: Prevent overflow in multiplication
        assert!(total_pool <= MAX_U64 / user_stake, E_OVERFLOW);

        let numerator = total_pool * user_stake;
        let reward = numerator / total_stake;
        reward
    }

    /// SECURE VERSION: Safe percentage calculation
    public fun apply_fee_secure(amount: u64, fee_bps: u64): u64 {
        // CHECK: Validate fee is reasonable
        assert!(fee_bps <= 10000, 5); // Max 100%

        // CHECK: Prevent overflow
        assert!(amount <= MAX_U64 / fee_bps, E_OVERFLOW);

        let fee = (amount * fee_bps) / 10000;

        // CHECK: Ensure fee doesn't exceed amount
        assert!(fee <= amount, E_UNDERFLOW);

        amount - fee
    }
}

/*
 * MOVE'S OVERFLOW PROTECTION:
 *
 * Move provides runtime overflow checking:
 * - Addition, subtraction, multiplication checked
 * - Overflow causes transaction to abort
 * - BUT: This can be exploited for DoS
 * - Better to check and return error than abort
 */

/*
 * EXPLOIT SCENARIOS:
 *
 * DoS via Overflow:
 * 1. Attacker finds victim's balance is near MAX_U64
 * 2. Attacker calls deposit with large amount
 * 3. Addition overflows, transaction aborts
 * 4. Victim's account stuck, can't deposit anymore
 *
 * Precision Loss:
 * 1. User stakes 10 tokens in pool of 1,000,000
 * 2. distribute_reward_vulnerable calculates:
 *    - user_share = 10 / 1,000,000 = 0 (integer division!)
 *    - reward = 100,000 * 0 = 0
 * 3. User gets 0 reward despite staking
 *
 * Overflow in Multiplication:
 * 1. User has large balance: 10,000,000,000
 * 2. Multiplier is 2,000,000
 * 3. calculate_reward: 10,000,000,000 * 2,000,000 overflows
 * 4. Transaction aborts, user can't claim reward
 */

/*
 * BEST PRACTICES:
 *
 * 1. Check bounds before arithmetic operations
 * 2. Use MAX_U64 constant for overflow checks
 * 3. Handle potential overflows gracefully with errors
 * 4. Multiply before dividing to minimize precision loss
 * 5. Validate input ranges for multiplication
 * 6. Use u128 for intermediate calculations if needed
 * 7. Consider using fixed-point arithmetic libraries
 */
