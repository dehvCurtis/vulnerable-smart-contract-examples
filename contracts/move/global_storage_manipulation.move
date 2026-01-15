/*
 * VULNERABLE MOVE MODULE - DO NOT USE IN PRODUCTION
 *
 * Global Storage Manipulation Vulnerabilities
 *
 * This module demonstrates vulnerabilities in global storage access,
 * including improper access control and race conditions.
 */

module vulnerable::global_storage_manipulation {
    use std::signer;
    use std::vector;

    struct GlobalConfig has key {
        admin: address,
        fee_percentage: u64,
        paused: bool,
    }

    struct UserBalance has key {
        amount: u64,
        last_updated: u64,
    }

    struct SharedPool has key {
        total_balance: u64,
        participant_count: u64,
    }

    /// Initialize global config at module address
    public entry fun initialize(admin: &signer, fee_percentage: u64) {
        let admin_addr = signer::address_of(admin);

        // Store at module address (@vulnerable)
        move_to(admin, GlobalConfig {
            admin: admin_addr,
            fee_percentage,
            paused: false,
        });
    }

    /// VULNERABLE: Anyone can modify global config
    public entry fun update_config_vulnerable(
        account: &signer,
        new_fee: u64
    ) acquires GlobalConfig {
        // VULNERABILITY: No admin check!
        // Anyone can modify global configuration
        // Should check: assert!(signer::address_of(account) == config.admin, ERROR);

        let config = borrow_global_mut<GlobalConfig>(@vulnerable);
        config.fee_percentage = new_fee;
    }

    /// VULNERABLE: Race condition in balance update
    public entry fun transfer_vulnerable(
        from: &signer,
        to_addr: address,
        amount: u64
    ) acquires UserBalance {
        let from_addr = signer::address_of(from);

        // VULNERABILITY: Multiple borrows create race condition potential
        // If called in complex transaction, state could be inconsistent

        let from_balance = borrow_global_mut<UserBalance>(from_addr);
        let initial_from_balance = from_balance.amount;

        // VULNERABILITY: No check before subtraction
        from_balance.amount = from_balance.amount - amount;

        // VULNERABILITY: Borrow after mut borrow could cause issues
        let to_balance = borrow_global_mut<UserBalance>(to_addr);
        to_balance.amount = to_balance.amount + amount;

        // If any assertion fails between these operations,
        // state could be inconsistent
    }

    /// VULNERABLE: Shared state without proper synchronization
    public entry fun join_pool_vulnerable(account: &signer, amount: u64)
    acquires SharedPool, UserBalance {
        let account_addr = signer::address_of(account);

        let pool = borrow_global_mut<SharedPool>(@vulnerable);
        let user_balance = borrow_global_mut<UserBalance>(account_addr);

        // VULNERABILITY: Multiple operations on shared state
        // No atomicity guarantees across these operations

        user_balance.amount = user_balance.amount - amount;
        pool.total_balance = pool.total_balance + amount;
        pool.participant_count = pool.participant_count + 1;

        // If this aborts, user loses amount but pool state might be inconsistent
    }

    /// VULNERABLE: Accessing global state without existence check
    public entry fun use_config_vulnerable(account: &signer) acquires GlobalConfig {
        // VULNERABILITY: No check if GlobalConfig exists
        // Will abort if not initialized
        let config = borrow_global<GlobalConfig>(@vulnerable);

        // Use config...
        let fee = config.fee_percentage;
    }

    /// VULNERABLE: Modifying storage at arbitrary address
    public entry fun admin_set_balance_vulnerable(
        admin: &signer,
        user: address,
        new_balance: u64
    ) acquires GlobalConfig, UserBalance {
        let config = borrow_global<GlobalConfig>(@vulnerable);

        // VULNERABILITY: Weak admin check
        assert!(signer::address_of(admin) == config.admin, 1);

        // VULNERABILITY: Admin can set arbitrary balances!
        // This breaks invariants - balance should only change via deposits/withdrawals
        let user_balance = borrow_global_mut<UserBalance>(user);
        user_balance.amount = new_balance;
    }

    /// VULNERABLE: Reading stale data
    public entry fun calculate_reward_vulnerable(account: &signer): u64
    acquires UserBalance, SharedPool {
        let account_addr = signer::address_of(account);

        // Read user balance
        let user_balance = borrow_global<UserBalance>(account_addr);
        let user_amount = user_balance.amount;

        // Read pool state
        let pool = borrow_global<SharedPool>(@vulnerable);
        let total = pool.total_balance;

        // VULNERABILITY: These reads are not atomic
        // Pool state could have changed between reads
        // Reward calculation based on potentially stale data

        let reward = (user_amount * 100) / total;
        reward
    }

    /// VULNERABLE: No access control on pause
    public entry fun pause_vulnerable(account: &signer)
    acquires GlobalConfig {
        // VULNERABILITY: Anyone can pause the system!
        let config = borrow_global_mut<GlobalConfig>(@vulnerable);
        config.paused = true;
    }

    /// SECURE VERSION: Proper admin check
    public entry fun update_config_secure(
        admin: &signer,
        new_fee: u64
    ) acquires GlobalConfig {
        let admin_addr = signer::address_of(admin);

        // CHECK: Verify config exists
        assert!(exists<GlobalConfig>(@vulnerable), 2);

        let config = borrow_global_mut<GlobalConfig>(@vulnerable);

        // CHECK: Verify caller is admin
        assert!(config.admin == admin_addr, 3);

        // CHECK: Validate new fee
        assert!(new_fee <= 10000, 4); // Max 100%

        config.fee_percentage = new_fee;
    }

    /// SECURE VERSION: Atomic transfer with checks
    public entry fun transfer_secure(
        from: &signer,
        to_addr: address,
        amount: u64
    ) acquires UserBalance {
        let from_addr = signer::address_of(from);

        // CHECK: Verify both accounts exist
        assert!(exists<UserBalance>(from_addr), 5);
        assert!(exists<UserBalance>(to_addr), 6);

        // CHECK: Verify sufficient balance BEFORE any modifications
        let from_balance_check = borrow_global<UserBalance>(from_addr);
        assert!(from_balance_check.amount >= amount, 7);

        // Now perform atomic update
        {
            let from_balance = borrow_global_mut<UserBalance>(from_addr);
            from_balance.amount = from_balance.amount - amount;
        }; // Borrow ends here

        {
            let to_balance = borrow_global_mut<UserBalance>(to_addr);
            to_balance.amount = to_balance.amount + amount;
        }; // Borrow ends here

        // All operations succeeded or none did (transaction atomicity)
    }

    /// SECURE VERSION: Existence check before access
    public entry fun use_config_secure(account: &signer): u64 acquires GlobalConfig {
        // CHECK: Verify config exists
        assert!(exists<GlobalConfig>(@vulnerable), 8);

        let config = borrow_global<GlobalConfig>(@vulnerable);

        // CHECK: Verify not paused
        assert!(!config.paused, 9);

        config.fee_percentage
    }

    /// SECURE VERSION: Proper pause with admin check
    public entry fun pause_secure(admin: &signer)
    acquires GlobalConfig {
        let admin_addr = signer::address_of(admin);

        assert!(exists<GlobalConfig>(@vulnerable), 10);

        let config = borrow_global_mut<GlobalConfig>(@vulnerable);

        // CHECK: Only admin can pause
        assert!(config.admin == admin_addr, 11);

        config.paused = true;
    }
}

/*
 * MOVE'S GLOBAL STORAGE MODEL:
 *
 * - Resources stored at account addresses
 * - Global storage accessed via borrow_global/borrow_global_mut
 * - Borrow checking enforced at runtime
 * - Only one mutable borrow at a time per resource
 * - Transaction atomicity ensures consistency
 *
 * However, vulnerabilities can still occur:
 * - Missing access control checks
 * - Improper borrow ordering
 * - Lack of existence checks
 * - State inconsistency in complex operations
 */

/*
 * EXPLOIT SCENARIOS:
 *
 * Config Manipulation:
 * 1. Protocol initialized with 1% fee
 * 2. Attacker calls update_config_vulnerable with 99% fee
 * 3. No admin check performed
 * 4. All users now paying 99% fees to protocol
 * 5. Attacker profits or causes DoS
 *
 * Arbitrary Balance Setting:
 * 1. Attacker colludes with compromised admin
 * 2. Admin sets attacker's balance to max value
 * 3. Attacker withdraws unlimited funds
 * 4. Protocol drained
 *
 * Pause Attack:
 * 1. Protocol operating normally
 * 2. Attacker calls pause_vulnerable
 * 3. No admin check
 * 4. Entire protocol paused
 * 5. Legitimate users cannot access funds
 * 6. DoS attack successful
 *
 * Race Condition:
 * 1. User A and User B both call join_pool simultaneously
 * 2. Both read pool.total_balance = 1000
 * 3. Both add 100 to total
 * 4. Result: total_balance = 1100 (should be 1200)
 * 5. Pool accounting broken
 */

/*
 * BEST PRACTICES:
 *
 * 1. Always check existence before accessing global storage
 * 2. Implement proper access control for admin functions
 * 3. Verify state before and after critical operations
 * 4. Use separate borrows for read and write operations
 * 5. Keep critical sections small and atomic
 * 6. Validate all state transitions
 * 7. Use events to track state changes
 * 8. Consider using addresses as namespaces
 * 9. Document global storage access patterns
 * 10. Test concurrent access scenarios
 */
