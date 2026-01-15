/*
 * VULNERABLE MOVE MODULE - DO NOT USE IN PRODUCTION
 *
 * Missing Initialization Check Vulnerabilities
 *
 * This module demonstrates issues with incomplete or missing initialization
 * checks, allowing reinitialization or use of uninitialized state.
 */

module vulnerable::missing_initialization {
    use std::signer;

    const E_ALREADY_INITIALIZED: u64 = 1;
    const E_NOT_INITIALIZED: u64 = 2;
    const E_NOT_AUTHORIZED: u64 = 3;

    struct Config has key {
        admin: address,
        initialized: bool,
        value: u64,
    }

    struct UserAccount has key {
        balance: u64,
        // VULNERABILITY: Missing initialized flag!
    }

    /// VULNERABLE: No check if already initialized
    public entry fun initialize_vulnerable(account: &signer, value: u64) {
        // VULNERABILITY: Can be called multiple times!
        // Should check: assert!(!exists<Config>(account_addr), E_ALREADY_INITIALIZED);

        move_to(account, Config {
            admin: signer::address_of(account),
            initialized: true,
            value,
        });
    }

    /// VULNERABLE: Has initialized flag but doesn't check it
    public entry fun initialize_with_flag_vulnerable(
        account: &signer,
        value: u64
    ) acquires Config {
        let account_addr = signer::address_of(account);

        if (exists<Config>(account_addr)) {
            let config = borrow_global_mut<Config>(account_addr);

            // VULNERABILITY: Doesn't check initialized flag!
            // Can reinitialize even if already initialized
            config.admin = account_addr;
            config.value = value;
            config.initialized = true;
        } else {
            move_to(account, Config {
                admin: account_addr,
                initialized: true,
                value,
            });
        };
    }

    /// VULNERABLE: Uses uninitialized state
    public entry fun use_config_vulnerable(account: &signer)
    acquires Config {
        let account_addr = signer::address_of(account);

        // VULNERABILITY: No check if Config is initialized
        let config = borrow_global<Config>(account_addr);

        // VULNERABILITY: initialized flag exists but not checked!
        // Could use config that was never properly initialized

        let _value = config.value;
        // Use value...
    }

    /// VULNERABLE: Two-step initialization with race condition
    struct TwoStepInit has key {
        step1_complete: bool,
        step2_complete: bool,
        admin: address,
        value: u64,
    }

    public entry fun init_step1_vulnerable(account: &signer) {
        move_to(account, TwoStepInit {
            step1_complete: true,
            step2_complete: false,
            admin: signer::address_of(account),
            value: 0,
        });
    }

    public entry fun init_step2_vulnerable(
        account: &signer,
        value: u64
    ) acquires TwoStepInit {
        let account_addr = signer::address_of(account);
        let init = borrow_global_mut<TwoStepInit>(account_addr);

        // VULNERABILITY: No check if step1 was completed
        // No check who is calling step2
        // Attacker could call step2 before legitimate admin

        init.value = value;
        init.step2_complete = true;
    }

    /// VULNERABLE: Reinitialization allowed
    public entry fun reinitialize_vulnerable(
        account: &signer,
        new_value: u64
    ) acquires Config {
        let account_addr = signer::address_of(account);

        // VULNERABILITY: No check preventing reinitialization
        // Attacker can reset state, change admin, etc.

        let config = borrow_global_mut<Config>(account_addr);
        config.admin = signer::address_of(account); // VULNERABILITY: Admin changed!
        config.value = new_value;
        config.initialized = true; // Reset initialized flag
    }

    /// SECURE VERSION: Proper initialization with checks
    public entry fun initialize_secure(account: &signer, value: u64) {
        let account_addr = signer::address_of(account);

        // CHECK: Ensure not already initialized
        assert!(!exists<Config>(account_addr), E_ALREADY_INITIALIZED);

        move_to(account, Config {
            admin: account_addr,
            initialized: true,
            value,
        });
    }

    /// SECURE VERSION: Check initialized flag before use
    public entry fun use_config_secure(account: &signer): u64
    acquires Config {
        let account_addr = signer::address_of(account);

        // CHECK: Verify config exists
        assert!(exists<Config>(account_addr), E_NOT_INITIALIZED);

        let config = borrow_global<Config>(account_addr);

        // CHECK: Verify properly initialized
        assert!(config.initialized, E_NOT_INITIALIZED);

        config.value
    }

    /// SECURE VERSION: Two-step initialization with proper checks
    public entry fun init_step1_secure(account: &signer) {
        let account_addr = signer::address_of(account);

        // CHECK: Ensure not already initialized
        assert!(!exists<TwoStepInit>(account_addr), E_ALREADY_INITIALIZED);

        move_to(account, TwoStepInit {
            step1_complete: true,
            step2_complete: false,
            admin: account_addr,
            value: 0,
        });
    }

    public entry fun init_step2_secure(
        account: &signer,
        value: u64
    ) acquires TwoStepInit {
        let account_addr = signer::address_of(account);

        // CHECK: Verify step1 exists
        assert!(exists<TwoStepInit>(account_addr), E_NOT_INITIALIZED);

        let init = borrow_global_mut<TwoStepInit>(account_addr);

        // CHECK: Verify step1 was completed
        assert!(init.step1_complete, E_NOT_INITIALIZED);

        // CHECK: Verify step2 not already completed
        assert!(!init.step2_complete, E_ALREADY_INITIALIZED);

        // CHECK: Verify caller is admin
        assert!(init.admin == account_addr, E_NOT_AUTHORIZED);

        init.value = value;
        init.step2_complete = true;
    }

    /// SECURE VERSION: Update with reinitialization prevention
    public entry fun update_secure(
        account: &signer,
        new_value: u64
    ) acquires Config {
        let account_addr = signer::address_of(account);

        // CHECK: Verify config exists and initialized
        assert!(exists<Config>(account_addr), E_NOT_INITIALIZED);

        let config = borrow_global_mut<Config>(account_addr);

        // CHECK: Verify initialized
        assert!(config.initialized, E_NOT_INITIALIZED);

        // CHECK: Verify caller is admin
        assert!(config.admin == account_addr, E_NOT_AUTHORIZED);

        // Only update value, NOT admin or initialized flag
        config.value = new_value;
    }
}

/*
 * EXPLOIT SCENARIOS:
 *
 * Reinitialization Attack:
 * 1. Alice initializes Config with Alice as admin
 * 2. Bob calls initialize_vulnerable with Bob's address
 * 3. If move_to doesn't revert, state overwritten
 * 4. Bob becomes admin, Alice loses control
 *
 * Admin Takeover via Reinitialization:
 * 1. Protocol initialized with admin = LEGITIMATE_ADMIN
 * 2. Attacker calls reinitialize_vulnerable
 * 3. Admin changed to attacker's address
 * 4. Attacker now has full control
 *
 * Uninitialized State Usage:
 * 1. Config resource created but not fully initialized
 * 2. Someone calls use_config_vulnerable
 * 3. No check if properly initialized
 * 4. Uses garbage/default values
 * 5. Incorrect behavior or security bypass
 *
 * Two-Step Race Condition:
 * 1. Admin calls init_step1
 * 2. Before admin calls init_step2, attacker calls it
 * 3. No authorization check on step2
 * 4. Attacker sets critical values
 * 5. Admin loses control of initialization
 */

/*
 * REAL-WORLD IMPACT:
 *
 * Similar issues have caused major exploits:
 * - Wormhole bridge hack: initialization issue
 * - Various DeFi protocols: reinitialization vulnerabilities
 * - Admin takeover through reinitialization
 * - Loss of funds through uninitialized state
 */

/*
 * BEST PRACTICES:
 *
 * 1. Always check if resource exists before move_to
 * 2. Use initialized flag and check it
 * 3. Prevent reinitialization explicitly
 * 4. Verify authorization for initialization
 * 5. Make initialization atomic (one-step if possible)
 * 6. If multi-step, verify each step and authorization
 * 7. Don't allow changing admin during reinitialization
 * 8. Use witness pattern for one-time initialization
 * 9. Document initialization requirements clearly
 * 10. Test initialization edge cases thoroughly
 */
