/*
 * VULNERABLE MOVE MODULE - DO NOT USE IN PRODUCTION
 *
 * Missing Capability Check Vulnerability
 *
 * Move uses capabilities for authorization, but this module fails to
 * properly check capabilities, allowing unauthorized privileged operations.
 */

module vulnerable::missing_capability_check {
    use std::signer;
    use std::vector;

    /// Admin capability - only admin should have this
    struct AdminCap has key, store {
        admin_address: address,
    }

    /// User registry
    struct UserRegistry has key {
        users: vector<address>,
        admin: address,
    }

    /// Initialize the registry with admin
    public entry fun initialize(admin: &signer) {
        let admin_addr = signer::address_of(admin);

        move_to(admin, AdminCap {
            admin_address: admin_addr,
        });

        move_to(admin, UserRegistry {
            users: vector::empty(),
            admin: admin_addr,
        });
    }

    /// VULNERABLE: Add user without checking AdminCap
    public entry fun add_user_vulnerable(account: &signer, user: address)
    acquires UserRegistry {
        // VULNERABILITY: No capability check!
        // Should verify account has AdminCap
        // Should have: assert!(exists<AdminCap>(signer::address_of(account)), ERROR_NOT_ADMIN);

        let registry = borrow_global_mut<UserRegistry>(@vulnerable);
        vector::push_back(&mut registry.users, user);
    }

    /// VULNERABLE: Remove user with weak check
    public entry fun remove_user_vulnerable(account: &signer, user: address)
    acquires UserRegistry {
        let account_addr = signer::address_of(account);
        let registry = borrow_global_mut<UserRegistry>(@vulnerable);

        // VULNERABILITY: Only checks admin field, not capability ownership
        // Attacker can pass any account if they know admin address
        assert!(registry.admin == account_addr, 1);

        let (exists, index) = vector::index_of(&registry.users, &user);
        if (exists) {
            vector::remove(&mut registry.users, index);
        };
    }

    /// VULNERABLE: Change admin without capability
    public entry fun change_admin_vulnerable(account: &signer, new_admin: address)
    acquires UserRegistry {
        // VULNERABILITY: No capability check at all
        // Anyone can change the admin!

        let registry = borrow_global_mut<UserRegistry>(@vulnerable);
        registry.admin = new_admin;
    }

    /// VULNERABLE: Execute privileged operation
    public entry fun privileged_operation_vulnerable(account: &signer)
    acquires UserRegistry {
        let account_addr = signer::address_of(account);

        // VULNERABILITY: Checks existence but doesn't verify ownership
        assert!(exists<AdminCap>(account_addr), 2);

        // But doesn't actually require the capability to be passed!
        // Attacker could create their own AdminCap

        let registry = borrow_global_mut<UserRegistry>(@vulnerable);
        // Do privileged operation...
        vector::push_back(&mut registry.users, account_addr);
    }

    /// SECURE VERSION: Proper capability check
    public entry fun add_user_secure(admin: &signer, user: address)
    acquires AdminCap, UserRegistry {
        let admin_addr = signer::address_of(admin);

        // CHECK: Verify admin capability exists
        assert!(exists<AdminCap>(admin_addr), 1); // ERROR_NOT_ADMIN

        // CHECK: Borrow the capability to verify ownership
        let admin_cap = borrow_global<AdminCap>(admin_addr);

        // CHECK: Verify capability is valid
        assert!(admin_cap.admin_address == admin_addr, 2); // ERROR_INVALID_CAP

        let registry = borrow_global_mut<UserRegistry>(@vulnerable);

        // CHECK: Double-check registry admin matches
        assert!(registry.admin == admin_addr, 3); // ERROR_NOT_REGISTRY_ADMIN

        vector::push_back(&mut registry.users, user);
    }

    /// EVEN MORE SECURE: Pass capability as parameter
    public fun add_user_with_cap(_admin_cap: &AdminCap, user: address)
    acquires UserRegistry {
        // By requiring AdminCap as parameter, caller MUST have it
        // This is the most secure pattern

        let registry = borrow_global_mut<UserRegistry>(@vulnerable);
        vector::push_back(&mut registry.users, user);
    }
}

/*
 * CAPABILITY PATTERNS IN MOVE:
 *
 * 1. Capability as Proof: Require capability as function parameter
 * 2. Capability Storage: Store capabilities in resources
 * 3. Capability Transfer: Use 'store' ability to transfer capabilities
 * 4. Capability Checking: Always verify capability ownership
 */

/*
 * EXPLOIT SCENARIO:
 *
 * Scenario 1: No Capability Check
 * 1. Admin initializes registry
 * 2. Attacker calls add_user_vulnerable(attacker_signer, attacker_address)
 * 3. No capability check performed
 * 4. Attacker added to privileged user list
 *
 * Scenario 2: Weak Capability Check
 * 1. Admin address is public: 0xADMIN
 * 2. Attacker creates their own AdminCap resource
 * 3. Attacker calls privileged_operation_vulnerable(attacker_signer)
 * 4. Function checks exists<AdminCap> but not if it's the legitimate one
 * 5. Attacker's fake capability accepted
 *
 * Scenario 3: Change Admin
 * 1. Admin has registry with valuable privileges
 * 2. Attacker calls change_admin_vulnerable(attacker_signer, attacker_address)
 * 3. No capability check at all
 * 4. Admin changed to attacker
 * 5. Attacker now has full admin access
 */

/*
 * SECURE PATTERNS:
 *
 * Best Practice #1: Require capability as parameter
 * ```move
 * public fun privileged_op(admin_cap: &AdminCap) {
 *     // Caller MUST have AdminCap to call this
 * }
 * ```
 *
 * Best Practice #2: Store capability at module level
 * ```move
 * public entry fun privileged_op(admin: &signer) acquires AdminCap {
 *     let admin_addr = signer::address_of(admin);
 *     assert!(exists<AdminCap>(admin_addr), ERROR);
 *     let cap = borrow_global<AdminCap>(admin_addr);
 *     // Verify cap is legitimate
 * }
 * ```
 *
 * Best Practice #3: Use witness pattern for one-time operations
 * ```move
 * struct Witness has drop {}
 *
 * public fun init(witness: Witness) {
 *     // Can only be called once with witness
 * }
 * ```
 */
