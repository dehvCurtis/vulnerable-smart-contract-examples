/*
 * VULNERABLE MOVE MODULE - DO NOT USE IN PRODUCTION
 *
 * Unsafe Resource Handling Vulnerabilities
 *
 * Move's resource safety prevents many bugs, but improper resource
 * management can still lead to loss of assets or broken functionality.
 */

module vulnerable::unsafe_resource_handling {
    use std::signer;
    use std::option::{Self, Option};

    /// A resource representing coins
    struct Coin has store {
        value: u64,
    }

    /// A vault for holding coins
    struct Vault has key {
        coins: Coin,
        owner: address,
    }

    /// VULNERABLE: Doesn't handle the case where vault already exists
    public entry fun create_vault_vulnerable(account: &signer, initial_amount: u64) {
        let account_addr = signer::address_of(account);

        // VULNERABILITY: If vault already exists, this will abort
        // Attacker can DoS by creating vault for victim first
        // Should check: assert!(!exists<Vault>(account_addr), ERROR_ALREADY_EXISTS);

        move_to(account, Vault {
            coins: Coin { value: initial_amount },
            owner: account_addr,
        });
    }

    /// VULNERABLE: Moves resource without proper checks
    public entry fun merge_vaults_vulnerable(
        account: &signer,
        other_vault_addr: address
    ) acquires Vault {
        let account_addr = signer::address_of(account);

        // VULNERABILITY: No check that account owns both vaults
        // Could drain other user's vault

        let other_vault = move_from<Vault>(other_vault_addr);
        let Vault { coins: other_coins, owner: _ } = other_vault;

        let my_vault = borrow_global_mut<Vault>(account_addr);
        my_vault.coins.value = my_vault.coins.value + other_coins.value;

        // other_coins automatically destroyed (correct)
    }

    /// VULNERABLE: Destroys resource without transferring value
    public entry fun close_vault_vulnerable(account: &signer) acquires Vault {
        let account_addr = signer::address_of(account);

        let vault = move_from<Vault>(account_addr);

        // VULNERABILITY: Vault destroyed, coins lost!
        // Should transfer coins out first
        let Vault { coins, owner: _ } = vault;

        // coins dropped here - value lost forever!
    }

    /// Resource with optional inner resource
    struct Container has key {
        inner: Option<Coin>,
        owner: address,
    }

    /// VULNERABLE: Doesn't handle None case properly
    public entry fun withdraw_from_container_vulnerable(account: &signer)
    acquires Container {
        let account_addr = signer::address_of(account);
        let container = borrow_global_mut<Container>(account_addr);

        // VULNERABILITY: Doesn't check if inner is Some before extracting
        // Will abort if None
        let coin = option::extract(&mut container.inner);

        // Use coin...
    }

    /// VULNERABLE: Double extraction possible
    public entry fun extract_twice_vulnerable(account: &signer)
    acquires Container {
        let account_addr = signer::address_of(account);
        let container = borrow_global_mut<Container>(account_addr);

        // VULNERABILITY: No check if already extracted
        if (option::is_some(&container.inner)) {
            let coin1 = option::extract(&mut container.inner);

            // Logic error - trying to extract again will fail
            // but function doesn't handle it properly
            let coin2 = option::extract(&mut container.inner); // ABORTS

            // Can't reach here
        };
    }

    /// Nested resource structure
    struct Treasury has key {
        vaults: vector<Vault>,
    }

    /// VULNERABLE: Doesn't properly handle vector of resources
    public entry fun drain_treasury_vulnerable(account: &signer)
    acquires Treasury {
        let account_addr = signer::address_of(account);

        let treasury = move_from<Treasury>(account_addr);
        let Treasury { vaults } = treasury;

        // VULNERABILITY: Vector of resources not properly handled
        // If function aborts here, resources could be lost

        // This is problematic - resources in vector need careful handling
        // Should iterate and properly destroy each vault
    }

    /// SECURE VERSION: Proper vault creation with checks
    public entry fun create_vault_secure(account: &signer, initial_amount: u64) {
        let account_addr = signer::address_of(account);

        // CHECK: Ensure vault doesn't already exist
        assert!(!exists<Vault>(account_addr), 1); // ERROR_ALREADY_EXISTS

        move_to(account, Vault {
            coins: Coin { value: initial_amount },
            owner: account_addr,
        });
    }

    /// SECURE VERSION: Safe vault merging with ownership checks
    public entry fun merge_vaults_secure(
        account: &signer,
        other_vault_addr: address
    ) acquires Vault {
        let account_addr = signer::address_of(account);

        // CHECK: Verify both vaults exist
        assert!(exists<Vault>(account_addr), 2);
        assert!(exists<Vault>(other_vault_addr), 3);

        // CHECK: Verify ownership of the vault being merged
        let other_vault_ref = borrow_global<Vault>(other_vault_addr);
        assert!(other_vault_ref.owner == account_addr, 4); // ERROR_NOT_OWNER

        // Now safe to merge
        let other_vault = move_from<Vault>(other_vault_addr);
        let Vault { coins: other_coins, owner: _ } = other_vault;

        let my_vault = borrow_global_mut<Vault>(account_addr);
        my_vault.coins.value = my_vault.coins.value + other_coins.value;
    }

    /// SECURE VERSION: Close vault with value preservation
    public entry fun close_vault_secure(account: &signer): u64 acquires Vault {
        let account_addr = signer::address_of(account);

        assert!(exists<Vault>(account_addr), 5);

        let vault = move_from<Vault>(account_addr);
        let Vault { coins, owner: _ } = vault;

        // Extract and return value before destroying
        let value = coins.value;

        // Coin destroyed properly (Move ensures this)

        value // Return value to caller
    }

    /// SECURE VERSION: Safe optional resource handling
    public entry fun withdraw_from_container_secure(account: &signer): u64
    acquires Container {
        let account_addr = signer::address_of(account);

        assert!(exists<Container>(account_addr), 6);

        let container = borrow_global_mut<Container>(account_addr);

        // CHECK: Verify inner exists before extracting
        assert!(option::is_some(&container.inner), 7); // ERROR_EMPTY_CONTAINER

        let coin = option::extract(&mut container.inner);
        let value = coin.value;

        // Properly handle coin before returning
        value
    }

    /// SECURE VERSION: Proper destruction with value extraction
    public entry fun destroy_coin(coin: Coin): u64 {
        let Coin { value } = coin;
        value
    }
}

/*
 * MOVE'S RESOURCE SAFETY:
 *
 * Move enforces resource safety through the type system:
 * 1. Resources cannot be copied (no 'copy' ability)
 * 2. Resources cannot be dropped (no 'drop' ability)
 * 3. Resources must be explicitly moved or destroyed
 * 4. Compiler ensures resources are properly handled
 *
 * However, logical errors can still occur:
 * - Moving resources without proper authorization
 * - Destroying resources without extracting value
 * - Improper handling of optional resources
 * - Complex nested resource structures
 */

/*
 * EXPLOIT SCENARIOS:
 *
 * DoS via Existing Resource:
 * 1. Attacker creates vault for victim's address
 * 2. Victim tries to create their vault
 * 3. move_to fails because resource already exists
 * 4. Victim cannot use the protocol
 *
 * Unauthorized Resource Merge:
 * 1. Victim has vault with 100 coins at 0xVICTIM
 * 2. Attacker calls merge_vaults_vulnerable(attacker, 0xVICTIM)
 * 3. Function doesn't check ownership
 * 4. Victim's vault merged into attacker's
 * 5. Attacker steals 100 coins
 *
 * Value Loss Through Destruction:
 * 1. User has vault with 1000 coins
 * 2. User calls close_vault_vulnerable
 * 3. Vault moved out and destructured
 * 4. Coins destructured but value not preserved
 * 5. 1000 coins lost forever
 */

/*
 * BEST PRACTICES:
 *
 * 1. Always check resource existence before move_to
 * 2. Verify ownership before moving resources
 * 3. Extract value before destroying resources
 * 4. Handle Option<Resource> carefully with is_some check
 * 5. Be careful with vectors of resources
 * 6. Document resource lifecycle clearly
 * 7. Test resource cleanup paths thoroughly
 * 8. Use Move's type system to enforce constraints
 */
