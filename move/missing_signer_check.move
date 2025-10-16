/*
 * VULNERABLE MOVE MODULE - DO NOT USE IN PRODUCTION
 *
 * Missing Signer Check Vulnerability
 *
 * This module fails to verify that the caller has proper authorization,
 * allowing unauthorized users to perform privileged operations.
 */

module vulnerable::missing_signer_check {
    use std::signer;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;

    struct Vault has key {
        owner: address,
        balance: u64,
    }

    /// Initialize a vault for a user
    public entry fun initialize(account: &signer) {
        let owner = signer::address_of(account);
        move_to(account, Vault {
            owner,
            balance: 0,
        });
    }

    /// VULNERABLE: Deposit without proper signer verification
    /// Anyone can deposit to any vault
    public entry fun deposit(depositor: &signer, vault_owner: address, amount: u64)
    acquires Vault {
        // VULNERABILITY: Doesn't verify that depositor has authorization
        // or that vault_owner is the signer

        let vault = borrow_global_mut<Vault>(vault_owner);
        vault.balance = vault.balance + amount;

        // Transfer coins from depositor
        let coins = coin::withdraw<AptosCoin>(depositor, amount);
        coin::deposit(vault_owner, coins);
    }

    /// VULNERABLE: Withdraw without verifying signer is the owner
    public entry fun withdraw(account: &signer, vault_owner: address, amount: u64)
    acquires Vault {
        // VULNERABILITY: No check that account is actually the vault owner!
        // Anyone can call this with any vault_owner address
        // Should have: assert!(signer::address_of(account) == vault_owner, ERROR_NOT_OWNER);

        let vault = borrow_global_mut<Vault>(vault_owner);

        // VULNERABILITY: No balance check
        vault.balance = vault.balance - amount;

        // Transfer coins to caller (who might not be the owner!)
        let coins = coin::withdraw<AptosCoin>(account, amount);
        coin::deposit(signer::address_of(account), coins);
    }

    /// VULNERABLE: Change owner without verification
    public entry fun change_owner(account: &signer, vault_owner: address, new_owner: address)
    acquires Vault {
        // VULNERABILITY: No check that account is the current owner
        // Anyone can take over anyone else's vault!

        let vault = borrow_global_mut<Vault>(vault_owner);
        vault.owner = new_owner;
    }

    /// SECURE VERSION: Proper signer verification
    public entry fun withdraw_secure(account: &signer, amount: u64)
    acquires Vault {
        let account_addr = signer::address_of(account);

        // CHECK: Verify signer is the vault owner
        assert!(exists<Vault>(account_addr), 1); // ERROR_VAULT_NOT_FOUND

        let vault = borrow_global_mut<Vault>(account_addr);

        // CHECK: Verify account owns the vault
        assert!(vault.owner == account_addr, 2); // ERROR_NOT_OWNER

        // CHECK: Verify sufficient balance
        assert!(vault.balance >= amount, 3); // ERROR_INSUFFICIENT_BALANCE

        vault.balance = vault.balance - amount;

        let coins = coin::withdraw<AptosCoin>(account, amount);
        coin::deposit(account_addr, coins);
    }
}

/*
 * EXPLOIT SCENARIO:
 *
 * 1. Alice creates a vault with 100 APT deposited
 * 2. Bob (attacker) calls withdraw(bob_signer, alice_address, 100)
 * 3. Function doesn't verify that bob_signer owns alice's vault
 * 4. Alice's vault balance decremented
 * 5. Coins transferred to Bob
 * 6. Bob stole 100 APT from Alice
 *
 * CHANGE OWNER ATTACK:
 * 1. Alice has vault with 100 APT
 * 2. Bob calls change_owner(bob_signer, alice_address, bob_address)
 * 3. Function doesn't verify Bob owns the vault
 * 4. Vault owner changed to Bob
 * 5. Bob now owns Alice's vault and funds
 */

/*
 * SECURE PATTERNS:
 *
 * 1. Always verify signer owns the resource
 * 2. Use signer::address_of() to get caller's address
 * 3. Check ownership before modifications
 * 4. Use assertions with clear error codes
 * 5. Consider using capabilities for authorization
 */
