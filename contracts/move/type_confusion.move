/*
 * VULNERABLE MOVE MODULE - DO NOT USE IN PRODUCTION
 *
 * Type Confusion Vulnerabilities
 *
 * Move's strong type system prevents many type errors, but logical
 * type confusion can still occur through generic type parameters
 * and improper validation.
 */

module vulnerable::type_confusion {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;

    /// Generic vault that can hold any coin type
    struct Vault<phantom CoinType> has key {
        coins: Coin<CoinType>,
        owner: address,
    }

    /// A fake coin type an attacker might create
    struct FakeCoin has store {}

    /// VULNERABLE: No verification of coin type
    public entry fun create_vault<CoinType>(account: &signer, amount: u64) {
        let account_addr = signer::address_of(account);

        // VULNERABILITY: Accepts any CoinType without validation
        // Attacker could use FakeCoin or other malicious types

        let coins = coin::withdraw<CoinType>(account, amount);

        move_to(account, Vault<CoinType> {
            coins,
            owner: account_addr,
        });
    }

    /// VULNERABLE: Type confusion in withdrawal
    public entry fun withdraw_wrong_type<RequestedType>(
        account: &signer,
        vault_addr: address,
        amount: u64
    ) acquires Vault {
        // VULNERABILITY: No check that RequestedType matches vault's type
        // If vault is Vault<AptosCoin> but caller requests Vault<FakeCoin>,
        // Move's type system catches this at compile time
        // But in complex scenarios with type wrapping, issues can occur

        let vault = borrow_global_mut<Vault<RequestedType>>(vault_addr);

        // This would fail if types don't match, but vulnerability
        // is in the logic that allows reaching this point
    }

    /// Wrapper type that could cause confusion
    struct WrappedCoin<phantom T> has key, store {
        inner: Coin<T>,
    }

    /// VULNERABLE: Type wrapping without validation
    public entry fun wrap_coin<CoinType>(
        account: &signer,
        amount: u64
    ) {
        // VULNERABILITY: Wraps coin without verifying CoinType is legitimate
        let coin = coin::withdraw<CoinType>(account, amount);

        move_to(account, WrappedCoin<CoinType> {
            inner: coin,
        });
    }

    /// VULNERABLE: Unwrapping with different type parameter
    public entry fun unwrap_confused<WrongType>(
        account: &signer
    ) acquires WrappedCoin {
        let account_addr = signer::address_of(account);

        // VULNERABILITY: If caller provides wrong WrongType,
        // Move catches at compile time, but logic flow is unclear

        // This demonstrates that type confusion is mostly caught by Move
        // but can lead to runtime errors if not properly handled
        let wrapped = move_from<WrappedCoin<WrongType>>(account_addr);
        let WrappedCoin { inner } = wrapped;

        coin::deposit(account_addr, inner);
    }

    /// Generic pool with type confusion potential
    struct Pool<phantom X, phantom Y> has key {
        reserve_x: Coin<X>,
        reserve_y: Coin<Y>,
    }

    /// VULNERABLE: Pool creation without type validation
    public entry fun create_pool<X, Y>(
        account: &signer,
        amount_x: u64,
        amount_y: u64
    ) {
        // VULNERABILITY: No validation that X and Y are legitimate coin types
        // No check that X != Y (creating pool with same type)

        let coin_x = coin::withdraw<X>(account, amount_x);
        let coin_y = coin::withdraw<Y>(account, amount_y);

        move_to(account, Pool<X, Y> {
            reserve_x: coin_x,
            reserve_y: coin_y,
        });
    }

    /// VULNERABLE: Swap with reversed type parameters
    public entry fun swap_confused<X, Y>(
        account: &signer,
        pool_addr: address,
        amount_in: u64
    ) acquires Pool {
        // VULNERABILITY: Caller might reverse X and Y types
        // Function should validate type order or handle both directions

        // If pool is Pool<AptosCoin, USDC> but caller uses Pool<USDC, AptosCoin>,
        // borrow_global fails at runtime (Move catches this)
        // But error message might be confusing

        let pool = borrow_global_mut<Pool<X, Y>>(pool_addr);
        // Swap logic...
    }

    /// Type validation helper
    struct CoinMetadata<phantom CoinType> has key {
        name: vector<u8>,
        verified: bool,
    }

    /// SECURE PATTERN: Whitelist approved coin types
    public entry fun create_vault_secure<CoinType>(
        account: &signer,
        amount: u64
    ) acquires CoinMetadata {
        let account_addr = signer::address_of(account);

        // CHECK: Verify coin type is whitelisted
        assert!(exists<CoinMetadata<CoinType>>(@vulnerable), 1);

        let metadata = borrow_global<CoinMetadata<CoinType>>(@vulnerable);

        // CHECK: Verify coin is verified
        assert!(metadata.verified, 2);

        let coins = coin::withdraw<CoinType>(account, amount);

        move_to(account, Vault<CoinType> {
            coins,
            owner: account_addr,
        });
    }

    /// SECURE PATTERN: Validate pool types
    public entry fun create_pool_secure<X, Y>(
        account: &signer,
        amount_x: u64,
        amount_y: u64
    ) acquires CoinMetadata {
        // CHECK: Both coins must be verified
        assert!(exists<CoinMetadata<X>>(@vulnerable), 3);
        assert!(exists<CoinMetadata<Y>>(@vulnerable), 4);

        let metadata_x = borrow_global<CoinMetadata<X>>(@vulnerable);
        let metadata_y = borrow_global<CoinMetadata<Y>>(@vulnerable);

        assert!(metadata_x.verified, 5);
        assert!(metadata_y.verified, 6);

        // CHECK: X and Y must be different types
        // In Move, this is enforced by type system if types are different
        // But good to document this requirement

        let coin_x = coin::withdraw<X>(account, amount_x);
        let coin_y = coin::withdraw<Y>(account, amount_y);

        move_to(account, Pool<X, Y> {
            reserve_x: coin_x,
            reserve_y: coin_y,
        });
    }
}

/*
 * MOVE'S TYPE SAFETY:
 *
 * Move has strong type safety:
 * - Generics are checked at compile time
 * - Type parameters must match exactly
 * - No runtime type casting
 * - Phantom types for type-level constraints
 *
 * However, logical errors can still occur:
 * - Using wrong type parameters
 * - Not validating coin types are legitimate
 * - Type wrapping confusion
 * - Unclear error messages from type mismatches
 */

/*
 * EXPLOIT SCENARIOS:
 *
 * Fake Coin Attack:
 * 1. Attacker creates FakeCoin type
 * 2. Attacker calls create_vault<FakeCoin>
 * 3. No validation that FakeCoin is legitimate
 * 4. Vault created with worthless fake coins
 * 5. If protocol treats all vaults equally, accounting breaks
 *
 * Type Parameter Reversal:
 * 1. Pool exists as Pool<AptosCoin, USDC>
 * 2. User accidentally calls swap_confused<USDC, AptosCoin>
 * 3. Types reversed
 * 4. borrow_global fails at runtime
 * 5. Poor user experience, potential loss of gas
 *
 * Type Wrapping Confusion:
 * 1. User wraps AptosCoin as WrappedCoin<AptosCoin>
 * 2. User tries to unwrap as WrappedCoin<USDC>
 * 3. Type mismatch caught at compile/runtime
 * 4. Funds stuck if user doesn't understand error
 */

/*
 * BEST PRACTICES:
 *
 * 1. Whitelist approved coin types
 * 2. Verify coin types have proper metadata
 * 3. Use phantom types for type-level constraints
 * 4. Document expected type parameters clearly
 * 5. Validate type parameter relationships
 * 6. Provide clear error messages for type mismatches
 * 7. Consider using type aliases for clarity
 * 8. Test with various type parameters
 * 9. Use Move's type system to enforce constraints
 * 10. Educate users on proper type parameter usage
 *
 * NOTE: Move's type system catches most type confusion at compile time,
 * making it much safer than dynamically typed systems. The main risk
 * is logical errors in type parameter usage, not runtime type confusion.
 */
