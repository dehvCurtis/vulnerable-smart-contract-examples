/*
 * VULNERABLE MOVE MODULE - DO NOT USE IN PRODUCTION
 *
 * Timestamp Dependence Vulnerability
 *
 * This module relies on block timestamps for critical logic,
 * which can be manipulated by validators within certain bounds.
 */

module vulnerable::timestamp_dependence {
    use std::signer;
    use std::vector;
    use aptos_framework::timestamp;
    use aptos_framework::transaction_context;

    struct Lottery has key {
        participants: vector<address>,
        prize_pool: u64,
        end_time: u64,
    }

    struct TimeLock has key {
        locked_until: u64,
        amount: u64,
    }

    struct Auction has key {
        highest_bidder: address,
        highest_bid: u64,
        end_time: u64,
    }

    /// VULNERABLE: Uses timestamp for lottery winner selection
    public entry fun start_lottery(account: &signer, duration: u64) {
        let current_time = timestamp::now_seconds();

        move_to(account, Lottery {
            participants: vector::empty(),
            prize_pool: 0,
            end_time: current_time + duration,
        });
    }

    public entry fun enter_lottery(account: &signer, lottery_addr: address)
    acquires Lottery {
        let lottery = borrow_global_mut<Lottery>(lottery_addr);
        let participant = signer::address_of(account);

        vector::push_back(&mut lottery.participants, participant);
    }

    /// VULNERABLE: Timestamp-based randomness
    public entry fun draw_winner(account: &signer)
    acquires Lottery {
        let account_addr = signer::address_of(account);
        let lottery = borrow_global_mut<Lottery>(account_addr);
        let current_time = timestamp::now_seconds();

        // VULNERABILITY: Check if lottery ended
        assert!(current_time >= lottery.end_time, 1);

        let num_participants = vector::length(&lottery.participants);
        assert!(num_participants > 0, 2);

        // VULNERABILITY: Using timestamp for randomness
        // Validators can manipulate timestamp slightly
        // This makes the outcome predictable/manipulable
        let random_index = (current_time % (num_participants as u64)) as u64;

        let winner = *vector::borrow(&lottery.participants, random_index);
        // Transfer prize to winner (simplified)
    }

    /// VULNERABLE: Time-based access control
    public entry fun create_timelock(account: &signer, lock_duration: u64, amount: u64) {
        let current_time = timestamp::now_seconds();

        move_to(account, TimeLock {
            locked_until: current_time + lock_duration,
            amount,
        });
    }

    public entry fun withdraw_timelock(account: &signer)
    acquires TimeLock {
        let account_addr = signer::address_of(account);
        let timelock = borrow_global_mut<TimeLock>(account_addr);
        let current_time = timestamp::now_seconds();

        // VULNERABILITY: Timestamp-based security
        // Validator can manipulate timestamp to allow early withdrawal
        assert!(current_time >= timelock.locked_until, 3);

        // Withdraw logic...
        timelock.amount = 0;
    }

    /// VULNERABLE: Auction with timestamp manipulation
    public entry fun start_auction(account: &signer, duration: u64) {
        let current_time = timestamp::now_seconds();
        let account_addr = signer::address_of(account);

        move_to(account, Auction {
            highest_bidder: account_addr,
            highest_bid: 0,
            end_time: current_time + duration,
        });
    }

    public entry fun place_bid(account: &signer, auction_addr: address, bid: u64)
    acquires Auction {
        let current_time = timestamp::now_seconds();
        let auction = borrow_global_mut<Auction>(auction_addr);

        // VULNERABILITY: Timestamp check can be manipulated
        // Validator could extend auction slightly for their own bid
        assert!(current_time < auction.end_time, 4);

        assert!(bid > auction.highest_bid, 5);

        auction.highest_bidder = signer::address_of(account);
        auction.highest_bid = bid;
    }

    /// VULNERABLE: Time-based rate limiting
    struct RateLimit has key {
        last_action: u64,
        cooldown: u64,
    }

    public entry fun rate_limited_action(account: &signer)
    acquires RateLimit {
        let account_addr = signer::address_of(account);
        let current_time = timestamp::now_seconds();

        if (!exists<RateLimit>(account_addr)) {
            move_to(account, RateLimit {
                last_action: 0,
                cooldown: 3600, // 1 hour
            });
        };

        let rate_limit = borrow_global_mut<RateLimit>(account_addr);

        // VULNERABILITY: Timestamp-based cooldown
        // Can be bypassed if validator manipulates timestamp
        let time_since_last = current_time - rate_limit.last_action;
        assert!(time_since_last >= rate_limit.cooldown, 6);

        rate_limit.last_action = current_time;

        // Perform rate-limited action...
    }

    /// VULNERABLE: Predictable randomness using transaction hash
    public fun generate_random_vulnerable(): u64 {
        let current_time = timestamp::now_seconds();

        // VULNERABILITY: Using timestamp and transaction context for randomness
        // All these values are predictable by validators
        let random_seed = current_time;

        random_seed % 100
    }

    /// BETTER (but still not perfect): Use VRF or oracle
    /// This is a placeholder - real implementation would use Aptos Randomness API
    /// or an oracle like Switchboard
    public entry fun draw_winner_better(account: &signer)
    acquires Lottery {
        let account_addr = signer::address_of(account);
        let lottery = borrow_global_mut<Lottery>(account_addr);
        let current_time = timestamp::now_seconds();

        assert!(current_time >= lottery.end_time, 1);

        let num_participants = vector::length(&lottery.participants);
        assert!(num_participants > 0, 2);

        // BETTER: Use Aptos Randomness API (when available)
        // Or oracle-based randomness like Switchboard
        // For now, showing concept:

        // Still using timestamp but with additional entropy
        // This is NOT production-ready!
        let entropy = current_time;
        let random_index = (entropy % (num_participants as u64)) as u64;

        let winner = *vector::borrow(&lottery.participants, random_index);
    }

    /// SECURE PATTERN: Commit-Reveal scheme
    struct Commitment has key {
        commitment: vector<u8>,
        revealed: bool,
    }

    public entry fun commit(account: &signer, commitment_hash: vector<u8>) {
        move_to(account, Commitment {
            commitment: commitment_hash,
            revealed: false,
        });
    }

    public entry fun reveal(account: &signer, value: u64, salt: vector<u8>)
    acquires Commitment {
        let account_addr = signer::address_of(account);
        let commitment = borrow_global_mut<Commitment>(account_addr);

        // Verify commitment matches reveal
        // let hash = hash(value + salt);
        // assert!(hash == commitment.commitment, 7);

        commitment.revealed = true;

        // Use revealed value...
    }
}

/*
 * TIMESTAMP MANIPULATION ON APTOS:
 *
 * - Block timestamps can be manipulated by validators
 * - Typically within small window (seconds)
 * - But enough to affect outcomes
 * - Never use for critical randomness or security
 */

/*
 * EXPLOIT SCENARIOS:
 *
 * Lottery Manipulation:
 * 1. Attacker is validator or colludes with validator
 * 2. Attacker enters lottery
 * 3. When drawing time comes, validator adjusts timestamp
 * 4. Timestamp % participants lands on attacker's index
 * 5. Attacker wins unfairly
 *
 * Timelock Bypass:
 * 1. User locks funds for 1 hour
 * 2. User is also a validator
 * 3. User sets block timestamp forward by 1 hour
 * 4. Timelock check passes
 * 5. User withdraws early
 *
 * Auction Extension:
 * 1. Auction ending soon
 * 2. Attacker validator places bid
 * 3. Validator sets timestamp slightly back
 * 4. Auction still "open" for attacker's bid
 * 5. Legitimate late bidders can't participate
 */

/*
 * BEST PRACTICES:
 *
 * 1. Never use timestamps for randomness
 * 2. Use Aptos Randomness API or oracle for random numbers
 * 3. Use commit-reveal schemes for fair ordering
 * 4. Timestamps OK for:
 *    - Non-critical ordering
 *    - Rough time checks (not security-critical)
 *    - Event logging
 * 5. Timestamps NOT OK for:
 *    - Randomness generation
 *    - Critical security checks
 *    - Precise access control
 *    - Winner selection
 *
 * 6. Consider using:
 *    - Block height instead of timestamp when possible
 *    - Commit-reveal schemes
 *    - VRF (Verifiable Random Function)
 *    - Oracle-based randomness
 */
