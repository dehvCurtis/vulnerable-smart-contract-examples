// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Remaining Security Patterns
 * @notice Tests remaining specialized and niche security detectors
 * @dev Tests: optimistic rollups, oracle staleness, readonly reentrancy,
 *             transient storage, emergency functions, vault attacks, weak patterns, etc.
 */

// =====================================================================
// 1. OPTIMISTIC ROLLUP CHALLENGES
// =====================================================================

/**
 * @dev Optimistic rollup with challenge period bypass
 */
contract VulnerableOptimisticRollup {
    struct Withdrawal {
        address user;
        uint256 amount;
        uint256 timestamp;
        bool finalized;
    }

    mapping(bytes32 => Withdrawal) public withdrawals;
    uint256 public constant CHALLENGE_PERIOD = 7 days;

    // ❌ VULNERABILITY 1: Challenge period bypass
    function finalizeWithdrawal(bytes32 withdrawalId) external {
        // ❌ CRITICAL: No challenge period enforcement
        // ❌ Should require: block.timestamp >= withdrawal.timestamp + CHALLENGE_PERIOD
        // ❌ Anyone can finalize immediately

        Withdrawal storage withdrawal = withdrawals[withdrawalId];
        require(!withdrawal.finalized, "Already finalized");

        withdrawal.finalized = true;
        payable(withdrawal.user).transfer(withdrawal.amount);

        // ❌ Missing: Challenge period validation
        // ❌ Missing: Fraud proof verification
    }

    // ❌ VULNERABILITY 2: Fraud proof timing manipulation
    function submitFraudProof(bytes32 withdrawalId, bytes calldata proof) external {
        // ❌ No timestamp validation
        // ❌ Fraud proofs can be submitted too late
        // ❌ No deadline enforcement

        Withdrawal storage withdrawal = withdrawals[withdrawalId];

        // Process fraud proof without timing checks
        // ❌ Missing: require(block.timestamp <= withdrawal.timestamp + CHALLENGE_PERIOD)
    }

    // ❌ VULNERABILITY 3: Early withdrawal without challenge window
    function quickWithdraw(bytes32 withdrawalId) external {
        // ❌ CRITICAL: Bypasses challenge period entirely
        Withdrawal storage withdrawal = withdrawals[withdrawalId];

        // Immediate finalization
        withdrawal.finalized = true;
        payable(withdrawal.user).transfer(withdrawal.amount);
    }
}

// =====================================================================
// 2. ORACLE STALENESS & PRICE VALIDATION
// =====================================================================

/**
 * @dev Oracle with staleness and validation issues
 */
contract VulnerableOracleStale {
    struct PriceData {
        uint256 price;
        uint256 timestamp;
        uint256 heartbeat;
    }

    mapping(address => PriceData) public prices;

    // ❌ VULNERABILITY 1: No staleness check (heartbeat)
    function getPrice(address token) external view returns (uint256) {
        // ❌ CRITICAL: No heartbeat validation
        // ❌ Stale prices can be used
        // ❌ Should check: block.timestamp - price.timestamp <= heartbeat

        return prices[token].price;

        // ❌ Missing: Staleness validation
        // ❌ Missing: Oracle liveness check
    }

    // ❌ VULNERABILITY 2: Missing price validation
    function swap(address tokenIn, address tokenOut, uint256 amountIn) external {
        // ❌ No price reasonableness check
        // ❌ No circuit breaker
        // ❌ No sanity checks

        uint256 priceIn = prices[tokenIn].price;
        uint256 priceOut = prices[tokenOut].price;

        // ❌ Missing: require(priceIn > 0 && priceIn < MAX_PRICE)
        // ❌ Missing: Price deviation check
        // ❌ Missing: Staleness validation

        uint256 amountOut = (amountIn * priceIn) / priceOut;

        // Process swap without validation
    }

    // ❌ VULNERABILITY 3: Stale oracle data usage
    function liquidate(address user, address collateral, address debt) external {
        // ❌ Uses potentially stale prices
        PriceData memory collateralPrice = prices[collateral];
        PriceData memory debtPrice = prices[debt];

        // ❌ No heartbeat check
        // ❌ No timestamp validation
        // ❌ Stale prices can cause incorrect liquidations

        uint256 collateralValue = 1000 * collateralPrice.price;
        uint256 debtValue = 500 * debtPrice.price;

        // Liquidation logic without staleness check
    }
}

// =====================================================================
// 3. READONLY REENTRANCY
// =====================================================================

/**
 * @dev Vault vulnerable to readonly reentrancy
 */
contract VulnerableReadonlyReentrancy {
    mapping(address => uint256) public balances;
    uint256 public totalShares;
    uint256 public totalAssets;

    // ❌ VULNERABILITY: Readonly reentrancy in view function
    function getShareValue() public view returns (uint256) {
        // ❌ CRITICAL: View function called during state changes
        // ❌ Can be reentered to read inconsistent state
        // ❌ Returns outdated share price

        if (totalShares == 0) return 0;

        // ❌ This can be called during withdrawal to get wrong price
        return (totalAssets * 1e18) / totalShares;
    }

    // Withdrawal that allows readonly reentrancy
    function withdraw(uint256 shares) external {
        // Update state
        balances[msg.sender] -= shares;
        totalShares -= shares;

        // ❌ External call before state is fully updated
        // ❌ Allows getShareValue() to be called with inconsistent state
        (bool success,) = msg.sender.call("");
        require(success);

        // Update more state after external call
        totalAssets -= shares;

        // ❌ Between the two state updates, getShareValue() is wrong
    }
}

// =====================================================================
// 4. TRANSIENT STORAGE EDGE CASES
// =====================================================================

/**
 * @dev Transient storage misuse and edge cases
 */
contract VulnerableTransientStorage {
    // ❌ VULNERABILITY 1: Transient storage state leak
    function processWithTransient() external {
        // ❌ Transient storage can leak across calls
        // ❌ No proper cleanup

        assembly {
            tstore(0, caller())
            tstore(1, callvalue())
        }

        // External call
        (bool success,) = msg.sender.call("");

        // ❌ Transient storage values may persist
        // ❌ Missing: Explicit cleanup after use
    }

    // ❌ VULNERABILITY 2: Transient reentrancy guard issues
    function guardedOperation() external {
        // ❌ Transient guard without proper checks
        assembly {
            let guard := tload(0)
            if eq(guard, 1) {
                revert(0, 0)
            }
            tstore(0, 1)
        }

        // External call
        (bool success,) = msg.sender.call("");

        // ❌ Guard not properly cleared
        // ❌ Missing: tstore(0, 0) cleanup
    }

    // ❌ VULNERABILITY 3: Transient storage composability issue
    function complexOperation() external {
        // ❌ Multiple transient storage slots used
        // ❌ Composability issues with other contracts

        assembly {
            tstore(0, 100)
            tstore(1, 200)
        }

        // Calls to other contracts
        // ❌ Other contracts may overwrite transient storage
        // ❌ No isolation between operations
    }

    // ❌ VULNERABILITY 4: Transient storage misuse
    function saveStateTemporarily(uint256 value) external {
        // ❌ Using transient storage incorrectly
        // ❌ Assuming it persists longer than it does

        assembly {
            tstore(0, value)
        }

        // ❌ Value lost at end of transaction
        // ❌ Misunderstanding transient storage semantics
    }
}

// =====================================================================
// 5. EMERGENCY FUNCTIONS
// =====================================================================

/**
 * @dev Emergency functions with abuse and centralization risks
 */
contract VulnerableEmergencyFunctions {
    address public admin;
    bool public paused;
    mapping(address => uint256) public balances;

    // ❌ VULNERABILITY 1: Emergency function abuse
    function emergencyWithdraw(address token, uint256 amount) external {
        // ❌ CRITICAL: No validation
        // ❌ Admin can drain any funds
        // ❌ No timelock or multisig

        require(msg.sender == admin, "Not admin");

        // ❌ Allows arbitrary withdrawal
        // ❌ No restrictions on what can be withdrawn
        payable(admin).transfer(amount);

        // ❌ Missing: Proper authorization
        // ❌ Missing: Audit trail
    }

    // ❌ VULNERABILITY 2: Emergency pause centralization
    function emergencyPause() external {
        // ❌ Single point of failure
        // ❌ No multisig requirement
        // ❌ Can be abused to freeze funds

        require(msg.sender == admin, "Not admin");
        paused = true;

        // ❌ No timelock
        // ❌ No governance
        // ❌ Centralized control
    }

    // ❌ VULNERABILITY 3: Emergency withdrawal abuse
    function emergencyUserWithdraw(address user) external {
        // ❌ Admin can withdraw user funds
        // ❌ No user consent
        // ❌ Centralization risk

        require(msg.sender == admin, "Not admin");

        uint256 amount = balances[user];
        balances[user] = 0;

        // ❌ Transfers user funds to admin
        payable(admin).transfer(amount);
    }
}

// =====================================================================
// 6. VAULT DONATION ATTACK
// =====================================================================

/**
 * @dev Vault vulnerable to donation attack (share inflation)
 */
contract VulnerableVaultDonation {
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    // ❌ VULNERABILITY: First depositor share inflation via donation
    function deposit(uint256 amount) external {
        uint256 sharesToMint;

        if (totalShares == 0) {
            // ❌ CRITICAL: First deposit vulnerable to inflation attack
            // Attacker can:
            // 1. Deposit 1 wei → Get 1 share
            // 2. Donate large amount directly to contract
            // 3. Next depositor gets 0 shares due to rounding

            sharesToMint = amount;
        } else {
            uint256 balance = address(this).balance;
            // ❌ Uses current balance including donations
            sharesToMint = (amount * totalShares) / balance;
        }

        shares[msg.sender] += sharesToMint;
        totalShares += sharesToMint;

        // ❌ Missing: Virtual shares/assets to prevent inflation
        // ❌ Missing: Minimum deposit amount
    }
}

// =====================================================================
// 7. WEAK COMMIT-REVEAL & WEAK SIGNATURE
// =====================================================================

/**
 * @dev Weak cryptographic patterns
 */
contract VulnerableWeakPatterns {
    mapping(address => bytes32) public commitments;

    // ❌ VULNERABILITY 1: Weak commit-reveal scheme
    function commitBid(uint256 bidAmount) external {
        // ❌ CRITICAL: Predictable commitment
        // ❌ No salt/nonce
        // ❌ Can be brute-forced

        bytes32 commitment = keccak256(abi.encodePacked(bidAmount));
        commitments[msg.sender] = commitment;

        // ❌ Missing: Random salt
        // ❌ Missing: Timestamp validation
        // ❌ Weak: Bidder address not included
    }

    // ❌ VULNERABILITY 2: Weak signature validation
    function processWithSignature(bytes memory signature) external {
        // ❌ No signature malleability check
        // ❌ No nonce validation
        // ❌ Replay possible

        // Simplified signature check
        // ❌ Missing: EIP-712 structured data
        // ❌ Missing: Chain ID
        // ❌ Missing: Nonce
    }
}

// =====================================================================
// 8. ROLE HIERARCHY & PRIVILEGE ESCALATION
// =====================================================================

/**
 * @dev Role hierarchy bypass and privilege escalation
 */
contract VulnerableRoleHierarchy {
    mapping(bytes32 => mapping(address => bool)) public roles;
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN");
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER");
    bytes32 public constant USER_ROLE = keccak256("USER");

    // ❌ VULNERABILITY 1: Role hierarchy bypass
    function grantRole(bytes32 role, address account) external {
        // ❌ CRITICAL: No hierarchy validation
        // ❌ Lower roles can grant higher roles
        // ❌ Privilege escalation possible

        // ❌ Missing: require(hasRole(ADMIN_ROLE, msg.sender))
        // ❌ Missing: Hierarchy checks

        roles[role][account] = true;

        // ❌ USER can grant themselves ADMIN role
    }

    // ❌ VULNERABILITY 2: Multi-role confusion
    function criticalOperation() external {
        // ❌ Unclear role requirements
        // ❌ Multiple roles accepted without clear hierarchy

        require(
            roles[ADMIN_ROLE][msg.sender] || roles[MANAGER_ROLE][msg.sender], "Not authorized"
        );

        // ❌ Which role is actually required?
        // ❌ MANAGER might not be appropriate
    }

    // ❌ VULNERABILITY 3: Privilege escalation path
    function promoteUser(address user) external {
        // ❌ Manager can promote to admin
        // ❌ No proper authorization

        require(roles[MANAGER_ROLE][msg.sender], "Not manager");

        // ❌ CRITICAL: Manager promoting to admin
        roles[ADMIN_ROLE][user] = true;
    }
}

// =====================================================================
// 9. AVS (ACTIVELY VALIDATED SERVICES) VALIDATION
// =====================================================================

/**
 * @dev AVS validation bypass (EigenLayer pattern)
 */
contract VulnerableAVSValidation {
    mapping(address => bool) public validators;
    mapping(bytes32 => bool) public validatedTasks;

    // ❌ VULNERABILITY: AVS validation bypass
    function submitTaskResult(bytes32 taskId, bytes calldata result, bytes calldata proof)
        external
    {
        // ❌ CRITICAL: No validator set verification
        // ❌ Anyone can submit results
        // ❌ No quorum check

        // ❌ Missing: Validator stake check
        // ❌ Missing: Quorum validation
        // ❌ Missing: Proof verification

        validatedTasks[taskId] = true;

        // ❌ Should verify:
        // 1. Validator is registered and staked
        // 2. Sufficient validators signed
        // 3. Proof is valid
        // 4. Task is within validation period
    }
}

// =====================================================================
// 10. ADDITIONAL PATTERNS
// =====================================================================

/**
 * @dev Storage predictability and other edge cases
 */
contract VulnerableStoragePredictability {
    mapping(address => uint256) private balances;
    uint256 private nonce;

    // ❌ VULNERABILITY: Predictable storage slot
    function generateRandomSlot() external view returns (uint256) {
        // ❌ Storage slots are predictable
        // ❌ Can be calculated off-chain

        return uint256(keccak256(abi.encodePacked(address(this), nonce)));

        // ❌ Missing: Unpredictable entropy source
    }
}

/**
 * @dev Short address attack
 */
contract VulnerableShortAddress {
    // ❌ VULNERABILITY: No address validation
    function transfer(address to, uint256 amount) external {
        // ❌ No address length validation
        // ❌ Short address attack possible

        // If 'to' is missing bytes, amount can be manipulated
        // ❌ Missing: require(to != address(0))
        // ❌ Missing: Address format validation
    }
}

/**
 * @dev Slashing mechanism without validation
 */
contract VulnerableSlashing {
    mapping(address => uint256) public stakes;

    // ❌ VULNERABILITY: Slashing without proper validation
    function slash(address validator, uint256 amount) external {
        // ❌ No evidence verification
        // ❌ No timelock
        // ❌ Anyone can slash

        stakes[validator] -= amount;

        // ❌ Missing: Proof of misbehavior
        // ❌ Missing: Governance approval
        // ❌ Missing: Appeal period
    }
}

/**
 * @dev Reward calculation manipulation
 */
contract VulnerableRewards {
    mapping(address => uint256) public rewards;

    // ❌ VULNERABILITY: Reward calculation manipulation
    function calculateReward(address user, uint256 multiplier) external view returns (uint256) {
        // ❌ Multiplier can be manipulated
        // ❌ No bounds checking
        // ❌ Overflow possible even in 0.8.x with large values

        return rewards[user] * multiplier;

        // ❌ Missing: Multiplier validation
        // ❌ Missing: Maximum reward cap
    }
}

/**
 * @dev Plaintext secret storage
 */
contract VulnerablePlaintextSecrets {
    // ❌ VULNERABILITY: Plaintext secret storage
    string private secretKey = "my-secret-api-key-12345";
    bytes32 private privateData = keccak256("sensitive");

    // ❌ CRITICAL: Private variables are visible on-chain
    // ❌ Anyone can read storage slots
    // ❌ No encryption

    function storeSecret(string memory secret) external {
        secretKey = secret; // ❌ Stored in plaintext
    }
}

/**
 * @dev Deadline manipulation
 */
contract VulnerableDeadline {
    // ❌ VULNERABILITY: No deadline validation
    function swap(uint256 amountIn, uint256 amountOutMin, uint256 deadline) external {
        // ❌ Deadline can be far future
        // ❌ No validation that deadline is reasonable

        // ❌ Missing: require(block.timestamp <= deadline)
        // ❌ Missing: Maximum deadline validation

        // Process swap
    }
}

/**
 * @dev Default visibility issue
 */
contract VulnerableDefaultVisibility {
    uint256 balance; // ❌ Default visibility (internal)

    // ❌ VULNERABILITY: Function without explicit visibility
    function sensitiveOperation() { // ❌ No visibility modifier
        // Default is public in older Solidity
        // Security risk if not explicit
    }
}

/**
 * @dev Redundant checks (gas optimization issue)
 */
contract VulnerableRedundant {
    function process(uint256 value) external {
        require(value > 0, "Zero value");
        require(value != 0, "Cannot be zero"); // ❌ Redundant check

        if (value > 0) { // ❌ Redundant check again
            // Process
        }
    }
}

/**
 * @dev Block dependency
 */
contract VulnerableBlockDependency {
    function random() external view returns (uint256) {
        // ❌ VULNERABILITY: Depends on block properties
        // ❌ Miners can manipulate

        return uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty)));

        // ❌ Predictable by miners
    }
}

/**
 * @dev Batch transfer overflow
 */
contract VulnerableBatchTransfer {
    mapping(address => uint256) public balances;

    // ❌ VULNERABILITY: Batch transfer overflow
    function batchTransfer(address[] calldata recipients, uint256[] calldata amounts) external {
        // ❌ No total amount validation
        // ❌ Can overflow balance

        for (uint256 i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += amounts[i];
        }

        // ❌ Missing: Total sum validation
        // ❌ Missing: Balance check before transfers
    }
}

/**
 * TESTING NOTES:
 *
 * Expected Detectors:
 * 1. optimistic-challenge-bypass (3 findings)
 * 2. optimistic-fraud-proof-timing (2 findings)
 * 3. oracle-staleness-heartbeat (3 findings)
 * 4. price-oracle-stale (3 findings)
 * 5. missing-price-validation (2 findings)
 * 6. readonly-reentrancy (1 finding)
 * 7. transient-storage-state-leak (1 finding)
 * 8. transient-reentrancy-guard (1 finding)
 * 9. transient-storage-composability (1 finding)
 * 10. transient-storage-misuse (1 finding)
 * 11. emergency-function-abuse (1 finding)
 * 12. emergency-pause-centralization (1 finding)
 * 13. emergency-withdrawal-abuse (1 finding)
 * 14. vault-donation-attack (1 finding)
 * 15. weak-commit-reveal (1 finding)
 * 16. weak-signature-validation (1 finding)
 * 17. role-hierarchy-bypass (1 finding)
 * 18. multi-role-confusion (1 finding)
 * 19. privilege-escalation-paths (1 finding)
 * 20. avs-validation-bypass (1 finding)
 * 21. storage-slot-predictability (1 finding)
 * 22. short-address-attack (1 finding)
 * 23. slashing-mechanism (1 finding)
 * 24. reward-calculation-manipulation (1 finding)
 * 25. yield-farming-manipulation (potential)
 * 26. plaintext-secret-storage (1 finding)
 * 27. deadline-manipulation (1 finding)
 * 28. default-visibility (2 findings)
 * 29. redundant-checks (2 findings)
 * 30. block-dependency (1 finding)
 * 31. batch-transfer-overflow (1 finding)
 *
 * Cross-Category Detectors Expected:
 * - centralization-risk
 * - missing-access-modifiers
 * - unchecked-external-call
 * - missing-input-validation
 * - missing-zero-address-check
 * - enhanced-access-control
 * - timestamp-manipulation
 * - insufficient-randomness
 * - logic-error-patterns
 *
 * Real-World Relevance:
 * - Optimistic rollups: Arbitrum, Optimism challenge periods
 * - Oracle staleness: Chainlink heartbeat, price manipulation
 * - Readonly reentrancy: Curve Finance vulnerability
 * - Emergency functions: Various protocol rug pulls
 * - Vault donation: ERC-4626 share inflation attacks
 * - AVS validation: EigenLayer actively validated services
 * - Short address: Historical ERC-20 attack vector
 */
