// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableAccountManagement
 * @notice Test contract for account initialization, session keys, and recovery vulnerabilities
 *
 * DETECTORS TO TEST:
 * - aa-initialization-vulnerability (High)
 * - aa-session-key-vulnerabilities (High)
 * - aa-social-recovery (Medium)
 * - aa-nonce-management (High)
 * - aa-nonce-management-advanced (Medium)
 *
 * VULNERABILITIES:
 * 1. Initialization without signature verification
 * 2. Missing initialization lock (can be re-initialized)
 * 3. Session keys without expiration
 * 4. Session keys with unlimited permissions
 * 5. Missing spending limits on session keys
 * 6. Social recovery without timelock
 * 7. Insufficient guardian threshold
 * 8. Missing nonce validation
 * 9. No support for parallel nonce keys
 */

struct SessionKeyData {
    address key;
    uint256 validUntil;
    address[] allowedTargets;
    bytes4[] allowedSelectors;
    uint256 spendingLimit;
}

contract VulnerableInitialization {
    address public owner;
    bool public initialized;

    // ❌ VULNERABILITY 1: Initialization without signature verification (aa-initialization-vulnerability)
    // Anyone can call this and set themselves as owner!
    function initialize(address _owner) external {
        // Missing: Signature verification
        // Missing: require(msg.sender == expectedInitializer)
        // Missing: Signature from _owner proving they authorized this

        require(!initialized, "Already initialized");
        owner = _owner;
        initialized = true;
    }

    // ❌ VULNERABILITY 2: Missing initialization lock (aa-initialization-vulnerability)
    // The initialized flag can be bypassed
    function initializeUnsafe(address _owner) external {
        // ❌ No check for existing initialization!
        // This allows re-initialization and owner takeover!
        owner = _owner;
    }

    // ❌ VULNERABILITY 3: EntryPoint-only initialization without proper check (aa-initialization-vulnerability)
    address public entryPoint;

    function initializeFromEntryPoint(address _owner) external {
        // ❌ EntryPoint address not validated before use
        // Missing: require(msg.sender == KNOWN_ENTRY_POINT)
        require(msg.sender == entryPoint, "Only EntryPoint");
        owner = _owner;
    }
}

contract VulnerableSessionKeys {
    address public owner;
    mapping(address => bool) public isSessionKey;
    mapping(address => SessionKeyData) public sessionKeys;

    // ❌ VULNERABILITY 4: Session key without expiration (aa-session-key-vulnerabilities)
    function addSessionKey(address key) external {
        require(msg.sender == owner, "Only owner");
        isSessionKey[key] = true;
        // ❌ Missing: validUntil timestamp
        // Session key is valid FOREVER!
    }

    // ❌ VULNERABILITY 5: Session key with unlimited permissions (aa-session-key-vulnerabilities)
    function addUnlimitedSessionKey(address key) external {
        require(msg.sender == owner, "Only owner");

        // ❌ No restrictions on what this session key can do!
        // Missing: allowedTargets array
        // Missing: allowedSelectors array
        // Missing: spendingLimit
        // Missing: validUntil

        isSessionKey[key] = true;
    }

    // ❌ VULNERABILITY 6: Session key execute without validation (aa-session-key-vulnerabilities)
    function executeWithSessionKey(
        address target,
        uint256 value,
        bytes calldata data
    ) external {
        require(isSessionKey[msg.sender], "Not a session key");

        // ❌ No validation of:
        // - Time expiration
        // - Allowed targets
        // - Allowed function selectors
        // - Spending limits

        (bool success,) = target.call{value: value}(data);
        require(success, "Execution failed");
    }

    // ❌ VULNERABILITY 7: Session key with spending limit but no reset period (aa-session-key-vulnerabilities)
    mapping(address => uint256) public sessionKeySpent;

    function addSessionKeyWithLimit(address key, uint256 limit) external {
        require(msg.sender == owner, "Only owner");

        sessionKeys[key] = SessionKeyData({
            key: key,
            validUntil: block.timestamp + 30 days,
            allowedTargets: new address[](0),
            allowedSelectors: new bytes4[](0),
            spendingLimit: limit
        });

        isSessionKey[key] = true;
    }

    function executeWithLimit(
        address target,
        uint256 value,
        bytes calldata data
    ) external {
        require(isSessionKey[msg.sender], "Not a session key");

        SessionKeyData memory keyData = sessionKeys[msg.sender];

        // ❌ VULNERABILITY: No period reset!
        // Once limit is reached, session key is useless forever
        // Missing: periodDuration and periodStart for resetting limits
        require(sessionKeySpent[msg.sender] + value <= keyData.spendingLimit, "Limit exceeded");

        sessionKeySpent[msg.sender] += value;

        (bool success,) = target.call{value: value}(data);
        require(success, "Execution failed");
    }
}

contract VulnerableSocialRecovery {
    address public owner;
    address[] public guardians;
    uint256 public threshold;

    address public pendingOwner;
    address[] public recoveryApprovals;

    // ❌ VULNERABILITY 8: Recovery without timelock (aa-social-recovery)
    function initiateRecovery(address newOwner) external {
        require(isGuardian(msg.sender), "Not a guardian");

        // ❌ No timelock delay between initiation and execution!
        // Should have 24-48 hour delay to allow legitimate owner to cancel

        recoveryApprovals.push(msg.sender);

        if (recoveryApprovals.length >= threshold) {
            // ❌ Immediate execution without delay!
            owner = newOwner;
            delete recoveryApprovals;
        }
    }

    // ❌ VULNERABILITY 9: Insufficient guardian threshold (aa-social-recovery)
    function setGuardians(address[] calldata _guardians) external {
        require(msg.sender == owner, "Only owner");

        guardians = _guardians;

        // ❌ Threshold set to 1 out of 5 guardians (only 20%!)
        // Should be at least 3 out of 5 (60%) or higher
        threshold = 1;
    }

    // ❌ VULNERABILITY 10: No cancel recovery function (aa-social-recovery)
    // If legitimate owner sees unauthorized recovery attempt, they can't stop it!
    // Missing: function cancelRecovery() external { require(msg.sender == owner); ... }

    // ❌ VULNERABILITY 11: Guardians can be duplicated (aa-social-recovery)
    function addGuardian(address guardian) external {
        require(msg.sender == owner, "Only owner");

        // ❌ No check for duplicate guardians!
        // Attacker could add same address multiple times
        guardians.push(guardian);
    }

    function isGuardian(address account) internal view returns (bool) {
        for (uint i = 0; i < guardians.length; i++) {
            if (guardians[i] == account) return true;
        }
        return false;
    }
}

contract VulnerableNonceManagement {
    address public owner;
    uint256 public nonce;
    mapping(uint256 => bool) public usedNonces;

    // ❌ VULNERABILITY 12: Sequential nonce only, no parallel support (aa-nonce-management)
    // ERC-4337 supports parallel operations with nonce keys, but this doesn't
    function validateUserOp(
        uint256 userOpNonce,
        bytes calldata signature
    ) external returns (uint256) {
        // ❌ Only supports sequential nonces (0, 1, 2, 3...)
        // No support for parallel nonces with different keys
        // Missing: uint192 key = uint192(userOpNonce >> 64);
        require(userOpNonce == nonce, "Invalid nonce");

        nonce++;
        return 0;
    }

    // ❌ VULNERABILITY 13: No nonce validation at all (aa-nonce-management)
    function executeWithoutNonceCheck(
        bytes calldata data
    ) external {
        // ❌ No nonce check! Allows replay attacks!

        (address target, uint256 value, bytes memory callData) = abi.decode(
            data,
            (address, uint256, bytes)
        );

        (bool success,) = target.call{value: value}(callData);
        require(success, "Execution failed");
    }

    // ❌ VULNERABILITY 14: Nonce not properly tracked in mapping (aa-nonce-management-advanced)
    function validateWithMapping(uint256 userOpNonce) external {
        // ❌ Checks mapping but doesn't set it!
        require(!usedNonces[userOpNonce], "Nonce already used");

        // Missing: usedNonces[userOpNonce] = true;

        // This allows same nonce to be used multiple times!
    }
}

/**
 * @notice Secure implementations for comparison
 */
contract SecureInitialization {
    address public owner;
    bool public initialized;
    uint256 public initNonce;

    // ✅ Secure initialization with signature
    function initialize(
        address _owner,
        uint256 nonce,
        bytes calldata signature
    ) external {
        require(!initialized, "Already initialized");

        // ✅ Verify signature from owner
        bytes32 hash = keccak256(abi.encodePacked(_owner, nonce, address(this), block.chainid));
        address signer = recoverSigner(hash, signature);
        require(signer == _owner, "Invalid signature");

        // ✅ Nonce prevents replay
        require(nonce == initNonce, "Invalid nonce");
        initNonce++;

        owner = _owner;
        initialized = true;
    }

    function recoverSigner(bytes32 hash, bytes calldata signature) internal pure returns (address) {
        // ECDSA recovery implementation
        return address(0); // Simplified
    }
}

contract SecureSessionKeys {
    address public owner;
    mapping(address => SessionKeyData) public sessionKeys;

    uint256 public constant PERIOD_DURATION = 1 days;

    struct SessionKeyTracking {
        uint256 spentInPeriod;
        uint256 periodStart;
    }

    mapping(address => SessionKeyTracking) public sessionKeyTracking;

    // ✅ Secure session key with all restrictions
    function addSessionKey(
        address key,
        uint256 validUntil,
        address[] calldata allowedTargets,
        bytes4[] calldata allowedSelectors,
        uint256 spendingLimit
    ) external {
        require(msg.sender == owner, "Only owner");
        require(validUntil > block.timestamp, "Already expired");
        require(spendingLimit > 0, "Invalid limit");

        sessionKeys[key] = SessionKeyData({
            key: key,
            validUntil: validUntil,
            allowedTargets: allowedTargets,
            allowedSelectors: allowedSelectors,
            spendingLimit: spendingLimit
        });
    }

    // ✅ Secure execution with full validation
    function executeWithSessionKey(
        address target,
        uint256 value,
        bytes calldata data
    ) external {
        SessionKeyData memory keyData = sessionKeys[msg.sender];
        require(keyData.key != address(0), "Not a session key");

        // ✅ Time validation
        require(block.timestamp <= keyData.validUntil, "Session key expired");

        // ✅ Target validation
        require(isAllowedTarget(keyData.allowedTargets, target), "Target not allowed");

        // ✅ Selector validation
        bytes4 selector = bytes4(data[0:4]);
        require(isAllowedSelector(keyData.allowedSelectors, selector), "Selector not allowed");

        // ✅ Spending limit with period reset
        SessionKeyTracking storage tracking = sessionKeyTracking[msg.sender];
        if (block.timestamp - tracking.periodStart > PERIOD_DURATION) {
            tracking.spentInPeriod = 0;
            tracking.periodStart = block.timestamp;
        }

        require(
            tracking.spentInPeriod + value <= keyData.spendingLimit,
            "Spending limit exceeded"
        );

        tracking.spentInPeriod += value;

        (bool success,) = target.call{value: value}(data);
        require(success, "Execution failed");
    }

    function isAllowedTarget(address[] memory allowed, address target) internal pure returns (bool) {
        for (uint i = 0; i < allowed.length; i++) {
            if (allowed[i] == target) return true;
        }
        return false;
    }

    function isAllowedSelector(bytes4[] memory allowed, bytes4 selector) internal pure returns (bool) {
        for (uint i = 0; i < allowed.length; i++) {
            if (allowed[i] == selector) return true;
        }
        return false;
    }
}

contract SecureSocialRecovery {
    address public owner;
    address[] public guardians;
    uint256 public threshold;

    address public pendingOwner;
    uint256 public recoveryInitiatedAt;
    uint256 public constant RECOVERY_DELAY = 48 hours;
    mapping(address => bool) public hasApproved;
    uint256 public approvalCount;

    // ✅ Secure recovery with timelock
    function initiateRecovery(address newOwner) external {
        require(isGuardian(msg.sender), "Not a guardian");
        require(!hasApproved[msg.sender], "Already approved");

        if (pendingOwner != newOwner) {
            // New recovery attempt, reset
            pendingOwner = newOwner;
            approvalCount = 0;
            recoveryInitiatedAt = 0;
            resetApprovals();
        }

        hasApproved[msg.sender] = true;
        approvalCount++;

        if (approvalCount >= threshold && recoveryInitiatedAt == 0) {
            // ✅ Start timelock delay
            recoveryInitiatedAt = block.timestamp;
        }
    }

    // ✅ Execute recovery after timelock
    function executeRecovery() external {
        require(pendingOwner != address(0), "No pending recovery");
        require(approvalCount >= threshold, "Insufficient approvals");
        require(recoveryInitiatedAt > 0, "Recovery not initiated");

        // ✅ Enforce timelock delay
        require(
            block.timestamp >= recoveryInitiatedAt + RECOVERY_DELAY,
            "Timelock not expired"
        );

        owner = pendingOwner;
        pendingOwner = address(0);
        recoveryInitiatedAt = 0;
        resetApprovals();
    }

    // ✅ Cancel recovery function
    function cancelRecovery() external {
        require(msg.sender == owner, "Only owner");

        pendingOwner = address(0);
        recoveryInitiatedAt = 0;
        approvalCount = 0;
        resetApprovals();
    }

    // ✅ Secure guardian management
    function setGuardians(address[] calldata _guardians, uint256 _threshold) external {
        require(msg.sender == owner, "Only owner");
        require(_guardians.length >= 3, "At least 3 guardians");
        require(_threshold >= (_guardians.length * 60) / 100, "Threshold too low"); // At least 60%

        // ✅ Check for duplicates
        for (uint i = 0; i < _guardians.length; i++) {
            for (uint j = i + 1; j < _guardians.length; j++) {
                require(_guardians[i] != _guardians[j], "Duplicate guardian");
            }
        }

        guardians = _guardians;
        threshold = _threshold;
    }

    function isGuardian(address account) internal view returns (bool) {
        for (uint i = 0; i < guardians.length; i++) {
            if (guardians[i] == account) return true;
        }
        return false;
    }

    function resetApprovals() internal {
        for (uint i = 0; i < guardians.length; i++) {
            hasApproved[guardians[i]] = false;
        }
    }
}

contract SecureNonceManagement {
    address public owner;
    address public entryPoint;

    // ✅ Support for parallel nonce keys (ERC-4337 standard)
    mapping(uint192 => uint256) public nonceSequenceNumber;

    function validateUserOp(
        uint256 userOpNonce
    ) external returns (uint256) {
        require(msg.sender == entryPoint, "Only EntryPoint");

        // ✅ Extract nonce key (upper 192 bits) and sequence (lower 64 bits)
        uint192 key = uint192(userOpNonce >> 64);
        uint64 sequence = uint64(userOpNonce);

        // ✅ Validate sequence number for this key
        require(sequence == nonceSequenceNumber[key], "Invalid nonce");

        // ✅ Increment sequence for this key
        nonceSequenceNumber[key]++;

        return 0;
    }

    // ✅ Get expected nonce for a key
    function getNonce(uint192 key) external view returns (uint256) {
        return (uint256(key) << 64) | nonceSequenceNumber[key];
    }
}
