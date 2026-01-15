// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableEntryPointTrust
 * @notice Test contract for ERC-4337 EntryPoint trust vulnerabilities
 *
 * DETECTORS TO TEST:
 * - aa-account-takeover (Critical)
 * - erc4337-entrypoint-trust (Critical)
 *
 * VULNERABILITIES:
 * 1. Hardcoded EntryPoint without validation
 * 2. Mutable EntryPoint without access control
 * 3. Missing EntryPoint validation in critical functions
 * 4. No timelock for EntryPoint changes
 * 5. Unprotected EntryPoint replacement allowing account takeover
 */

interface IEntryPoint {
    function validateUserOp(
        address account,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData);

    function handleOps(
        bytes[] calldata ops,
        address payable beneficiary
    ) external;
}

contract VulnerableSmartAccount {
    // ❌ VULNERABILITY 1: Hardcoded EntryPoint address (erc4337-entrypoint-trust)
    // Should be: Validated against known safe EntryPoints or use upgradeable pattern
    address public constant ENTRY_POINT = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    address public owner;
    uint256 public nonce;

    // ❌ VULNERABILITY 2: Mutable EntryPoint without ANY access control (aa-account-takeover)
    // Anyone can call this and replace the EntryPoint!
    address public trustedEntryPoint;

    constructor(address _owner) {
        owner = _owner;
        trustedEntryPoint = ENTRY_POINT;
    }

    // ❌ VULNERABILITY 3: Unprotected EntryPoint replacement (aa-account-takeover)
    // Missing: onlyOwner modifier, timelock, multi-sig requirement
    // This allows ANYONE to replace the EntryPoint and take over the account!
    function setEntryPoint(address newEntryPoint) external {
        // Should have:
        // - require(msg.sender == owner, "Only owner");
        // - Timelock delay (e.g., 48 hours)
        // - Multi-sig approval
        // - Emit EntryPointChanged event
        trustedEntryPoint = newEntryPoint;
    }

    // ❌ VULNERABILITY 4: Missing EntryPoint validation (erc4337-entrypoint-trust)
    // validateUserOp should ONLY be callable by trusted EntryPoint
    function validateUserOp(
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        // Missing: require(msg.sender == trustedEntryPoint, "Only EntryPoint");

        // Signature validation would go here...
        nonce++;

        // Pay EntryPoint if needed
        if (missingAccountFunds > 0) {
            (bool success,) = msg.sender.call{value: missingAccountFunds}("");
            require(success, "Payment failed");
        }

        return 0; // Valid
    }

    // ❌ VULNERABILITY 5: Execute function accepts calls from any EntryPoint (erc4337-entrypoint-trust)
    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external {
        // Missing: require(msg.sender == trustedEntryPoint, "Only EntryPoint");

        (bool success, bytes memory result) = dest.call{value: value}(func);
        require(success, string(result));
    }

    // ❌ VULNERABILITY 6: No validation that EntryPoint is legitimate contract
    function unsafeEntryPointUpdate(address _newEntryPoint) external {
        // Missing:
        // - Code size check: require(_newEntryPoint.code.length > 0)
        // - Interface verification
        // - Known EntryPoint registry check
        trustedEntryPoint = _newEntryPoint;
    }

    receive() external payable {}
}

/**
 * @notice Example of a malicious EntryPoint that could be set via setEntryPoint
 */
contract MaliciousEntryPoint {
    // Attacker can deploy this and call victim.setEntryPoint(address(this))
    // Then drain all funds by calling validateUserOp

    function validateUserOp(
        address account,
        bytes32,
        uint256
    ) external returns (uint256) {
        // Drain the account
        (bool success,) = msg.sender.call(
            abi.encodeWithSignature("execute(address,uint256,bytes)", address(this), address(account).balance, "")
        );
        require(success);
        return 0;
    }
}

/**
 * @notice Secure implementation for comparison
 */
contract SecureSmartAccount {
    address public immutable ENTRY_POINT; // ✅ Immutable if no upgrade needed
    address public owner;
    uint256 public nonce;

    // For upgradeable EntryPoint pattern
    address public pendingEntryPoint;
    uint256 public entryPointChangeTimestamp;
    uint256 public constant TIMELOCK_DURATION = 48 hours;

    event EntryPointChangeInitiated(address indexed newEntryPoint, uint256 executeAfter);
    event EntryPointChanged(address indexed oldEntryPoint, address indexed newEntryPoint);

    constructor(address _entryPoint, address _owner) {
        ENTRY_POINT = _entryPoint;
        owner = _owner;
    }

    modifier onlyEntryPoint() {
        require(msg.sender == ENTRY_POINT, "Only EntryPoint");
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    // ✅ Secure EntryPoint change with timelock
    function initiateEntryPointChange(address newEntryPoint) external onlyOwner {
        require(newEntryPoint != address(0), "Invalid address");
        require(newEntryPoint.code.length > 0, "Not a contract");

        pendingEntryPoint = newEntryPoint;
        entryPointChangeTimestamp = block.timestamp + TIMELOCK_DURATION;

        emit EntryPointChangeInitiated(newEntryPoint, entryPointChangeTimestamp);
    }

    // ✅ Execute EntryPoint change after timelock
    function executeEntryPointChange() external onlyOwner {
        require(pendingEntryPoint != address(0), "No pending change");
        require(block.timestamp >= entryPointChangeTimestamp, "Timelock not expired");

        address oldEntryPoint = ENTRY_POINT;
        // In real implementation, would use storage variable
        // ENTRY_POINT = pendingEntryPoint;

        emit EntryPointChanged(oldEntryPoint, pendingEntryPoint);

        pendingEntryPoint = address(0);
        entryPointChangeTimestamp = 0;
    }

    // ✅ Properly protected validateUserOp
    function validateUserOp(
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        // Signature validation...
        nonce++;

        if (missingAccountFunds > 0) {
            (bool success,) = msg.sender.call{value: missingAccountFunds}("");
            require(success, "Payment failed");
        }

        return 0;
    }

    // ✅ Properly protected execute
    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external onlyEntryPoint {
        (bool success, bytes memory result) = dest.call{value: value}(func);
        require(success, string(result));
    }

    receive() external payable {}
}
