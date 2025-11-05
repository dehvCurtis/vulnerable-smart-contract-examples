// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableBundlerDoS
 * @notice Test contract for bundler DoS and gas griefing vulnerabilities
 *
 * DETECTORS TO TEST:
 * - aa-bundler-dos (Medium)
 * - aa-bundler-dos-enhanced (High)
 * - aa-entry-point-reentrancy (Medium)
 * - erc4337-gas-griefing (Low)
 *
 * VULNERABILITIES:
 * 1. External calls in validateUserOp
 * 2. Unbounded loops in validation
 * 3. Storage access violations
 * 4. Expensive operations without gas limits
 * 5. Storage reads from unknown contracts
 * 6. Reentrancy in validation phase
 * 7. Reentrancy in handleOps
 * 8. Storage writes in validation (gas griefing)
 */

interface IEntryPoint {
    function handleOps(bytes[] calldata ops, address payable beneficiary) external;
}

interface IExternalOracle {
    function getPrice() external view returns (uint256);
}

contract VulnerableBundlerDoS {
    address public owner;
    uint256 public nonce;
    address[] public allowedAddresses;
    mapping(address => bool) public isAllowed;

    // ❌ VULNERABILITY 1: External call in validateUserOp (aa-bundler-dos)
    // External calls can consume unbounded gas and DoS the bundler!
    function validateUserOp(
        bytes32 userOpHash,
        bytes calldata signature
    ) external returns (uint256) {
        // ❌ External call to unknown contract in validation!
        // This violates ERC-4337 validation rules
        IExternalOracle oracle = IExternalOracle(0x1234567890123456789012345678901234567890);
        uint256 price = oracle.getPrice(); // Can consume unlimited gas!

        // Signature validation...
        nonce++;

        return 0;
    }

    // ❌ VULNERABILITY 2: Unbounded loop in validateUserOp (aa-bundler-dos)
    function validateWithLoop(
        address[] calldata addresses,
        bytes calldata signature
    ) external returns (uint256) {
        // ❌ Loop without bounds checking!
        // Attacker can pass huge array and DoS the bundler
        for (uint i = 0; i < addresses.length; i++) {
            // ❌ No maximum iteration limit
            require(isAllowed[addresses[i]], "Not allowed");
        }

        nonce++;
        return 0;
    }

    // ❌ VULNERABILITY 3: Storage access from unknown contract (aa-bundler-dos-enhanced)
    function validateWithExternalStorage(
        address externalContract,
        bytes calldata signature
    ) external returns (uint256) {
        // ❌ Reading storage from arbitrary external contract
        // This violates ERC-4337 storage access rules
        (bool success, bytes memory data) = externalContract.staticcall(
            abi.encodeWithSignature("someStorageValue()")
        );

        require(success, "External call failed");

        nonce++;
        return 0;
    }

    // ❌ VULNERABILITY 4: Expensive operation without gas limit (aa-bundler-dos-enhanced)
    function validateWithExpensiveOp(
        uint256 complexity,
        bytes calldata signature
    ) external returns (uint256) {
        // ❌ No check on gasleft() before expensive operation
        uint256 result = 1;

        // Expensive computation without bounds
        for (uint i = 0; i < complexity; i++) {
            result = result * 2;
            // This could consume all available gas
        }

        nonce++;
        return 0;
    }

    // ❌ VULNERABILITY 5: Multiple storage slots accessed (aa-bundler-dos)
    function validateWithMultipleStorage(
        bytes calldata signature
    ) external returns (uint256) {
        // ❌ Accessing storage from multiple slots/contracts
        // ERC-4337 validation should only access account's own storage

        for (uint i = 0; i < allowedAddresses.length; i++) {
            // Reading from array (multiple storage slots)
            address addr = allowedAddresses[i];
            bool allowed = isAllowed[addr]; // Reading mapping
        }

        nonce++;
        return 0;
    }
}

contract VulnerableEntryPointReentrancy {
    address public owner;
    uint256 public nonce;
    mapping(address => uint256) public balances;

    // ❌ VULNERABILITY 6: Reentrancy in validateUserOp (aa-entry-point-reentrancy)
    function validateUserOp(
        address payable recipient,
        uint256 amount,
        bytes calldata signature
    ) external returns (uint256) {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // ❌ External call BEFORE state update!
        // This allows reentrancy attack
        (bool success,) = recipient.call{value: amount}("");
        require(success, "Transfer failed");

        // State update AFTER external call (vulnerable!)
        balances[msg.sender] -= amount;
        nonce++;

        return 0;
    }

    // ❌ VULNERABILITY 7: handleOps without reentrancy guard (aa-entry-point-reentrancy)
    function handleOps(
        address[] calldata targets,
        uint256[] calldata values
    ) external {
        // ❌ No reentrancy protection on batch operation handler!
        // Missing: nonReentrant modifier

        for (uint i = 0; i < targets.length; i++) {
            // External calls in loop without reentrancy guard
            (bool success,) = targets[i].call{value: values[i]}("");
            require(success, "Call failed");
        }
    }

    // ❌ VULNERABILITY 8: State changes after external call (aa-entry-point-reentrancy)
    function executeOperation(
        address target,
        bytes calldata data
    ) external {
        require(msg.sender == owner, "Only owner");

        // ❌ External call before state changes
        (bool success,) = target.call(data);
        require(success, "Execution failed");

        // State changes AFTER external call - vulnerable to reentrancy!
        nonce++;
        balances[msg.sender] += 1 ether;
    }

    receive() external payable {}
}

contract VulnerableGasGriefing {
    address public owner;
    uint256 public nonce;
    uint256[] public data;
    mapping(uint256 => uint256) public registry;

    // ❌ VULNERABILITY 9: Storage writes in validation (erc4337-gas-griefing)
    // Storage writes consume lots of gas and can grief bundlers
    function validateUserOp(
        uint256 value,
        bytes calldata signature
    ) external returns (uint256) {
        // ❌ Writing to storage in validation phase!
        // This violates ERC-4337 and causes gas griefing
        registry[nonce] = value;
        data.push(value);

        nonce++;
        return 0;
    }

    // ❌ VULNERABILITY 10: Unbounded loop writing storage (erc4337-gas-griefing)
    function validateWithStorageWrites(
        uint256[] calldata values,
        bytes calldata signature
    ) external returns (uint256) {
        // ❌ Writing multiple storage slots in validation
        for (uint i = 0; i < values.length; i++) {
            registry[i] = values[i]; // Expensive storage write
            data.push(values[i]); // Growing array
        }

        nonce++;
        return 0;
    }

    // ❌ VULNERABILITY 11: Complex iteration in validation (aa-bundler-dos)
    function validateWithIteration(
        bytes calldata signature
    ) external returns (uint256) {
        // ❌ Iterating over entire data array
        // As array grows, validation becomes more expensive
        uint256 sum = 0;
        for (uint i = 0; i < data.length; i++) {
            sum += data[i];
        }

        nonce++;
        return 0;
    }
}

/**
 * @notice Secure implementations for comparison
 */
contract SecureBundlerProtection {
    address public owner;
    address public immutable entryPoint;
    uint256 public nonce;

    uint256 public constant MAX_ITERATION_LIMIT = 10;

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
        owner = msg.sender;
    }

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "Only EntryPoint");
        _;
    }

    // ✅ Secure validation without external calls
    function validateUserOp(
        bytes32 userOpHash,
        bytes calldata signature
    ) external onlyEntryPoint returns (uint256) {
        // ✅ No external calls in validation
        // ✅ Only access account's own storage
        // ✅ No expensive operations

        // Validate signature using ECDSA (no external calls)
        require(validateSignature(userOpHash, signature), "Invalid signature");

        nonce++;
        return 0;
    }

    // ✅ Bounded loop validation
    function validateWithLoop(
        address[] calldata addresses,
        bytes calldata signature
    ) external onlyEntryPoint returns (uint256) {
        // ✅ Enforce maximum iteration limit
        require(addresses.length <= MAX_ITERATION_LIMIT, "Too many addresses");

        for (uint i = 0; i < addresses.length; i++) {
            // Safe iteration with bounds
            require(addresses[i] != address(0), "Invalid address");
        }

        nonce++;
        return 0;
    }

    // ✅ Gas limit check before expensive operation
    function validateWithGasCheck(
        uint256 complexity,
        bytes calldata signature
    ) external onlyEntryPoint returns (uint256) {
        // ✅ Check remaining gas before expensive operation
        require(gasleft() >= 100000, "Insufficient gas");

        // ✅ Bounded complexity
        require(complexity <= 100, "Complexity too high");

        uint256 result = 1;
        for (uint i = 0; i < complexity; i++) {
            result = result * 2;
        }

        nonce++;
        return 0;
    }

    function validateSignature(bytes32 hash, bytes calldata signature) internal view returns (bool) {
        // ECDSA signature validation (no external calls)
        return true; // Simplified
    }
}

contract SecureReentrancyProtection {
    address public owner;
    uint256 public nonce;
    mapping(address => uint256) public balances;

    bool private locked;

    modifier nonReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }

    // ✅ Secure validation with checks-effects-interactions
    function validateUserOp(
        address payable recipient,
        uint256 amount,
        bytes calldata signature
    ) external nonReentrant returns (uint256) {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // ✅ State changes BEFORE external call (checks-effects-interactions)
        balances[msg.sender] -= amount;
        nonce++;

        // External call AFTER state changes
        (bool success,) = recipient.call{value: amount}("");
        require(success, "Transfer failed");

        return 0;
    }

    // ✅ Secure handleOps with reentrancy guard
    function handleOps(
        address[] calldata targets,
        uint256[] calldata values
    ) external nonReentrant {
        require(targets.length == values.length, "Length mismatch");

        for (uint i = 0; i < targets.length; i++) {
            (bool success,) = targets[i].call{value: values[i]}("");
            require(success, "Call failed");
        }
    }

    // ✅ State changes before external call
    function executeOperation(
        address target,
        bytes calldata data
    ) external nonReentrant {
        require(msg.sender == owner, "Only owner");

        // ✅ State changes BEFORE external call
        nonce++;
        balances[msg.sender] += 1 ether;

        // External call AFTER state changes
        (bool success,) = target.call(data);
        require(success, "Execution failed");
    }

    receive() external payable {}
}

contract SecureGasOptimization {
    address public owner;
    address public immutable entryPoint;
    uint256 public nonce;

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "Only EntryPoint");
        _;
    }

    // ✅ No storage writes in validation
    function validateUserOp(
        bytes32 userOpHash,
        bytes calldata signature
    ) external onlyEntryPoint returns (uint256) {
        // ✅ Only read from storage, no writes
        // ✅ No expensive operations

        require(validateSignature(userOpHash, signature), "Invalid signature");

        // State changes happen in execution phase, not validation
        return 0;
    }

    // ✅ Execution phase for state changes (not validation)
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyEntryPoint {
        // ✅ State changes in execution phase (OK)
        nonce++;

        (bool success,) = target.call{value: value}(data);
        require(success, "Execution failed");
    }

    function validateSignature(bytes32 hash, bytes calldata signature) internal view returns (bool) {
        return true; // Simplified
    }
}
