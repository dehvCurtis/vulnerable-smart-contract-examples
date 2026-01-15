// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableSignatureValidation
 * @notice Test contract for ERC-4337 signature and validation vulnerabilities
 *
 * DETECTORS TO TEST:
 * - aa-calldata-encoding-exploit (Critical)
 * - aa-signature-aggregation-bypass (High)
 * - aa-user-operation-replay (High)
 *
 * VULNERABILITIES:
 * 1. Calldata manipulation after signature validation
 * 2. UserOperation fields modified after validation
 * 3. Missing chain ID validation for replay protection
 * 4. Missing nonce validation
 * 5. Signature aggregation without individual validation
 * 6. Missing unique operation IDs
 * 7. Batch validation without proper checks
 */

struct UserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}

contract VulnerableCalldataEncoding {
    address public owner;
    uint256 public nonce;

    constructor(address _owner) {
        owner = _owner;
    }

    // ❌ VULNERABILITY 1: Calldata decoded AFTER signature validation (aa-calldata-encoding-exploit)
    // This allows calldata manipulation after signature check!
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256 validationData) {
        // Validate signature
        require(validateSignature(userOpHash, userOp.signature), "Invalid signature");

        // ❌ VULNERABILITY: Now decode and execute calldata
        // The calldata could have been modified after the signature was created!
        // Signature should have covered the FINAL calldata, not just the hash
        (address target, uint256 value, bytes memory data) = abi.decode(
            userOp.callData,
            (address, uint256, bytes)
        );

        // Execute with potentially manipulated calldata
        (bool success,) = target.call{value: value}(data);
        require(success, "Execution failed");

        return 0;
    }

    // ❌ VULNERABILITY 2: UserOperation fields modified after validation (aa-calldata-encoding-exploit)
    function validateAndExecute(
        UserOperation memory userOp // Note: memory, not calldata!
    ) external returns (uint256) {
        // Validate signature
        bytes32 userOpHash = getUserOpHash(userOp);
        require(validateSignature(userOpHash, userOp.signature), "Invalid signature");

        // ❌ VULNERABILITY: Modify UserOperation after signature validation!
        // This should NEVER happen - signature becomes invalid
        userOp.callGasLimit = 10000000; // Increase gas limit
        userOp.maxFeePerGas = 1000 gwei; // Increase fee

        // Execute with modified parameters
        executeUserOp(userOp);

        return 0;
    }

    function getUserOpHash(UserOperation memory userOp) public view returns (bytes32) {
        return keccak256(abi.encode(
            userOp.sender,
            userOp.nonce,
            keccak256(userOp.callData)
            // ❌ VULNERABILITY 3: Hash doesn't include chainId! (aa-user-operation-replay)
            // Missing: block.chainid
            // This allows replay attacks across different chains!
        ));
    }

    function validateSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        // Simplified signature validation
        return true; // In real implementation, would verify ECDSA signature
    }

    function executeUserOp(UserOperation memory userOp) internal {
        // Execution logic
    }
}

contract VulnerableSignatureAggregation {
    uint256 public threshold = 3;
    mapping(address => bool) public isOwner;

    // ❌ VULNERABILITY 4: Batch validation without individual signature checks (aa-signature-aggregation-bypass)
    function validateBatchOperations(
        UserOperation[] calldata userOps,
        bytes calldata aggregatedSignature
    ) external returns (bool) {
        // ❌ Only checks aggregated signature, not individual UserOp signatures!
        // Missing: for (uint i = 0; i < userOps.length; i++) { validateIndividual(userOps[i]); }

        bytes32 batchHash = keccak256(abi.encode(userOps));
        // Verify only the batch signature, not individual operations
        require(verifyAggregatedSignature(batchHash, aggregatedSignature), "Invalid batch signature");

        // ❌ VULNERABILITY 5: Missing array length validation (aa-signature-aggregation-bypass)
        // Missing: require(userOps.length == expectedSignatures.length, "Length mismatch");

        return true;
    }

    // ❌ VULNERABILITY 6: No unique operation IDs (aa-signature-aggregation-bypass)
    function executeBatchOperations(
        UserOperation[] calldata userOps
    ) external {
        // Missing: Generate unique ID for each operation
        // Missing: bytes32 opId = keccak256(abi.encode(userOps[i], nonce, block.chainid));

        for (uint i = 0; i < userOps.length; i++) {
            // Execute without checking if operation was already executed
            executeOperation(userOps[i]);
        }
    }

    // ❌ VULNERABILITY 7: Signature aggregation without duplicate signer check (aa-signature-aggregation-bypass)
    function validateMultiSig(
        bytes32 messageHash,
        address[] calldata signers,
        bytes[] calldata signatures
    ) external view returns (bool) {
        // ❌ Missing: Duplicate signer check!
        // Attacker could provide same signature 3 times to bypass threshold
        // Missing: for (uint i = 0; i < signers.length; i++) {
        //     for (uint j = i+1; j < signers.length; j++) {
        //         require(signers[i] != signers[j], "Duplicate signer");
        //     }
        // }

        require(signers.length >= threshold, "Insufficient signers");

        for (uint i = 0; i < signers.length; i++) {
            require(isOwner[signers[i]], "Not an owner");
            // Verify signature (simplified)
        }

        return true;
    }

    function verifyAggregatedSignature(bytes32 hash, bytes calldata signature) internal pure returns (bool) {
        return true; // Simplified
    }

    function executeOperation(UserOperation calldata userOp) internal {
        // Execution logic
    }
}

contract VulnerableUserOperationReplay {
    mapping(uint256 => bool) public usedNonces;
    address public owner;

    // ❌ VULNERABILITY 8: Missing nonce validation (aa-user-operation-replay)
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256) {
        // ❌ No nonce validation at all!
        // Missing: require(!usedNonces[userOp.nonce], "Nonce already used");
        // Missing: require(userOp.nonce == currentNonce, "Invalid nonce");
        // Missing: usedNonces[userOp.nonce] = true;

        // Validate signature
        require(validateSignature(userOpHash, userOp.signature), "Invalid signature");

        return 0;
    }

    // ❌ VULNERABILITY 9: No chain ID validation (aa-user-operation-replay)
    // UserOps can be replayed across different chains
    function getUserOpHash(UserOperation calldata userOp) public pure returns (bytes32) {
        return keccak256(abi.encode(
            userOp.sender,
            userOp.nonce,
            keccak256(userOp.callData)
            // ❌ Missing: block.chainid
            // This allows same UserOp to be replayed on different chains!
        ));
    }

    // ❌ VULNERABILITY 10: UserOp hash doesn't include all fields (aa-user-operation-replay)
    function getIncompleteUserOpHash(UserOperation calldata userOp) public pure returns (bytes32) {
        return keccak256(abi.encode(
            userOp.sender,
            userOp.nonce
            // ❌ Missing: callData, callGasLimit, verificationGasLimit, etc.
            // Attacker could change these fields and replay with same signature!
        ));
    }

    function validateSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        return true; // Simplified
    }
}

/**
 * @notice Secure implementations for comparison
 */
contract SecureSignatureValidation {
    address public owner;
    mapping(uint256 => bool) public usedNonces;
    uint256 public currentNonce;

    // ✅ Secure calldata handling
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256) {
        // ✅ Generate hash that includes ALL fields
        bytes32 completeHash = keccak256(abi.encode(
            userOp.sender,
            userOp.nonce,
            keccak256(userOp.initCode),
            keccak256(userOp.callData), // ✅ Signature covers final calldata
            userOp.callGasLimit,
            userOp.verificationGasLimit,
            userOp.preVerificationGas,
            userOp.maxFeePerGas,
            userOp.maxPriorityFeePerGas,
            keccak256(userOp.paymasterAndData),
            block.chainid // ✅ Include chain ID for replay protection
        ));

        // ✅ Validate signature covers complete operation
        require(validateSignature(completeHash, userOp.signature), "Invalid signature");

        // ✅ Nonce validation for replay protection
        require(userOp.nonce == currentNonce, "Invalid nonce");
        require(!usedNonces[userOp.nonce], "Nonce already used");
        usedNonces[userOp.nonce] = true;
        currentNonce++;

        // ✅ Execute with validated, immutable calldata
        (address target, uint256 value, bytes memory data) = abi.decode(
            userOp.callData,
            (address, uint256, bytes)
        );

        (bool success,) = target.call{value: value}(data);
        require(success, "Execution failed");

        return 0;
    }

    function validateSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        return true; // Simplified
    }
}

contract SecureSignatureAggregation {
    uint256 public threshold = 3;
    mapping(address => bool) public isOwner;
    mapping(bytes32 => bool) public executedOperations;

    // ✅ Secure batch validation
    function validateBatchOperations(
        UserOperation[] calldata userOps,
        bytes[] calldata signatures
    ) external returns (bool) {
        // ✅ Array length validation
        require(userOps.length == signatures.length, "Length mismatch");
        require(userOps.length > 0, "Empty batch");

        // ✅ Validate each operation individually
        for (uint i = 0; i < userOps.length; i++) {
            // ✅ Generate unique operation ID
            bytes32 opId = keccak256(abi.encode(
                userOps[i].sender,
                userOps[i].nonce,
                userOps[i].callData,
                block.chainid
            ));

            // ✅ Check for replay
            require(!executedOperations[opId], "Operation already executed");

            // ✅ Validate individual signature
            bytes32 userOpHash = getUserOpHash(userOps[i]);
            require(validateSignature(userOpHash, signatures[i]), "Invalid signature");

            executedOperations[opId] = true;
        }

        return true;
    }

    // ✅ Secure multi-sig with duplicate check
    function validateMultiSig(
        bytes32 messageHash,
        address[] calldata signers,
        bytes[] calldata signatures
    ) external view returns (bool) {
        require(signers.length >= threshold, "Insufficient signers");
        require(signers.length == signatures.length, "Length mismatch");

        // ✅ Check for duplicate signers
        for (uint i = 0; i < signers.length; i++) {
            require(isOwner[signers[i]], "Not an owner");

            // ✅ Duplicate signer check
            for (uint j = i + 1; j < signers.length; j++) {
                require(signers[i] != signers[j], "Duplicate signer");
            }

            // Verify signature
            require(validateSignature(messageHash, signatures[i]), "Invalid signature");
        }

        return true;
    }

    function getUserOpHash(UserOperation calldata userOp) internal view returns (bytes32) {
        return keccak256(abi.encode(
            userOp.sender,
            userOp.nonce,
            keccak256(userOp.callData),
            block.chainid
        ));
    }

    function validateSignature(bytes32 hash, bytes memory signature) internal pure returns (bool) {
        return true; // Simplified
    }
}
