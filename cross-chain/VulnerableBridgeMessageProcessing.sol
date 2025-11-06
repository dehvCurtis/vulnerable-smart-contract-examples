// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableBridgeMessageProcessing
 * @notice Test contract for bridge message processing vulnerabilities
 *
 * DETECTORS TO TEST:
 * - bridge-message-verification (Critical)
 * - cross-chain-replay (Critical)
 * - missing-chainid-validation (High)
 *
 * VULNERABILITIES:
 * 1. Missing signature verification in message processing
 * 2. Missing Merkle proof validation
 * 3. No replay protection (processed messages can be re-executed)
 * 4. Missing chain ID validation (allows cross-chain replay attacks)
 * 5. Missing nonce/sequence validation
 * 6. No finality checks before message execution
 * 7. Weak cryptographic validation
 */

/**
 * @notice Vulnerable bridge without signature verification
 */
contract VulnerableBridgeNoSignature {
    struct Message {
        address target;
        bytes data;
        uint256 value;
        uint256 nonce;
    }

    mapping(uint256 => bool) public processedNonces;
    address public relayer;

    constructor() {
        relayer = msg.sender;
    }

    // ❌ VULNERABILITY 1: No signature verification (bridge-message-verification)
    // Anyone can submit arbitrary messages!
    function processMessage(
        address target,
        bytes calldata data,
        uint256 value,
        uint256 nonce
    ) external {
        // ❌ No signature verification!
        // ❌ No proof validation!
        // ❌ Anyone can call this and execute arbitrary calls!

        require(!processedNonces[nonce], "Already processed");
        processedNonces[nonce] = true;

        (bool success,) = target.call{value: value}(data);
        require(success, "Call failed");
    }

    // ❌ VULNERABILITY 2: Signature check without message hash validation
    function processMessageWeakSig(
        address target,
        bytes calldata data,
        uint256 value,
        uint256 nonce,
        bytes calldata signature
    ) external {
        // ❌ Signature length check is NOT sufficient!
        require(signature.length == 65, "Invalid signature");

        // ❌ No actual signature verification against message hash!
        // ❌ No ecrecover or similar cryptographic validation!

        require(!processedNonces[nonce], "Already processed");
        processedNonces[nonce] = true;

        (bool success,) = target.call{value: value}(data);
        require(success);
    }

    receive() external payable {}
}

/**
 * @notice Vulnerable bridge without Merkle proof validation
 */
contract VulnerableBridgeNoMerkleProof {
    bytes32 public stateRoot;
    mapping(bytes32 => bool) public processedMessages;

    function updateStateRoot(bytes32 newRoot) external {
        stateRoot = newRoot;
    }

    // ❌ VULNERABILITY 3: No Merkle proof validation (bridge-message-verification)
    function executeMessage(
        address target,
        bytes calldata data,
        bytes32 messageHash,
        bytes32[] calldata proof // ❌ proof parameter exists but NOT validated!
    ) external {
        require(!processedMessages[messageHash], "Already processed");

        // ❌ No Merkle proof verification against stateRoot!
        // ❌ Anyone can provide fake proof!
        // Should verify: verifyMerkleProof(messageHash, proof, stateRoot)

        processedMessages[messageHash] = true;

        (bool success,) = target.call(data);
        require(success);
    }

    // ❌ VULNERABILITY 4: Incomplete Merkle validation
    function executeMessageWeakProof(
        address target,
        bytes calldata data,
        bytes32 messageHash,
        bytes32[] calldata proof
    ) external {
        require(!processedMessages[messageHash], "Already processed");

        // ❌ Only checks proof length, doesn't validate proof!
        require(proof.length > 0, "Invalid proof");

        // ❌ No cryptographic verification of proof against stateRoot!

        processedMessages[messageHash] = true;

        (bool success,) = target.call(data);
        require(success);
    }
}

/**
 * @notice Vulnerable bridge with replay attack issues
 */
contract VulnerableBridgeReplay {
    struct CrossChainMessage {
        uint256 sourceChainId;
        uint256 destinationChainId;
        address target;
        bytes data;
        uint256 nonce;
    }

    address public validator;

    constructor() {
        validator = msg.sender;
    }

    // ❌ VULNERABILITY 5: No replay protection (cross-chain-replay)
    function processMessage(
        uint256 sourceChainId,
        address target,
        bytes calldata data,
        uint256 nonce,
        bytes calldata signature
    ) external {
        // ❌ No mapping to track processed messages!
        // ❌ Same message can be executed multiple times!

        // Validate signature
        bytes32 messageHash = keccak256(
            abi.encodePacked(sourceChainId, target, data, nonce)
        );
        require(verifySignature(messageHash, signature), "Invalid signature");

        // ❌ No check: require(!processed[messageHash])
        // ❌ No set: processed[messageHash] = true

        (bool success,) = target.call(data);
        require(success);
    }

    // ❌ VULNERABILITY 6: Replay protection without nonce (cross-chain-replay)
    mapping(bytes32 => bool) public executed;

    function processMessageHashOnly(
        uint256 sourceChainId,
        address target,
        bytes calldata data,
        bytes calldata signature
    ) external {
        // ❌ No nonce in message hash!
        // If message needs to be sent twice legitimately, it can't be!
        // But also vulnerable if hash collision or replay needed

        bytes32 messageHash = keccak256(
            abi.encodePacked(sourceChainId, target, data)
        );

        require(!executed[messageHash], "Already executed");
        require(verifySignature(messageHash, signature), "Invalid signature");

        executed[messageHash] = true;

        (bool success,) = target.call(data);
        require(success);
    }

    // Helper function for signature verification
    function verifySignature(bytes32 hash, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        if (signature.length != 65) return false;

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );

        address signer = ecrecover(ethSignedHash, v, r, s);
        return signer == validator;
    }
}

/**
 * @notice Vulnerable bridge without chain ID validation
 */
contract VulnerableBridgeNoChainId {
    mapping(uint256 => bool) public processedNonces;
    address public validator;

    constructor() {
        validator = msg.sender;
    }

    // ❌ VULNERABILITY 7: Missing chain ID validation (missing-chainid-validation)
    // Messages can be replayed across different chains!
    function processMessage(
        address target,
        bytes calldata data,
        uint256 nonce,
        bytes calldata signature
    ) external {
        require(!processedNonces[nonce], "Already processed");

        // ❌ Message hash does NOT include chain ID!
        // ❌ Same signature valid on all chains!
        // Attacker can replay transaction from mainnet to L2, Arbitrum, etc.
        bytes32 messageHash = keccak256(abi.encodePacked(target, data, nonce));

        require(verifySignature(messageHash, signature), "Invalid signature");

        processedNonces[nonce] = true;

        (bool success,) = target.call(data);
        require(success);
    }

    // ❌ VULNERABILITY 8: Chain ID in hash but no runtime validation (missing-chainid-validation)
    function processMessageWithChainIdInHash(
        uint256 sourceChainId,
        uint256 destinationChainId, // ❌ Parameter exists but NOT validated!
        address target,
        bytes calldata data,
        uint256 nonce,
        bytes calldata signature
    ) external {
        require(!processedNonces[nonce], "Already processed");

        // ✅ Chain ID is in hash (prevents signature replay)
        bytes32 messageHash = keccak256(
            abi.encodePacked(sourceChainId, destinationChainId, target, data, nonce)
        );

        require(verifySignature(messageHash, signature), "Invalid signature");

        // ❌ But no runtime check: require(destinationChainId == block.chainid)
        // Message intended for Ethereum can be executed on Arbitrum!

        processedNonces[nonce] = true;

        (bool success,) = target.call(data);
        require(success);
    }

    // ❌ VULNERABILITY 9: No chain ID anywhere (missing-chainid-validation)
    function executeMessageNoChainId(
        address target,
        bytes calldata data,
        bytes calldata signature
    ) external {
        // ❌ No chain ID in hash
        // ❌ No chain ID validation
        // Complete cross-chain replay vulnerability!

        bytes32 messageHash = keccak256(abi.encodePacked(target, data));
        require(verifySignature(messageHash, signature), "Invalid signature");

        (bool success,) = target.call(data);
        require(success);
    }

    function verifySignature(bytes32 hash, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        if (signature.length != 65) return false;

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );

        address signer = ecrecover(ethSignedHash, v, r, s);
        return signer == validator;
    }
}

/**
 * @notice Vulnerable bridge with sequence/ordering issues
 */
contract VulnerableBridgeOrdering {
    uint256 public nextExpectedNonce;
    mapping(bytes32 => bool) public executed;
    address public validator;

    constructor() {
        validator = msg.sender;
        nextExpectedNonce = 1;
    }

    // ❌ VULNERABILITY 10: No sequence enforcement (cross-chain-message-ordering)
    function processMessageUnordered(
        address target,
        bytes calldata data,
        uint256 nonce,
        bytes calldata signature
    ) external {
        bytes32 messageHash = keccak256(
            abi.encodePacked(block.chainid, target, data, nonce)
        );

        require(!executed[messageHash], "Already executed");
        require(verifySignature(messageHash, signature), "Invalid signature");

        // ❌ No check: require(nonce == nextExpectedNonce)
        // Messages can be processed out of order!
        // This may break dependent operations

        executed[messageHash] = true;

        (bool success,) = target.call(data);
        require(success);
    }

    function verifySignature(bytes32 hash, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        if (signature.length != 65) return false;

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );

        address signer = ecrecover(ethSignedHash, v, r, s);
        return signer == validator;
    }
}

/**
 * @notice Secure bridge implementation
 */
contract SecureBridge {
    struct Message {
        uint256 sourceChainId;
        uint256 destinationChainId;
        address target;
        bytes data;
        uint256 value;
        uint256 nonce;
    }

    mapping(bytes32 => bool) public processedMessages;
    bytes32 public stateRoot;
    address public validator;

    constructor() {
        validator = msg.sender;
    }

    modifier onlyValidator() {
        require(msg.sender == validator, "Not validator");
        _;
    }

    function updateStateRoot(bytes32 newRoot) external onlyValidator {
        stateRoot = newRoot;
    }

    // ✅ Secure message processing
    function processMessage(
        Message calldata message,
        bytes32[] calldata merkleProof,
        bytes calldata signature
    ) external {
        // ✅ 1. Validate destination chain
        require(message.destinationChainId == block.chainid, "Wrong chain");

        // ✅ 2. Generate message hash with all fields including chain IDs
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                message.sourceChainId,
                message.destinationChainId,
                message.target,
                message.data,
                message.value,
                message.nonce
            )
        );

        // ✅ 3. Check replay protection
        require(!processedMessages[messageHash], "Already processed");

        // ✅ 4. Verify Merkle proof
        require(verifyMerkleProof(messageHash, merkleProof), "Invalid proof");

        // ✅ 5. Verify signature
        require(verifySignature(messageHash, signature), "Invalid signature");

        // ✅ 6. Mark as processed BEFORE external call
        processedMessages[messageHash] = true;

        // ✅ 7. Execute message
        (bool success,) = message.target.call{value: message.value}(message.data);
        require(success, "Execution failed");
    }

    function verifyMerkleProof(bytes32 leaf, bytes32[] calldata proof)
        internal
        view
        returns (bool)
    {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];

            if (computedHash <= proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }

        return computedHash == stateRoot;
    }

    function verifySignature(bytes32 hash, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        if (signature.length != 65) return false;

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );

        address signer = ecrecover(ethSignedHash, v, r, s);
        return signer == validator;
    }

    receive() external payable {}
}
