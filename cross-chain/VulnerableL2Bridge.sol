// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableL2Bridge
 * @notice Test contract for L2 bridge and cross-rollup vulnerabilities
 *
 * DETECTORS TO TEST:
 * - l2-bridge-message-validation (Critical)
 * - cross-rollup-atomicity (Critical)
 * - erc7683-crosschain-validation (High)
 *
 * VULNERABILITIES:
 * 1. Missing Merkle proof validation for L1→L2 messages
 * 2. No finality checks before message execution
 * 3. Cross-rollup atomic operations without rollback mechanism
 * 4. Missing state root verification
 * 5. No sequencer signature validation
 * 6. Cross-chain intent execution without proper validation
 */

/**
 * @notice Vulnerable L1→L2 bridge without proper validation
 */
contract VulnerableL1ToL2Bridge {
    struct L1Message {
        address sender;
        address target;
        bytes data;
        uint256 value;
        uint256 nonce;
    }

    mapping(uint256 => bool) public processedNonces;
    bytes32 public l1StateRoot;

    event MessageProcessed(uint256 indexed nonce, address indexed target);

    function updateL1StateRoot(bytes32 newRoot) external {
        l1StateRoot = newRoot;
    }

    // ❌ VULNERABILITY 1: No Merkle proof validation (l2-bridge-message-validation)
    function processL1Message(
        address sender,
        address target,
        bytes calldata data,
        uint256 value,
        uint256 nonce,
        bytes32[] calldata proof // ❌ proof parameter but NOT validated!
    ) external payable {
        require(!processedNonces[nonce], "Already processed");

        // ❌ No Merkle proof verification!
        // ❌ Anyone can submit fake L1 messages!
        // Should verify: verifyMerkleProof(messageHash, proof, l1StateRoot)

        processedNonces[nonce] = true;

        (bool success,) = target.call{value: value}(data);
        require(success, "Execution failed");

        emit MessageProcessed(nonce, target);
    }

    // ❌ VULNERABILITY 2: No state root validation (l2-bridge-message-validation)
    function executeL1Message(
        address target,
        bytes calldata data,
        uint256 nonce
    ) external {
        require(!processedNonces[nonce], "Already processed");

        // ❌ No validation against L1 state root!
        // ❌ No proof that this message exists on L1!

        processedNonces[nonce] = true;

        (bool success,) = target.call(data);
        require(success);
    }
}

/**
 * @notice Vulnerable L2 bridge without finality checks
 */
contract VulnerableL2BridgeNoFinality {
    struct L1Message {
        uint256 blockNumber;
        address target;
        bytes data;
        bytes32 messageHash;
    }

    mapping(bytes32 => bool) public executed;
    bytes32 public l1StateRoot;
    uint256 public constant FINALITY_BLOCKS = 32; // ~6.5 min on Ethereum

    // ❌ VULNERABILITY 3: No finality checks (l2-bridge-message-validation)
    function processL1Message(
        uint256 l1BlockNumber,
        address target,
        bytes calldata data,
        bytes32 messageHash,
        bytes32[] calldata proof
    ) external {
        require(!executed[messageHash], "Already executed");

        // ❌ No finality check!
        // ❌ Message could be from reorged block!
        // Should check: require(block.number >= l1BlockNumber + FINALITY_BLOCKS)

        require(verifyProof(messageHash, proof), "Invalid proof");

        executed[messageHash] = true;

        (bool success,) = target.call(data);
        require(success);
    }

    // ❌ VULNERABILITY 4: Insufficient finality period (l2-bridge-message-validation)
    function processWithWeakFinality(
        uint256 l1BlockNumber,
        address target,
        bytes calldata data,
        bytes32 messageHash,
        bytes32[] calldata proof
    ) external {
        require(!executed[messageHash], "Already executed");

        // ❌ Only 1 block confirmation - insufficient!
        // Should wait for at least 32 blocks (~6.5 min) on Ethereum
        require(block.number > l1BlockNumber, "Too soon");

        require(verifyProof(messageHash, proof), "Invalid proof");

        executed[messageHash] = true;

        (bool success,) = target.call(data);
        require(success);
    }

    function verifyProof(bytes32 messageHash, bytes32[] calldata proof)
        internal
        view
        returns (bool)
    {
        bytes32 computedHash = messageHash;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];

            if (computedHash <= proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }

        return computedHash == l1StateRoot;
    }
}

/**
 * @notice Vulnerable cross-rollup atomic swap
 */
contract VulnerableCrossRollupSwap {
    enum SwapState {
        Pending,
        Executed,
        Cancelled
    }

    struct CrossRollupSwap {
        address initiator;
        uint256 sourceRollup;
        uint256 targetRollup;
        address sourceToken;
        address targetToken;
        uint256 sourceAmount;
        uint256 targetAmount;
        SwapState state;
    }

    mapping(bytes32 => CrossRollupSwap) public swaps;

    event SwapInitiated(bytes32 indexed swapId);
    event SwapExecuted(bytes32 indexed swapId);

    // ❌ VULNERABILITY 5: No atomicity guarantee (cross-rollup-atomicity)
    function initiateSwap(
        uint256 targetRollup,
        address sourceToken,
        address targetToken,
        uint256 sourceAmount,
        uint256 targetAmount
    ) external returns (bytes32 swapId) {
        swapId = keccak256(
            abi.encodePacked(
                msg.sender,
                block.chainid,
                targetRollup,
                sourceToken,
                targetToken,
                sourceAmount,
                targetAmount,
                block.timestamp
            )
        );

        // ❌ No locking mechanism!
        // ❌ No escrow!
        // ❌ User transfers tokens but no guarantee of completion

        // Transfer source tokens
        (bool success,) = sourceToken.call(
            abi.encodeWithSignature(
                "transferFrom(address,address,uint256)",
                msg.sender,
                address(this),
                sourceAmount
            )
        );
        require(success, "Transfer failed");

        swaps[swapId] = CrossRollupSwap({
            initiator: msg.sender,
            sourceRollup: block.chainid,
            targetRollup: targetRollup,
            sourceToken: sourceToken,
            targetToken: targetToken,
            sourceAmount: sourceAmount,
            targetAmount: targetAmount,
            state: SwapState.Pending
        });

        emit SwapInitiated(swapId);

        // ❌ If target rollup execution fails, funds stuck!
        // ❌ No rollback mechanism!
    }

    // ❌ VULNERABILITY 6: Execute without state validation (cross-rollup-atomicity)
    function executeSwap(bytes32 swapId) external {
        CrossRollupSwap storage swap = swaps[swapId];

        require(swap.state == SwapState.Pending, "Not pending");

        // ❌ No validation that source rollup completed!
        // ❌ No proof from source chain!
        // ❌ No timeout mechanism!

        swap.state = SwapState.Executed;

        emit SwapExecuted(swapId);

        // If this fails, source tokens already transferred but target not!
    }

    // ❌ VULNERABILITY 7: Cancel without rollback (cross-rollup-atomicity)
    function cancelSwap(bytes32 swapId) external {
        CrossRollupSwap storage swap = swaps[swapId];

        require(swap.initiator == msg.sender, "Not initiator");
        require(swap.state == SwapState.Pending, "Not pending");

        // ❌ Marks as cancelled but doesn't refund tokens!
        swap.state = SwapState.Cancelled;

        // ❌ Should return tokens to initiator
        // ❌ No actual rollback of state changes
    }
}

/**
 * @notice Vulnerable sequencer message validation
 */
contract VulnerableSequencerValidation {
    address public sequencer;
    mapping(bytes32 => bool) public processedBatches;

    struct Batch {
        uint256 batchId;
        bytes32 stateRoot;
        bytes32[] transactions;
    }

    constructor() {
        sequencer = msg.sender;
    }

    // ❌ VULNERABILITY 8: No sequencer signature validation (l2-bridge-message-validation)
    function submitBatch(
        uint256 batchId,
        bytes32 stateRoot,
        bytes32[] calldata transactions,
        bytes calldata signature // ❌ signature parameter but NOT validated!
    ) external {
        bytes32 batchHash = keccak256(
            abi.encodePacked(batchId, stateRoot, keccak256(abi.encodePacked(transactions)))
        );

        require(!processedBatches[batchHash], "Already processed");

        // ❌ No signature verification!
        // ❌ Anyone can submit fake batches!
        // Should verify: require(verifySequencerSignature(batchHash, signature))

        processedBatches[batchHash] = true;

        // Process batch...
    }

    // ❌ VULNERABILITY 9: Weak sequencer validation (l2-bridge-message-validation)
    function submitBatchWeakValidation(
        uint256 batchId,
        bytes32 stateRoot,
        bytes32[] calldata transactions
    ) external {
        // ❌ Only checks msg.sender == sequencer
        // ❌ If sequencer key compromised, entire L2 vulnerable!
        // ❌ No multi-sig or additional validation!
        require(msg.sender == sequencer, "Not sequencer");

        bytes32 batchHash = keccak256(
            abi.encodePacked(batchId, stateRoot, keccak256(abi.encodePacked(transactions)))
        );

        require(!processedBatches[batchHash], "Already processed");

        processedBatches[batchHash] = true;
    }
}

/**
 * @notice Vulnerable ERC-7683 cross-chain intent
 */
contract VulnerableCrossChainIntent {
    struct CrossChainOrder {
        address initiator;
        uint256 sourceChain;
        uint256 destinationChain;
        address inputToken;
        address outputToken;
        uint256 inputAmount;
        uint256 outputAmount;
        uint256 deadline;
    }

    mapping(bytes32 => bool) public filled;

    // ❌ VULNERABILITY 10: No origin validation (erc7683-crosschain-validation)
    function fillOrder(
        CrossChainOrder calldata order,
        bytes calldata signature
    ) external {
        bytes32 orderHash = keccak256(abi.encode(order));

        require(!filled[orderHash], "Already filled");
        require(block.timestamp <= order.deadline, "Expired");

        // ❌ No validation that order came from source chain!
        // ❌ No proof of order initiation!
        // ❌ Signature validated but not against verified source!

        require(verifySignature(orderHash, signature), "Invalid signature");

        filled[orderHash] = true;

        // Transfer tokens...
    }

    // ❌ VULNERABILITY 11: No settlement validation (erc7683-crosschain-validation)
    function settleOrder(bytes32 orderHash) external {
        require(filled[orderHash], "Not filled");

        // ❌ No validation that output was received on destination!
        // ❌ No proof from destination chain!
        // ❌ User could claim settlement without completing transfer!

        // Mark as settled...
    }

    function verifySignature(bytes32 hash, bytes calldata signature)
        internal
        pure
        returns (bool)
    {
        return signature.length == 65;
    }
}

/**
 * @notice Secure L2 bridge implementation
 */
contract SecureL2Bridge {
    struct L1Message {
        address sender;
        address target;
        bytes data;
        uint256 value;
        uint256 l1BlockNumber;
        uint256 nonce;
    }

    mapping(bytes32 => bool) public executed;
    bytes32 public l1StateRoot;
    address public sequencer;
    uint256 public constant FINALITY_BLOCKS = 32;

    event MessageExecuted(bytes32 indexed messageHash);

    constructor(address _sequencer) {
        sequencer = _sequencer;
    }

    // ✅ Secure L1→L2 message processing
    function processL1Message(
        L1Message calldata message,
        bytes32[] calldata merkleProof,
        bytes calldata sequencerSignature
    ) external payable {
        // ✅ 1. Generate message hash
        bytes32 messageHash = keccak256(
            abi.encode(
                message.sender,
                message.target,
                message.data,
                message.value,
                message.l1BlockNumber,
                message.nonce
            )
        );

        // ✅ 2. Check replay protection
        require(!executed[messageHash], "Already executed");

        // ✅ 3. Verify finality
        require(
            block.number >= message.l1BlockNumber + FINALITY_BLOCKS,
            "Insufficient finality"
        );

        // ✅ 4. Verify Merkle proof against L1 state root
        require(verifyMerkleProof(messageHash, merkleProof), "Invalid Merkle proof");

        // ✅ 5. Verify sequencer signature
        require(
            verifySequencerSignature(messageHash, sequencerSignature),
            "Invalid sequencer signature"
        );

        // ✅ 6. Mark as executed BEFORE external call
        executed[messageHash] = true;

        // ✅ 7. Execute message
        (bool success,) = message.target.call{value: message.value}(message.data);
        require(success, "Execution failed");

        emit MessageExecuted(messageHash);
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

        return computedHash == l1StateRoot;
    }

    function verifySequencerSignature(bytes32 hash, bytes calldata signature)
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
        return signer == sequencer;
    }

    function updateL1StateRoot(bytes32 newRoot, bytes calldata signature) external {
        require(
            verifySequencerSignature(newRoot, signature),
            "Invalid signature"
        );

        l1StateRoot = newRoot;
    }

    receive() external payable {}
}
