// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Final Edge Cases Security Patterns
 * @notice Tests final specialized and ultra-niche security detectors
 * @dev Tests: fraud proof timing, AVS validation, cross-rollup atomicity,
 *             L2 bridge validation, oracle heartbeat, and other rare patterns
 */

// =====================================================================
// 1. OPTIMISTIC FRAUD PROOF TIMING
// =====================================================================

/**
 * @dev Fraud proof timing issues
 */
contract VulnerableFraudProofTiming {
    struct FraudProof {
        bytes32 stateRoot;
        uint256 timestamp;
        bool verified;
    }

    mapping(bytes32 => FraudProof) public fraudProofs;
    uint256 public constant FRAUD_PROOF_WINDOW = 7 days;

    // ❌ VULNERABILITY 1: Fraud proof submitted after window
    function submitFraudProof(bytes32 withdrawalId, bytes32 stateRoot, bytes calldata proof)
        external
    {
        // ❌ CRITICAL: No timing validation
        // ❌ Fraud proofs can be submitted too late
        // ❌ Challenge window may have expired

        fraudProofs[withdrawalId] = FraudProof({
            stateRoot: stateRoot,
            timestamp: block.timestamp,
            verified: false
        });

        // ❌ Missing: Withdrawal timestamp check
        // ❌ Missing: require(block.timestamp <= withdrawal.timestamp + FRAUD_PROOF_WINDOW)
        // ❌ Missing: Window expiration validation
    }

    // ❌ VULNERABILITY 2: No deadline for fraud proof verification
    function verifyFraudProof(bytes32 withdrawalId) external {
        // ❌ Can verify fraud proof at any time
        // ❌ No upper bound on verification time

        FraudProof storage proof = fraudProofs[withdrawalId];
        proof.verified = true;

        // ❌ Missing: Time bounds on verification
    }
}

// =====================================================================
// 2. CROSS-ROLLUP ATOMICITY
// =====================================================================

/**
 * @dev Cross-rollup operations without atomicity guarantees
 */
contract VulnerableCrossRollupAtomicity {
    struct CrossRollupTransfer {
        address sourceChain;
        address destChain;
        uint256 amount;
        bool sourceCompleted;
        bool destCompleted;
    }

    mapping(bytes32 => CrossRollupTransfer) public transfers;

    // ❌ VULNERABILITY: No atomicity between rollups
    function initiateCrossRollupTransfer(
        address destChain,
        uint256 amount,
        bytes32 transferId
    ) external {
        // ❌ CRITICAL: Source completes without dest guarantee
        // ❌ Funds can be lost if dest fails
        // ❌ No rollback mechanism

        transfers[transferId].sourceChain = address(this);
        transfers[transferId].destChain = destChain;
        transfers[transferId].amount = amount;
        transfers[transferId].sourceCompleted = true;

        // ❌ Missing: Atomic commit protocol
        // ❌ Missing: Two-phase commit
        // ❌ Missing: Rollback on dest failure
    }

    // Destination may fail after source completes
    function completeCrossRollupTransfer(bytes32 transferId) external {
        // ❌ If this fails, source already completed
        // ❌ Funds stuck

        transfers[transferId].destCompleted = true;
    }
}

// =====================================================================
// 3. L2 BRIDGE MESSAGE VALIDATION
// =====================================================================

/**
 * @dev L2 bridge without proper message validation
 */
contract VulnerableL2BridgeValidation {
    struct BridgeMessage {
        bytes32 messageHash;
        address sender;
        uint256 nonce;
        bool executed;
    }

    mapping(bytes32 => BridgeMessage) public messages;

    // ❌ VULNERABILITY: L2 bridge message without validation
    function processL2Message(bytes32 messageHash, bytes calldata message, bytes calldata proof)
        external
    {
        // ❌ CRITICAL: No L1 inclusion proof
        // ❌ No merkle proof verification
        // ❌ No state root validation
        // ❌ Anyone can submit fake L2 messages

        messages[messageHash].messageHash = messageHash;
        messages[messageHash].sender = msg.sender;
        messages[messageHash].executed = true;

        // Execute message without validation
        // ❌ Missing: L1 state root verification
        // ❌ Missing: Merkle proof validation
        // ❌ Missing: Sequencer signature check
    }
}

// =====================================================================
// 4. AVS (ACTIVELY VALIDATED SERVICES) ADVANCED
// =====================================================================

/**
 * @dev AVS with advanced validation issues
 */
contract VulnerableAVSAdvanced {
    struct Task {
        bytes32 taskHash;
        uint256 quorum;
        uint256 validatorCount;
        mapping(address => bool) validators;
    }

    mapping(bytes32 => Task) public tasks;

    // ❌ VULNERABILITY: AVS validation without stake verification
    function submitTaskResult(bytes32 taskHash, bytes calldata result, address[] calldata signers)
        external
    {
        // ❌ CRITICAL: No stake amount verification
        // ❌ Validators may not have sufficient stake
        // ❌ No slashing conditions validated

        Task storage task = tasks[taskHash];

        for (uint256 i = 0; i < signers.length; i++) {
            // ❌ Missing: Stake verification
            // ❌ Missing: require(getValidatorStake(signers[i]) >= MIN_STAKE)
            // ❌ Missing: Slashable stake check

            task.validators[signers[i]] = true;
        }

        task.validatorCount = signers.length;

        // ❌ Missing: Quorum calculation based on stake weight
        // ❌ Missing: BLS signature aggregation verification
    }
}

// =====================================================================
// 5. CROSS-CHAIN MESSAGE ORDERING
// =====================================================================

/**
 * @dev Cross-chain messages without ordering guarantees
 */
contract VulnerableCrossChainOrdering {
    struct Message {
        uint256 sequence;
        bytes payload;
        bool executed;
    }

    mapping(uint256 => Message) public messages;
    uint256 public lastExecutedSequence;

    // ❌ VULNERABILITY: Messages executed out of order
    function executeMessage(uint256 sequence, bytes calldata payload) external {
        // ❌ CRITICAL: No sequence validation
        // ❌ Messages can be executed out of order
        // ❌ Can skip sequence numbers

        Message storage message = messages[sequence];
        message.sequence = sequence;
        message.payload = payload;
        message.executed = true;

        // ❌ Missing: require(sequence == lastExecutedSequence + 1)
        // ❌ Missing: Sequential ordering enforcement
        // ❌ Missing: Gap detection

        // Process message
    }
}

// =====================================================================
// 6. ERC-7683 CROSS-CHAIN VALIDATION
// =====================================================================

/**
 * @dev ERC-7683 intents without cross-chain validation
 */
contract VulnerableERC7683CrossChain {
    struct CrossChainIntent {
        address user;
        uint256 sourceChainId;
        uint256 destChainId;
        bytes32 intentHash;
        bool fulfilled;
    }

    mapping(bytes32 => CrossChainIntent) public intents;

    // ❌ VULNERABILITY: Cross-chain intent without validation
    function fulfillCrossChainIntent(
        bytes32 intentHash,
        uint256 sourceChainId,
        bytes calldata proof
    ) external {
        // ❌ CRITICAL: No source chain state verification
        // ❌ No merkle proof of intent on source
        // ❌ Can claim fulfillment without source validation

        CrossChainIntent storage intent = intents[intentHash];
        intent.sourceChainId = sourceChainId;
        intent.fulfilled = true;

        // ❌ Missing: Source chain state root verification
        // ❌ Missing: Intent existence proof
        // ❌ Missing: Cross-chain message validation
    }
}

// =====================================================================
// 7. LRT (LIQUID RESTAKING TOKEN) SHARE INFLATION
// =====================================================================

/**
 * @dev LRT with share inflation vulnerability
 */
contract VulnerableLRTShareInflation {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    uint256 public totalAssets;

    // ❌ VULNERABILITY: LRT first depositor share inflation
    function depositForLRT(uint256 amount) external {
        uint256 sharesToMint;

        if (totalShares == 0) {
            // ❌ CRITICAL: First deposit vulnerable to inflation
            // Attacker can:
            // 1. Deposit 1 wei → Get 1 share
            // 2. Donate large amount via restaking rewards
            // 3. Next depositor gets 0 shares due to rounding

            sharesToMint = amount;
        } else {
            // ❌ Uses current assets including donations
            sharesToMint = (amount * totalShares) / totalAssets;
        }

        shares[msg.sender] += sharesToMint;
        totalShares += sharesToMint;
        totalAssets += amount;

        // ❌ Missing: Virtual shares/assets for LRT
        // ❌ Missing: Minimum first deposit
    }
}

// =====================================================================
// 8. BRIDGE TOKEN MINTING CONTROL
// =====================================================================

/**
 * @dev Bridge with unchecked token minting
 */
contract VulnerableBridgeTokenMint {
    mapping(address => uint256) public balances;
    mapping(bytes32 => bool) public processedMessages;

    // ❌ VULNERABILITY: Bridge mints without proper validation
    function mintBridgedTokens(
        address to,
        uint256 amount,
        bytes32 messageId,
        bytes calldata signature
    ) external {
        // ❌ CRITICAL: No minting limit
        // ❌ Weak signature validation
        // ❌ Can mint unlimited tokens

        require(!processedMessages[messageId], "Already processed");
        processedMessages[messageId] = true;

        // ❌ Missing: Signature verification
        // ❌ Missing: Minting cap per message
        // ❌ Missing: Time window validation
        // ❌ Missing: Source chain verification

        balances[to] += amount;

        // ❌ Bridge can be exploited to mint arbitrary amounts
    }
}

// =====================================================================
// 9. CELESTIA DATA AVAILABILITY ADVANCED
// =====================================================================

/**
 * @dev Celestia DA with advanced issues
 */
contract VulnerableCelestiaDAAdvanced {
    struct DataAvailability {
        bytes32 dataRoot;
        uint256 blockHeight;
        bool verified;
    }

    mapping(bytes32 => DataAvailability) public daProofs;

    // ❌ VULNERABILITY: Celestia DA without proper verification
    function submitDataAvailability(bytes32 dataRoot, uint256 blockHeight, bytes calldata daProof)
        external
    {
        // ❌ CRITICAL: No data availability sampling
        // ❌ No namespace verification
        // ❌ No data square verification

        daProofs[dataRoot].dataRoot = dataRoot;
        daProofs[dataRoot].blockHeight = blockHeight;
        daProofs[dataRoot].verified = true;

        // ❌ Missing: DAS (Data Availability Sampling)
        // ❌ Missing: Namespace ID validation
        // ❌ Missing: Block header verification
        // ❌ Missing: Merkle proof of data square
    }
}

// =====================================================================
// 10. SOVEREIGN ROLLUP STATE VALIDATION
// =====================================================================

/**
 * @dev Sovereign rollup with state validation issues
 */
contract VulnerableSovereignRollupAdvanced {
    bytes32 public stateRoot;
    uint256 public blockNumber;

    struct StateTransition {
        bytes32 prevRoot;
        bytes32 newRoot;
        bytes32 transitionProof;
    }

    mapping(uint256 => StateTransition) public transitions;

    // ❌ VULNERABILITY: Sovereign rollup state without validation
    function applyStateTransition(
        bytes32 newRoot,
        bytes32 transitionProof,
        bytes calldata zkProof
    ) external {
        // ❌ CRITICAL: No ZK proof verification
        // ❌ State transition not validated
        // ❌ Anyone can propose invalid states

        transitions[blockNumber] = StateTransition({
            prevRoot: stateRoot,
            newRoot: newRoot,
            transitionProof: transitionProof
        });

        stateRoot = newRoot;
        blockNumber++;

        // ❌ Missing: ZK-SNARK/STARK proof verification
        // ❌ Missing: State transition function validation
        // ❌ Missing: Validator consensus
    }
}

// =====================================================================
// 11. METAMORPHIC CONTRACT ADVANCED
// =====================================================================

/**
 * @dev Metamorphic contract factory
 */
contract VulnerableMetamorphicFactory {
    // ❌ VULNERABILITY: CREATE2 + SELFDESTRUCT enables metamorphic pattern
    function deployMetamorphic(bytes32 salt, bytes memory bytecode)
        external
        returns (address deployed)
    {
        // ❌ CRITICAL: Can deploy, selfdestruct, redeploy at same address
        // ❌ Breaks immutability assumptions
        // ❌ Allows contract code changes at same address

        assembly {
            deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }

        // Pattern:
        // 1. Deploy contract via CREATE2 at deterministic address
        // 2. Contract can SELFDESTRUCT
        // 3. Redeploy different code at same address
        // ❌ Enables rug pulls and malicious code swaps
    }

    // Helper to calculate deployment address
    function predictAddress(bytes32 salt, bytes memory bytecode) external view returns (address) {
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff), address(this), salt, keccak256(bytecode)
                        )
                    )
                )
            )
        );
    }
}

// =====================================================================
// 12. ADDITIONAL NICHE PATTERNS
// =====================================================================

/**
 * @dev Division before multiplication
 */
contract VulnerableDivisionBeforeMultiplication {
    // ❌ VULNERABILITY: Division before multiplication causes precision loss
    function calculateReward(uint256 amount, uint256 rate, uint256 denominator)
        external
        pure
        returns (uint256)
    {
        // ❌ CRITICAL: Divides first, then multiplies
        // ❌ Loses precision

        uint256 intermediate = amount / denominator;
        return intermediate * rate;

        // ✅ CORRECT: return (amount * rate) / denominator;
    }
}

/**
 * @dev ERC-1155 batch validation
 */
contract VulnerableERC1155Batch {
    mapping(uint256 => mapping(address => uint256)) public balances;

    // ❌ VULNERABILITY: Batch transfer without validation
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts
    ) external {
        // ❌ No array length validation
        // ❌ Arrays can be different lengths

        // ❌ Missing: require(ids.length == amounts.length)

        for (uint256 i = 0; i < ids.length; i++) {
            // ❌ Can go out of bounds if arrays differ
            balances[ids[i]][from] -= amounts[i];
            balances[ids[i]][to] += amounts[i];
        }
    }
}

/**
 * @dev ERC-721 enumeration DOS
 */
contract VulnerableERC721Enumeration {
    uint256[] public allTokens;
    mapping(uint256 => uint256) public allTokensIndex;

    // ❌ VULNERABILITY: Unbounded array iteration
    function removeToken(uint256 tokenId) external {
        uint256 lastTokenIndex = allTokens.length - 1;
        uint256 tokenIndex = allTokensIndex[tokenId];

        // ❌ DOS: Removing from middle of array is O(n)
        // ❌ For large collections, this can exceed gas limit

        uint256 lastTokenId = allTokens[lastTokenIndex];
        allTokens[tokenIndex] = lastTokenId;
        allTokensIndex[lastTokenId] = tokenIndex;

        allTokens.pop();
        delete allTokensIndex[tokenId];

        // ❌ Enumeration operations can DOS with many tokens
    }
}

/**
 * @dev ERC-777 reentrancy via hooks
 */
contract VulnerableERC777Hooks {
    mapping(address => uint256) public balances;

    // ❌ VULNERABILITY: ERC-777 hook reentrancy
    function transfer(address to, uint256 amount) external {
        balances[msg.sender] -= amount;

        // ❌ CRITICAL: ERC-777 calls tokensToSend hook BEFORE state update
        // ❌ Then calls tokensReceived hook on recipient
        // ❌ Both hooks can reenter

        // Simulate hook call
        (bool success,) = to.call("");
        require(success);

        balances[to] += amount;

        // ❌ Reentrancy possible through ERC-777 hooks
    }
}

/**
 * @dev ERC-20 infinite approval
 */
contract VulnerableInfiniteApproval {
    mapping(address => mapping(address => uint256)) public allowances;

    // ❌ VULNERABILITY: Infinite approval risk
    function approve(address spender, uint256 amount) external {
        // ❌ Allows infinite approval (2^256-1)
        // ❌ No warning for maximum approval
        // ❌ Security risk if spender compromised

        allowances[msg.sender][spender] = amount;

        // ❌ Should warn: if amount == type(uint256).max
    }
}

/**
 * @dev Token permit front-running
 */
contract VulnerableTokenPermit {
    mapping(address => uint256) public nonces;

    // ❌ VULNERABILITY: Permit front-running
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // ❌ Front-running possible
        // ❌ Attacker can see permit in mempool
        // ❌ Submit their transaction first using the signature

        // Verify signature (simplified)
        nonces[owner]++;

        // ❌ Missing: Front-running protection
        // ❌ Missing: Deadline check could be stricter
    }
}

/**
 * @dev Integer overflow in older Solidity
 */
contract VulnerableIntegerOverflow {
    uint8 public smallValue = 255;

    // ❌ VULNERABILITY: Potential overflow (if using <0.8.0)
    function increment() external {
        // In Solidity <0.8.0, this would wrap to 0
        // In >=0.8.0, this reverts automatically

        smallValue++; // ❌ Would overflow in <0.8.0

        // ✅ Better: Use SafeMath or check manually
    }
}

/**
 * TESTING NOTES:
 *
 * Expected Detectors:
 * 1. optimistic-fraud-proof-timing (2 findings)
 * 2. cross-rollup-atomicity (1 finding)
 * 3. l2-bridge-message-validation (1 finding)
 * 4. avs-validation-bypass (1 finding) - enhanced
 * 5. cross-chain-message-ordering (1 finding)
 * 6. erc7683-crosschain-validation (1 finding)
 * 7. lrt-share-inflation (1 finding)
 * 8. bridge-token-mint-control (1 finding)
 * 9. celestia-data-availability (1 finding) - advanced
 * 10. sovereign-rollup-validation (1 finding) - advanced
 * 11. metamorphic-contract (1 finding)
 * 12. division-before-multiplication (1 finding)
 * 13. erc1155-batch-validation (1 finding)
 * 14. erc721-enumeration-dos (1 finding)
 * 15. erc777-reentrancy-hooks (1 finding)
 * 16. erc20-infinite-approval (1 finding)
 * 17. token-permit-front-running (1 finding)
 * 18. integer-overflow (1 finding)
 *
 * Real-World Relevance:
 * - Optimistic rollups: Arbitrum, Optimism fraud proof timing
 * - Cross-rollup: Connext, Hop Protocol atomicity
 * - L2 bridges: Validating cross-layer messages
 * - AVS: EigenLayer actively validated services
 * - LRT: Liquid restaking tokens (EigenLayer, Renzo)
 * - Metamorphic: Tornado Cash attack pattern
 * - ERC-777: Known reentrancy vector
 */
