// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Specialized Vulnerability Patterns
 * @notice Tests highly specialized and niche security detectors
 * @dev Tests: missing-commit-reveal, auction-timing-manipulation,
 *             celestia-data-availability, sovereign-rollup-validation, etc.
 */

// =====================================================================
// 1. MISSING COMMIT-REVEAL SCHEMES
// =====================================================================

/**
 * @dev Auction without commit-reveal protection
 */
contract VulnerableAuctionNoCommitReveal {
    struct BidInfo {
        address bidder;
        uint256 amount;
        uint256 timestamp;
    }

    mapping(uint256 => BidInfo) public highestBid;
    mapping(uint256 => bool) public auctionEnded;

    // ❌ VULNERABILITY 1: Direct bidding without commit-reveal
    function placeBid(uint256 auctionId) external payable {
        // ❌ Bid amount visible in mempool
        // ❌ Front-runners can see and outbid
        // ❌ No commit-reveal protection

        require(msg.value > highestBid[auctionId].amount, "Bid too low");

        // Refund previous bidder
        if (highestBid[auctionId].bidder != address(0)) {
            payable(highestBid[auctionId].bidder).transfer(highestBid[auctionId].amount);
        }

        highestBid[auctionId] = BidInfo({
            bidder: msg.sender,
            amount: msg.value,
            timestamp: block.timestamp
        });

        // ❌ CRITICAL: Bids can be front-run
        // Should use commit-reveal pattern
    }

    // ❌ VULNERABILITY 2: NFT auction without commit-reveal
    function bidOnNFT(uint256 tokenId, uint256 bidAmount) external {
        // ❌ Transparent bidding
        // ❌ Sniping possible
        // ❌ Front-running enabled

        require(bidAmount > 0, "Invalid bid");

        // Process bid openly
    }

    // ❌ VULNERABILITY 3: Batch auction without commit-reveal
    function submitBatchBid(uint256[] calldata itemIds, uint256[] calldata amounts) external payable {
        // ❌ Entire bid strategy visible
        // ❌ Competitors can see and counter
        // ❌ No privacy protection

        for (uint256 i = 0; i < itemIds.length; i++) {
            // Process each bid openly
        }
    }
}

// =====================================================================
// 2. AUCTION TIMING MANIPULATION
// =====================================================================

/**
 * @dev Auction with predictable timing
 */
contract VulnerableAuctionTiming {
    struct Auction {
        uint256 startTime;
        uint256 endTime;
        uint256 highestBid;
        address highestBidder;
    }

    mapping(uint256 => Auction) public auctions;
    uint256 public nextAuctionId;

    // ❌ VULNERABILITY 1: Anyone can start auction with predictable timing
    function createAuction(uint256 duration) external returns (uint256 auctionId) {
        // ❌ VULNERABILITY: Anyone can start
        // ❌ Predictable timing manipulation
        // ❌ No access control

        auctionId = nextAuctionId++;

        auctions[auctionId] = Auction({
            startTime: block.timestamp,
            endTime: block.timestamp + duration,
            highestBid: 0,
            highestBidder: address(0)
        });

        // ❌ MEV bots can monitor and front-run
    }

    // ❌ VULNERABILITY 2: Predictable batch auction start
    function startAuction(uint256 auctionId, uint256 delay) external {
        // ❌ VULNERABILITY: Predictable timing
        // ❌ MEV bots can prepare in advance

        auctions[auctionId].startTime = block.timestamp + delay;
        auctions[auctionId].endTime = block.timestamp + delay + 1 hours;

        // ❌ No randomization
        // ❌ No commit-reveal for start time
    }

    // ❌ VULNERABILITY 3: Immediate auction start
    function initiateAuction() external {
        // ❌ VULNERABILITY: timing manipulation
        uint256 id = nextAuctionId++;

        // Starts immediately - fully predictable
        auctions[id].startTime = block.timestamp;
        auctions[id].endTime = block.timestamp + 1 days;
    }

    // ❌ VULNERABILITY 4: Batch auction with fixed schedule
    function beginAuction(uint256 batchId) external {
        // ❌ VULNERABILITY: Predictable timing
        // Fixed schedule known in advance

        auctions[batchId].startTime = block.timestamp;
        auctions[batchId].endTime = block.timestamp + 7 days;
    }
}

// =====================================================================
// 3. CELESTIA DATA AVAILABILITY
// =====================================================================

/**
 * @dev Modular blockchain without DA verification
 */
contract VulnerableCelestiaDA {
    struct Transaction {
        bytes32 dataRoot;
        bytes data;
        bool finalized;
    }

    mapping(bytes32 => Transaction) public transactions;

    // ❌ VULNERABILITY 1: Celestia DA without verification
    function submitTransaction(bytes32 txHash, bytes calldata blobData) external {
        // ❌ CRITICAL: No DA proof verification
        // ❌ Data may not be available on Celestia
        // ❌ No dataRoot verification

        transactions[txHash] = Transaction({
            dataRoot: bytes32(0),
            data: blobData,
            finalized: false
        });

        // ❌ Missing: require(verifyDataRoot(dataRoot, proof))
    }

    // ❌ VULNERABILITY 2: DataAvailability layer without proof
    function postDataToCelestia(bytes32 commitment, bytes calldata dataAvailability) external {
        // ❌ No Merkle proof verification
        // ❌ No DA attestation check
        // ❌ Assumes data is available

        // Store without verification
        transactions[commitment].dataRoot = commitment;
        transactions[commitment].data = dataAvailability;
    }

    // ❌ VULNERABILITY 3: Blob data without DA proof
    function submitBlobData(bytes32 dataRoot, bytes calldata blobData) external {
        // ❌ CRITICAL: Missing DA layer verification
        // Data could be unavailable on Celestia

        transactions[dataRoot].data = blobData;
        transactions[dataRoot].finalized = true;

        // ❌ No dataRoot validation
        // ❌ No Merkle proof
    }
}

// =====================================================================
// 4. SOVEREIGN ROLLUP VALIDATION
// =====================================================================

/**
 * @dev Sovereign rollup without state transition validation
 */
contract VulnerableSovereignRollup {
    bytes32 public currentStateRoot;
    uint256 public blockNumber;

    struct Block {
        bytes32 stateRoot;
        bytes32 transitionsHash;
        uint256 timestamp;
    }

    mapping(uint256 => Block) public blocks;

    // ❌ VULNERABILITY 1: Sovereign rollup state update without validation
    function updateState(bytes32 newStateRoot, bytes calldata stateTransition) external {
        // ❌ CRITICAL: No state transition validation
        // ❌ Anyone can update to invalid state
        // ❌ No proof verification

        currentStateRoot = newStateRoot;
        blockNumber++;

        // ❌ Missing: require(validateStateTransition(currentStateRoot, newStateRoot, proof))
    }

    // ❌ VULNERABILITY 2: Sovereign chain state without validation
    function proposeBlock(bytes32 stateRoot, bytes32 transitionsHash) external {
        // ❌ No validation of state transition
        // Invalid states possible

        blocks[blockNumber] = Block({
            stateRoot: stateRoot,
            transitionsHash: transitionsHash,
            timestamp: block.timestamp
        });

        blockNumber++;

        // ❌ Sovereign rollup should validate all transitions
    }

    // ❌ VULNERABILITY 3: State transition without proof
    function commitStateTransition(bytes32 oldState, bytes32 newState) external {
        // ❌ CRITICAL: No validation that transition is valid
        // ❌ Sovereign rollup must validate all state changes

        currentStateRoot = newState;

        // ❌ Missing validation logic
    }
}

// =====================================================================
// 5. MODULAR BLOCKCHAIN PATTERNS
// =====================================================================

/**
 * @dev L2 rollup with data availability issues
 */
contract VulnerableModularBlockchain {
    bytes32 public dataRoot;
    bytes32 public stateRoot;

    // ❌ VULNERABILITY: Data availability without Celestia verification
    function submitBatch(bytes32 batchDataRoot, bytes calldata blobData) external {
        // Uses Celestia for DA but doesn't verify
        dataRoot = batchDataRoot;

        // ❌ No DA proof verification
        // ❌ Data may not actually be on Celestia
    }

    // ❌ VULNERABILITY: Sovereign execution without validation
    function executeStateTransition(bytes32 newStateRoot) external {
        // Sovereign rollup pattern
        stateRoot = newStateRoot;

        // ❌ No state transition validation
    }
}

/**
 * @dev Cross-rollup bridge with modular components
 */
contract VulnerableModularBridge {
    // ❌ VULNERABILITY: Uses DataAvailability layer without verification
    function bridgeAssets(bytes32 celestiaRoot, bytes calldata dataAvailability) external {
        // Claims data is on Celestia
        // ❌ Doesn't verify DA proof

        // Process bridge transaction
    }
}

// =====================================================================
// 6. METAMORPHIC CONTRACT (ENSURE DETECTION)
// =====================================================================

/**
 * @dev Simple metamorphic contract (not a factory)
 */
contract SimpleMetamorphicContract {
    address public implementation;

    // ❌ CRITICAL: Uses CREATE2 and can SELFDESTRUCT
    constructor() {
        // Can be deployed via CREATE2
    }

    // ❌ VULNERABILITY: Contract can be destroyed and redeployed
    function destroy() external {
        // ❌ Combined with CREATE2, enables metamorphic pattern
        selfdestruct(payable(msg.sender));

        // Pattern: Deploy via CREATE2 → selfdestruct → redeploy at same address
        // Breaks immutability assumptions
    }

    // Note: This is a simple contract (not a factory)
    // Should still trigger metamorphic-contract detector
}

/**
 * TESTING NOTES:
 *
 * Expected Detectors:
 * 1. missing-commit-reveal (3+ findings)
 *    - Auction/bidding without commit-reveal
 *    - Direct bids visible in mempool
 *    - Front-running possible
 *
 * 2. auction-timing-manipulation (4+ findings)
 *    - Anyone can start auction
 *    - Predictable timing
 *    - No randomization
 *    - MEV bot front-running
 *
 * 3. celestia-data-availability (3+ findings)
 *    - No DA proof verification
 *    - Missing dataRoot validation
 *    - Blob data without Merkle proof
 *
 * 4. sovereign-rollup-validation (3+ findings)
 *    - State transitions without validation
 *    - No proof verification
 *    - Invalid states possible
 *
 * 5. metamorphic-contract (1+ finding)
 *    - CREATE2 + SELFDESTRUCT pattern
 *    - Simple contract (not factory)
 *
 * Cross-Category Detectors Expected:
 * - front-running-mitigation
 * - missing-access-modifiers
 * - timestamp-manipulation
 * - centralization-risk
 * - unchecked-external-call
 * - selfdestruct-abuse
 *
 * Real-World Relevance:
 * - Commit-reveal: NFT mints, auctions (Fei Protocol, Paradigm CTF)
 * - Auction timing: MEV extraction in DeFi auctions
 * - Celestia: Modular blockchain data availability
 * - Sovereign rollups: Rollkit, Dymension patterns
 * - Metamorphic: Tornado Cash attack pattern
 *
 * Protocol Examples:
 * - Celestia: Data availability layer for modular blockchains
 * - Sovereign rollups: Execution layers using Celestia DA
 * - Auction platforms: Need commit-reveal for fair bidding
 * - CREATE2 factories: Must avoid metamorphic patterns
 */
