// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableFrontRunning
 * @notice Test contract for front-running vulnerabilities in bidding, auctions, and state changes
 *
 * DETECTORS TO TEST:
 * - front-running (Medium)
 * - front-running-mitigation (High)
 * - mev-backrun-opportunities (Medium)
 * - mev-priority-gas-auction (Medium)
 * - mev-toxic-flow-exposure (Medium)
 *
 * VULNERABILITIES:
 * 1. Bidding without commit-reveal scheme
 * 2. Auction without hidden bid mechanism
 * 3. Price-sensitive liquidation without TWAP
 * 4. High-value withdrawal observable in mempool
 * 5. Approval changes without nonce/signature
 * 6. NFT minting with predictable price
 * 7. Priority gas auction manipulation
 * 8. Backrun opportunities in state changes
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IPriceOracle {
    function getPrice(address token) external view returns (uint256);
}

/**
 * @notice Vulnerable auction without commit-reveal
 */
contract VulnerableAuction {
    struct Bid {
        address bidder;
        uint256 amount;
        uint256 timestamp;
    }

    Bid public highestBid;
    address public auctionItem;
    uint256 public auctionEnd;

    mapping(address => uint256) public pendingReturns;

    // ❌ VULNERABILITY 1: Bidding without commit-reveal (front-running)
    // Attacker can see your bid in mempool and outbid you by 1 wei
    function bid(uint256 amount) external {
        // ❌ Bid amount visible in mempool!
        // ❌ No commit-reveal mechanism
        // ❌ No secret/hash

        require(block.timestamp < auctionEnd, "Auction ended");
        require(amount > highestBid.amount, "Bid too low");

        // Attacker can:
        // 1. See your bid(1000 ETH) in mempool
        // 2. Front-run with bid(1001 ETH)
        // 3. You lose the auction

        if (highestBid.bidder != address(0)) {
            pendingReturns[highestBid.bidder] += highestBid.amount;
        }

        highestBid = Bid({
            bidder: msg.sender,
            amount: amount,
            timestamp: block.timestamp
        });
    }

    // ❌ VULNERABILITY 2: English auction vulnerable to sniping (mev-priority-gas-auction)
    // Last-second bids with high gas can always win
    function bidWithGas() external payable {
        require(block.timestamp < auctionEnd, "Auction ended");
        require(msg.value > highestBid.amount, "Bid too low");

        // ❌ No bid extension on late bids
        // ❌ No gas price cap
        // Attacker can:
        // 1. Wait until last block before auctionEnd
        // 2. Submit bid with very high gas price
        // 3. Outbid everyone at the last second

        if (highestBid.bidder != address(0)) {
            payable(highestBid.bidder).transfer(highestBid.amount);
        }

        highestBid = Bid({
            bidder: msg.sender,
            amount: msg.value,
            timestamp: block.timestamp
        });
    }

    function withdraw() external {
        uint256 amount = pendingReturns[msg.sender];
        require(amount > 0, "No funds");

        pendingReturns[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}

/**
 * @notice Vulnerable liquidation system
 */
contract VulnerableLiquidation {
    IPriceOracle public oracle;

    struct Position {
        uint256 collateral;
        uint256 debt;
    }

    mapping(address => Position) public positions;

    constructor(address _oracle) {
        oracle = IPriceOracle(_oracle);
    }

    // ❌ VULNERABILITY 3: Liquidation using spot price (front-running-mitigation)
    // Front-runners can manipulate oracle price
    function liquidate(address user, address collateralToken) external {
        Position storage position = positions[user];

        // ❌ Uses spot price - can be manipulated!
        uint256 collateralPrice = oracle.getPrice(collateralToken);

        // ❌ No TWAP protection
        // ❌ No minimum time between price updates
        // ❌ No liquidation delay

        uint256 collateralValue = position.collateral * collateralPrice;
        uint256 healthFactor = (collateralValue * 100) / position.debt;

        require(healthFactor < 100, "Position healthy");

        // Attacker can:
        // 1. See liquidate() transaction in mempool
        // 2. Front-run with price manipulation
        // 3. Trigger unfair liquidation
        // 4. Back-run to restore price

        // Transfer collateral to liquidator
        position.collateral = 0;
        position.debt = 0;
    }

    // ❌ VULNERABILITY 4: Mint price based on current conditions (front-running)
    function mintBasedOnPrice(address token) external returns (uint256 amountToMint) {
        // ❌ Mint amount determined by current price
        uint256 tokenPrice = oracle.getPrice(token);

        // ❌ No minimum mint amount protection
        // ❌ Visible in mempool

        amountToMint = 1000e18 / tokenPrice;

        // Attacker can:
        // 1. Front-run with price increase
        // 2. You mint fewer tokens
        // 3. Attacker back-runs to profit

        // Mint logic...
    }
}

/**
 * @notice Vulnerable withdrawal system
 */
contract VulnerableWithdrawal {
    mapping(address => uint256) public balances;

    // ❌ VULNERABILITY 5: Large withdrawal observable in mempool (front-running-mitigation)
    function withdraw(uint256 amount) external {
        // ❌ High-value state change visible in mempool
        // ❌ No commitment mechanism
        // ❌ No signature/nonce validation

        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Observable withdrawal can be front-run for:
        // 1. Market manipulation if this triggers price changes
        // 2. Gaming mechanisms that depend on balance
        // 3. MEV extraction opportunities

        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // ❌ VULNERABILITY 6: Batch withdrawal creates backrun opportunity (mev-backrun-opportunities)
    function withdrawBatch(address[] calldata users, uint256[] calldata amounts) external {
        // ❌ Large state changes create MEV opportunities
        // After this transaction, arbitrageurs can profit from:
        // 1. Price changes from liquidity removal
        // 2. Balance-dependent mechanism triggers
        // 3. Collateral ratio changes

        require(users.length == amounts.length, "Length mismatch");

        for (uint256 i = 0; i < users.length; i++) {
            require(balances[users[i]] >= amounts[i], "Insufficient balance");
            balances[users[i]] -= amounts[i];
            payable(users[i]).transfer(amounts[i]);
        }

        // ❌ No protection against backrun MEV extraction
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}

/**
 * @notice Vulnerable NFT minting
 */
contract VulnerableNFTMint {
    uint256 public totalSupply;
    uint256 public maxSupply = 10000;

    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public mintCount;

    // ❌ VULNERABILITY 7: Mint with predictable price increase (front-running)
    function mint() external payable returns (uint256 tokenId) {
        require(totalSupply < maxSupply, "Sold out");

        // ❌ Price increases with supply - predictable!
        uint256 price = getCurrentPrice();
        require(msg.value >= price, "Insufficient payment");

        // Attacker can:
        // 1. See your mint transaction
        // 2. Calculate exact price at that supply
        // 3. Front-run with higher gas to mint before you
        // 4. You pay more or transaction fails

        tokenId = totalSupply;
        totalSupply++;

        ownerOf[tokenId] = msg.sender;
        mintCount[msg.sender]++;
    }

    function getCurrentPrice() public view returns (uint256) {
        // ❌ Predictable price curve
        return 0.1 ether + (totalSupply * 0.001 ether);
    }

    // ❌ VULNERABILITY 8: Whitelist mint without signature (front-running)
    mapping(address => bool) public whitelist;

    function whitelistMint() external payable returns (uint256) {
        // ❌ No signature validation!
        // ❌ Anyone can front-run if they see address added to whitelist

        require(whitelist[msg.sender], "Not whitelisted");
        require(totalSupply < maxSupply, "Sold out");

        uint256 tokenId = totalSupply;
        totalSupply++;

        ownerOf[tokenId] = msg.sender;
        mintCount[msg.sender]++;

        return tokenId;
    }

    function addToWhitelist(address user) external {
        whitelist[user] = true;
        // ❌ Transaction is visible, user can be front-run
    }
}

/**
 * @notice Priority gas auction manipulation
 */
contract VulnerablePriorityAuction {
    uint256 public rewardPool = 100 ether;
    address public lastCaller;
    uint256 public highestGasPrice;

    // ❌ VULNERABILITY 9: Reward based on gas price (mev-priority-gas-auction)
    // Creates toxic MEV gas auction
    function claimRewardHighestGas() external {
        // ❌ Rewards highest gas price!
        // This creates destructive priority gas auction (PGA)

        require(tx.gasprice > highestGasPrice, "Gas price too low");

        // Attacker can:
        // 1. See your transaction with gas price X
        // 2. Submit transaction with gas price X+1
        // 3. Escalating gas war hurts all participants
        // 4. Only miners profit

        highestGasPrice = tx.gasprice;
        lastCaller = msg.sender;

        // Award based on gas price - very bad pattern!
        uint256 reward = (tx.gasprice * 1 ether) / 1 gwei;
        if (reward > rewardPool) reward = rewardPool;

        rewardPool -= reward;
        payable(msg.sender).transfer(reward);
    }

    // ❌ VULNERABILITY 10: First-come-first-serve with gas (mev-priority-gas-auction)
    bool public claimed;

    function claimFirstCome() external {
        require(!claimed, "Already claimed");

        // ❌ FCFS creates priority gas auction!
        // Users compete with gas price to be first
        // This is MEV-extractable

        claimed = true;
        payable(msg.sender).transfer(1 ether);
    }

    function resetAuction() external payable {
        claimed = false;
        rewardPool += msg.value;
    }
}

/**
 * @notice Toxic flow exposure
 */
contract VulnerableToxicFlow {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // ❌ VULNERABILITY 11: Large swap creates toxic flow (mev-toxic-flow-exposure)
    function executeArbitrage(
        uint256 amountIn,
        address[] calldata path
    ) external {
        // ❌ Arbitrage execution visible in mempool
        // ❌ Creates toxic order flow that sophisticated MEV bots can exploit

        // This transaction signals valuable information:
        // 1. Price discrepancy exists
        // 2. Arbitrage opportunity size
        // 3. Best execution path

        // MEV bots can:
        // 1. Front-run this arbitrage
        // 2. Sandwich the arbitrage
        // 3. Backrun with better arbitrage

        token.transferFrom(msg.sender, address(this), amountIn);
        // Execute arbitrage...
    }
}

/**
 * @notice Secure auction with commit-reveal
 */
contract SecureAuction {
    struct Commitment {
        bytes32 commitHash;
        uint256 commitTime;
    }

    struct Bid {
        address bidder;
        uint256 amount;
    }

    mapping(address => Commitment) public commitments;
    Bid public highestBid;

    uint256 public commitPhaseEnd;
    uint256 public revealPhaseEnd;
    uint256 public constant REVEAL_DURATION = 1 hours;

    // ✅ Phase 1: Commit bid hash
    function commitBid(bytes32 bidHash) external {
        require(block.timestamp < commitPhaseEnd, "Commit phase ended");

        // ✅ Only hash is revealed, bid amount hidden
        commitments[msg.sender] = Commitment({
            commitHash: bidHash,
            commitTime: block.timestamp
        });
    }

    // ✅ Phase 2: Reveal actual bid
    function revealBid(uint256 amount, bytes32 secret) external {
        require(block.timestamp >= commitPhaseEnd, "Still in commit phase");
        require(block.timestamp < revealPhaseEnd, "Reveal phase ended");

        Commitment memory commitment = commitments[msg.sender];
        require(commitment.commitTime > 0, "No commitment");

        // ✅ Verify bid matches commitment
        bytes32 bidHash = keccak256(abi.encodePacked(amount, secret, msg.sender));
        require(bidHash == commitment.commitHash, "Invalid reveal");

        // Update highest bid if applicable
        if (amount > highestBid.amount) {
            highestBid = Bid({
                bidder: msg.sender,
                amount: amount
            });
        }
    }

    // ✅ Secure liquidation with TWAP
    // Implementation would use time-weighted average price
    // instead of spot price to prevent manipulation
}
