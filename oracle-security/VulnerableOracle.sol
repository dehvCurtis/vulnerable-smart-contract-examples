// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableOracle
 * @notice Test contract for oracle price manipulation vulnerabilities
 *
 * DETECTORS TO TEST:
 * - oracle-manipulation (Critical)
 * - price-oracle-stale (Critical)
 * - oracle-staleness-heartbeat (Medium)
 * - single-oracle-source (High)
 * - flashloan-price-oracle-manipulation (Critical)
 *
 * VULNERABILITIES:
 * 1. Using spot price from DEX as oracle
 * 2. No staleness checks on Chainlink data
 * 3. Missing heartbeat validation
 * 4. Single oracle source without redundancy
 * 5. Flash loan price manipulation via reserves
 * 6. No circuit breaker for price deviations
 * 7. Missing updatedAt timestamp validation
 */

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function token0() external view returns (address);
    function token1() external view returns (address);
}

interface AggregatorV3Interface {
    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );

    function decimals() external view returns (uint8);
}

/**
 * @notice Vulnerable lending protocol using spot price oracle
 */
contract VulnerableLendingSpotPrice {
    IUniswapV2Pair public pricePair;

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrowed;

    uint256 public constant COLLATERAL_RATIO = 150; // 150%

    constructor(address _pricePair) {
        pricePair = IUniswapV2Pair(_pricePair);
    }

    // ❌ VULNERABILITY 1: Using spot price from DEX (oracle-manipulation)
    // Flash loans can manipulate reserves, causing wrong price!
    function getPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1,) = pricePair.getReserves();

        // ❌ Spot price calculation - manipulable via flash loan!
        // Attacker can:
        // 1. Flash loan large amount of token0
        // 2. Swap to manipulate reserves
        // 3. Trigger liquidation with wrong price
        // 4. Profit from liquidation
        // 5. Swap back and return flash loan

        return (uint256(reserve1) * 1e18) / uint256(reserve0);
    }

    // ❌ VULNERABILITY 2: Liquidation using manipulable price (flashloan-price-oracle-manipulation)
    function liquidate(address user) external {
        uint256 price = getPrice(); // ❌ Manipulable!

        uint256 collateralValue = collateral[user] * price / 1e18;
        uint256 borrowedValue = borrowed[user];

        // ❌ If attacker manipulates price down, healthy positions become "underwater"
        require(collateralValue * 100 < borrowedValue * COLLATERAL_RATIO, "Position healthy");

        // Transfer collateral to liquidator (at manipulated price!)
        // Liquidator gets collateral at unfair price
    }

    function depositCollateral() external payable {
        collateral[msg.sender] += msg.value;
    }

    function borrow(uint256 amount) external {
        uint256 price = getPrice();
        uint256 maxBorrow = (collateral[msg.sender] * price * 100) / (COLLATERAL_RATIO * 1e18);

        require(borrowed[msg.sender] + amount <= maxBorrow, "Insufficient collateral");
        borrowed[msg.sender] += amount;
    }
}

/**
 * @notice Vulnerable Chainlink oracle without staleness check
 */
contract VulnerableChainlinkNoStaleness {
    AggregatorV3Interface public priceFeed;

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    constructor(address _priceFeed) {
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    // ❌ VULNERABILITY 3: No staleness check (price-oracle-stale)
    function getPrice() public view returns (uint256) {
        (
            ,  // roundId
            int256 price,
            ,  // startedAt
            ,  // updatedAt - ❌ NOT CHECKED!
               // answeredInRound
        ) = priceFeed.latestRoundData();

        // ❌ No validation of updatedAt!
        // ❌ No check: require(block.timestamp - updatedAt < HEARTBEAT)
        // If Chainlink oracle stops updating (network issues, data provider outage),
        // stale price will be used, causing:
        // - Incorrect liquidations
        // - Wrong collateral valuations
        // - Arbitrage opportunities

        require(price > 0, "Invalid price");
        return uint256(price);
    }

    function depositCollateral() external payable {
        collateral[msg.sender] += msg.value;
    }

    function borrow(uint256 amount) external {
        uint256 price = getPrice(); // ❌ Stale price possible!
        uint256 collateralValue = collateral[msg.sender] * price / 1e18;

        require(debt[msg.sender] + amount <= collateralValue / 2, "Insufficient collateral");
        debt[msg.sender] += amount;
    }
}

/**
 * @notice Vulnerable Chainlink oracle without heartbeat validation
 */
contract VulnerableChainlinkNoHeartbeat {
    AggregatorV3Interface public priceFeed;

    constructor(address _priceFeed) {
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    // ❌ VULNERABILITY 4: Missing heartbeat validation (oracle-staleness-heartbeat)
    function getPrice() public view returns (uint256) {
        (
            uint80 roundId,
            int256 price,
            ,  // startedAt
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();

        // ❌ Missing heartbeat check!
        // ❌ Should have: uint256 constant HEARTBEAT = 3600; // 1 hour for ETH/USD
        // ❌ Should check: require(block.timestamp - updatedAt <= HEARTBEAT, "Stale price");

        // ❌ Only checks price > 0, not freshness!
        require(price > 0, "Invalid price");
        require(answeredInRound >= roundId, "Stale round");

        // Different pairs have different heartbeats:
        // - ETH/USD: 1 hour
        // - BTC/USD: 1 hour
        // - Less liquid pairs: 24 hours
        // Must validate based on expected heartbeat!

        return uint256(price);
    }

    function executeWithPrice() external {
        uint256 price = getPrice();
        // Critical operation using potentially stale price
    }
}

/**
 * @notice Vulnerable contract with single oracle source
 */
contract VulnerableSingleOracle {
    AggregatorV3Interface public priceFeed;

    mapping(address => uint256) public balances;

    constructor(address _priceFeed) {
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    // ❌ VULNERABILITY 5: Single oracle source (single-oracle-source)
    function getPrice() public view returns (uint256) {
        (,int256 price,,,) = priceFeed.latestRoundData();

        // ❌ Only one oracle source!
        // ❌ No redundancy or validation against other sources!
        // Single point of failure:
        // - Oracle compromise
        // - Data provider manipulation
        // - Network partition
        // - Smart contract bug in oracle

        // Should use multiple oracles:
        // - Chainlink + Band Protocol
        // - Chainlink + Uniswap TWAP
        // - Multiple Chainlink feeds with median

        require(price > 0);
        return uint256(price);
    }

    function swap(uint256 amountIn) external returns (uint256 amountOut) {
        uint256 price = getPrice(); // ❌ Single point of failure!

        amountOut = (amountIn * price) / 1e18;

        // If oracle is compromised, entire protocol breaks
        balances[msg.sender] += amountOut;
    }
}

/**
 * @notice Multiple vulnerabilities combined
 */
contract VulnerableMultipleOracle {
    IUniswapV2Pair public uniswapPair;
    AggregatorV3Interface public chainlinkFeed;

    mapping(address => uint256) public deposits;
    mapping(address => uint256) public loans;

    constructor(address _pair, address _feed) {
        uniswapPair = IUniswapV2Pair(_pair);
        chainlinkFeed = AggregatorV3Interface(_feed);
    }

    // ❌ VULNERABILITY 6: Combines spot price AND stale oracle (oracle-manipulation + price-oracle-stale)
    function getAveragePrice() public view returns (uint256) {
        // Get Uniswap spot price (manipulable!)
        (uint112 reserve0, uint112 reserve1,) = uniswapPair.getReserves();
        uint256 uniPrice = (uint256(reserve1) * 1e18) / uint256(reserve0);

        // Get Chainlink price (no staleness check!)
        (,int256 clPrice,,,) = chainlinkFeed.latestRoundData();

        // ❌ Average of manipulable and potentially stale price!
        // Attacker can manipulate Uniswap price via flash loan
        // If Chainlink is also stale, both prices are wrong!

        return (uniPrice + uint256(clPrice)) / 2;
    }

    function liquidatePosition(address user) external {
        uint256 price = getAveragePrice();

        uint256 collateralValue = deposits[user] * price / 1e18;
        uint256 debtValue = loans[user];

        // ❌ Liquidation based on manipulable/stale price!
        require(collateralValue < debtValue, "Healthy position");

        // Unfair liquidation occurs
    }
}

/**
 * @notice Secure oracle implementation with proper checks
 */
contract SecureOracleImplementation {
    AggregatorV3Interface public chainlinkFeed;
    AggregatorV3Interface public backupFeed;

    uint256 public constant HEARTBEAT = 3600; // 1 hour
    uint256 public constant MAX_PRICE_DEVIATION = 5; // 5%
    uint256 public constant GRACE_PERIOD = 3600; // 1 hour grace for Chainlink

    constructor(address _primary, address _backup) {
        chainlinkFeed = AggregatorV3Interface(_primary);
        backupFeed = AggregatorV3Interface(_backup);
    }

    // ✅ Secure price fetching with multiple validations
    function getPrice() public view returns (uint256) {
        // ✅ Get primary oracle data
        (
            uint80 roundId,
            int256 primaryPrice,
            ,
            uint256 primaryUpdatedAt,
            uint80 answeredInRound
        ) = chainlinkFeed.latestRoundData();

        // ✅ 1. Validate primary oracle staleness
        require(block.timestamp - primaryUpdatedAt <= HEARTBEAT + GRACE_PERIOD, "Primary oracle stale");
        require(primaryPrice > 0, "Invalid primary price");
        require(answeredInRound >= roundId, "Stale round");

        // ✅ 2. Get backup oracle for validation
        (,int256 backupPrice,,uint256 backupUpdatedAt,) = backupFeed.latestRoundData();

        // ✅ 3. Validate backup oracle
        require(block.timestamp - backupUpdatedAt <= HEARTBEAT + GRACE_PERIOD, "Backup oracle stale");
        require(backupPrice > 0, "Invalid backup price");

        // ✅ 4. Check price deviation between oracles
        uint256 deviation = primaryPrice > backupPrice
            ? uint256((primaryPrice - backupPrice) * 100 / primaryPrice)
            : uint256((backupPrice - primaryPrice) * 100 / backupPrice);

        require(deviation <= MAX_PRICE_DEVIATION, "Price deviation too high");

        // ✅ 5. Return median of both prices
        return uint256((primaryPrice + backupPrice) / 2);
    }

    // ✅ Use TWAP for DEX-based pricing (manipulation resistant)
    function getTWAP(address pair, uint256 period) public view returns (uint256) {
        // Implement TWAP using cumulative price over time period
        // Much harder to manipulate than spot price
        // Requires sustained manipulation over entire period
        return 0; // Placeholder
    }

    // ✅ Circuit breaker for extreme price movements
    uint256 public lastPrice;
    uint256 public lastUpdateTime;
    uint256 public constant MAX_PRICE_CHANGE = 10; // 10% per update

    function updatePriceWithCircuitBreaker() external {
        uint256 newPrice = getPrice();

        if (lastPrice > 0) {
            uint256 priceChange = newPrice > lastPrice
                ? (newPrice - lastPrice) * 100 / lastPrice
                : (lastPrice - newPrice) * 100 / lastPrice;

            // ✅ Revert if price changed too much
            require(priceChange <= MAX_PRICE_CHANGE, "Circuit breaker triggered");
        }

        lastPrice = newPrice;
        lastUpdateTime = block.timestamp;
    }
}
