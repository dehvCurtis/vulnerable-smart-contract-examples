// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableOracleTimeWindow
 * @notice Test contract for oracle time window attack vulnerabilities
 *
 * DETECTORS TO TEST:
 * - oracle-time-window-attack (High)
 * - oracle-manipulation (Critical)
 *
 * VULNERABILITIES:
 * 1. Oracle update time window exploitation
 * 2. Block timestamp manipulation in oracle reads
 * 3. Front-running oracle updates
 * 4. MEV extraction via oracle timing
 * 5. Predictable oracle update patterns
 */

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

    function getRoundData(uint80 _roundId)
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
}

/**
 * @notice Vulnerable to oracle time window attacks
 */
contract VulnerableOracleTimeWindow {
    AggregatorV3Interface public priceFeed;

    uint256 public lastUpdateTime;
    uint256 public cachedPrice;

    uint256 public constant UPDATE_INTERVAL = 1 hours;

    constructor(address _priceFeed) {
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    // ❌ VULNERABILITY 1: Predictable update window (oracle-time-window-attack)
    function updatePrice() external {
        // ❌ Predictable update timing!
        // ❌ Anyone can see when update will happen
        // Attackers can:
        // 1. Monitor mempool for updatePrice() calls
        // 2. Front-run with favorable position
        // 3. Back-run after price updates
        // 4. Extract MEV from predictable timing

        require(block.timestamp >= lastUpdateTime + UPDATE_INTERVAL, "Too soon");

        (,int256 price,,,) = priceFeed.latestRoundData();

        cachedPrice = uint256(price);
        lastUpdateTime = block.timestamp;
    }

    // ❌ VULNERABILITY 2: Using cached price in time window
    function getPrice() public view returns (uint256) {
        // ❌ Returns cached price which may be stale
        // ❌ During UPDATE_INTERVAL window, price doesn't change
        // Attackers can exploit stale cached price

        return cachedPrice;
    }

    // ❌ VULNERABILITY 3: Liquidation during time window
    function liquidate(address user, uint256 collateral, uint256 debt) external {
        uint256 price = getPrice(); // ❌ May be stale!

        uint256 collateralValue = collateral * price / 1e18;

        // ❌ Liquidation based on stale price in time window
        // If real price moved but cached price hasn't updated,
        // healthy positions may be liquidated or
        // underwater positions may not be liquidatable

        require(collateralValue < debt, "Position healthy");

        // Unfair liquidation
    }
}

/**
 * @notice Vulnerable to front-running oracle updates
 */
contract VulnerableOracleFrontRunning {
    AggregatorV3Interface public priceFeed;

    uint80 public lastRoundId;
    uint256 public lastPrice;

    mapping(address => uint256) public userBalances;
    mapping(address => uint256) public userShares;

    constructor(address _priceFeed) {
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    // ❌ VULNERABILITY 4: Front-runnable oracle update (oracle-time-window-attack)
    function processOracleUpdate() external {
        (uint80 roundId, int256 price,,,) = priceFeed.latestRoundData();

        // ❌ No protection against front-running!
        // Attacker can:
        // 1. Monitor Chainlink oracle for price updates
        // 2. See new price being published on-chain
        // 3. Front-run processOracleUpdate() with higher gas
        // 4. Execute trades at old price before update
        // 5. Profit from price difference

        if (roundId > lastRoundId) {
            lastRoundId = roundId;
            lastPrice = uint256(price);

            // Rebalance based on new price
            _rebalance();
        }
    }

    function _rebalance() internal {
        // Rebalancing logic that can be front-run
    }

    // ❌ VULNERABILITY 5: Trade execution vulnerable to oracle timing
    function swap(uint256 amountIn) external returns (uint256 amountOut) {
        // ❌ Uses lastPrice which may not reflect latest oracle update
        // Attacker can front-run oracle update and trade at stale price

        amountOut = (amountIn * lastPrice) / 1e18;
        userBalances[msg.sender] += amountOut;
    }
}

/**
 * @notice Vulnerable to MEV via oracle update timing
 */
contract VulnerableOracleMEV {
    AggregatorV3Interface public priceFeed;

    uint256 public vaultValue;
    uint256 public totalShares;

    mapping(address => uint256) public shares;

    constructor(address _priceFeed) {
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    // ❌ VULNERABILITY 6: Share price calculation vulnerable to MEV (oracle-time-window-attack)
    function deposit() external payable returns (uint256 sharesIssued) {
        (,int256 oraclePrice,,,) = priceFeed.latestRoundData();

        uint256 price = uint256(oraclePrice);

        // ❌ Share price depends on oracle reading at this exact moment
        // MEV bot can:
        // 1. Monitor oracle for price updates
        // 2. Bundle: [Oracle Update Tx, Deposit Tx, Withdraw Tx]
        // 3. Deposit right after favorable price update
        // 4. Withdraw immediately after
        // 5. Profit from price movement within single block

        uint256 valueToAdd = msg.value * price / 1e18;

        if (totalShares == 0) {
            sharesIssued = valueToAdd;
        } else {
            sharesIssued = (valueToAdd * totalShares) / vaultValue;
        }

        shares[msg.sender] += sharesIssued;
        totalShares += sharesIssued;
        vaultValue += valueToAdd;
    }

    function withdraw(uint256 sharesToBurn) external {
        (,int256 oraclePrice,,,) = priceFeed.latestRoundData();

        uint256 price = uint256(oraclePrice);

        // ❌ Withdrawal value depends on oracle price at this moment
        // Can be exploited via MEV bundling

        uint256 userValue = (sharesToBurn * vaultValue) / totalShares;
        uint256 ethToReturn = userValue * 1e18 / price;

        shares[msg.sender] -= sharesToBurn;
        totalShares -= sharesToBurn;
        vaultValue -= userValue;

        payable(msg.sender).transfer(ethToReturn);
    }
}

/**
 * @notice Vulnerable to block timestamp manipulation
 */
contract VulnerableTimestampOracle {
    struct PricePoint {
        uint256 price;
        uint256 timestamp;
    }

    PricePoint[] public priceHistory;
    AggregatorV3Interface public priceFeed;

    constructor(address _priceFeed) {
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    // ❌ VULNERABILITY 7: Relies on block.timestamp (oracle-time-window-attack)
    function recordPrice() external {
        (,int256 price,,,) = priceFeed.latestRoundData();

        // ❌ Uses block.timestamp which miners can manipulate by ~15 seconds
        // Can affect:
        // - Price averaging calculations
        // - TWAP calculations
        // - Time-weighted positions
        // - Vesting schedules based on price + time

        priceHistory.push(PricePoint({
            price: uint256(price),
            timestamp: block.timestamp // ❌ Manipulable by miners!
        }));
    }

    // ❌ VULNERABILITY 8: Time-weighted average with manipulable timestamps
    function getTWAP(uint256 period) external view returns (uint256) {
        require(priceHistory.length > 0, "No price history");

        uint256 sum = 0;
        uint256 count = 0;
        uint256 cutoff = block.timestamp - period;

        // ❌ TWAP calculation using manipulable timestamps
        for (uint256 i = 0; i < priceHistory.length; i++) {
            if (priceHistory[i].timestamp >= cutoff) {
                sum += priceHistory[i].price;
                count++;
            }
        }

        require(count > 0, "No recent prices");
        return sum / count;
    }
}

/**
 * @notice Vulnerable to oracle round manipulation
 */
contract VulnerableRoundManipulation {
    AggregatorV3Interface public priceFeed;

    mapping(uint80 => bool) public processedRounds;

    constructor(address _priceFeed) {
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    // ❌ VULNERABILITY 9: Can skip oracle rounds (oracle-time-window-attack)
    function processRound(uint80 roundId) external {
        require(!processedRounds[roundId], "Already processed");

        (
            uint80 rId,
            int256 price,
            ,
            uint256 updatedAt,

        ) = priceFeed.getRoundData(roundId);

        require(rId == roundId, "Invalid round");
        require(price > 0, "Invalid price");

        // ❌ No validation that rounds are processed in order!
        // ❌ Attacker can skip unfavorable price rounds
        // ❌ Cherry-pick only favorable rounds

        processedRounds[roundId] = true;

        // Execute logic based on selected round price
        _executeWithPrice(uint256(price));
    }

    function _executeWithPrice(uint256 price) internal {
        // Critical logic using cherry-picked price
    }
}

/**
 * @notice Secure oracle with time window protection
 */
contract SecureOracleTimeWindow {
    AggregatorV3Interface public priceFeed;

    uint256 public constant MIN_UPDATE_DELAY = 5 minutes;
    uint256 public constant MAX_UPDATE_DELAY = 2 hours;

    uint80 public lastProcessedRound;
    uint256 public lastUpdateTime;
    uint256 public lastPrice;

    // ✅ TWAP accumulator for manipulation resistance
    uint256 public cumulativePrice;
    uint256 public cumulativeTime;

    constructor(address _priceFeed) {
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    // ✅ Secure oracle update with protections
    function updateOracle() external {
        // ✅ 1. Rate limiting
        require(
            block.timestamp >= lastUpdateTime + MIN_UPDATE_DELAY,
            "Update too frequent"
        );

        (
            uint80 roundId,
            int256 price,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();

        // ✅ 2. Validate round progression (no skipping)
        require(roundId > lastProcessedRound, "Round not advanced");
        require(answeredInRound >= roundId, "Stale round");

        // ✅ 3. Staleness check
        require(block.timestamp - updatedAt <= MAX_UPDATE_DELAY, "Oracle stale");

        // ✅ 4. Price sanity check
        require(price > 0, "Invalid price");

        if (lastPrice > 0) {
            uint256 priceChange = uint256(price) > lastPrice
                ? (uint256(price) - lastPrice) * 100 / lastPrice
                : (lastPrice - uint256(price)) * 100 / lastPrice;

            // ✅ 5. Circuit breaker for extreme moves
            require(priceChange <= 50, "Price change too large");
        }

        // ✅ 6. Update TWAP accumulator
        if (lastUpdateTime > 0) {
            uint256 elapsed = block.timestamp - lastUpdateTime;
            cumulativePrice += lastPrice * elapsed;
            cumulativeTime += elapsed;
        }

        lastProcessedRound = roundId;
        lastUpdateTime = block.timestamp;
        lastPrice = uint256(price);
    }

    // ✅ Get TWAP instead of spot price
    function getTWAP() public view returns (uint256) {
        require(cumulativeTime > 0, "Insufficient data");
        return cumulativePrice / cumulativeTime;
    }

    // ✅ Prevent MEV by using TWAP and commit-reveal
    mapping(bytes32 => uint256) public commitments;

    function commitTrade(bytes32 commitment) external {
        commitments[commitment] = block.timestamp;
    }

    function executeTrade(
        uint256 amount,
        uint256 nonce,
        bytes32 secret
    ) external {
        bytes32 commitment = keccak256(abi.encodePacked(msg.sender, amount, nonce, secret));

        require(commitments[commitment] > 0, "No commitment");
        require(block.timestamp >= commitments[commitment] + 1 minutes, "Too soon");
        require(block.timestamp <= commitments[commitment] + 1 hours, "Expired");

        delete commitments[commitment];

        // ✅ Use TWAP price, not spot price
        uint256 price = getTWAP();

        // Execute trade with manipulation-resistant price
    }
}
