// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableFlashLoanPriceManipulation
 * @notice Test contract for flash loan price manipulation vulnerabilities
 *
 * DETECTORS TO TEST:
 * - flashloan-price-oracle-manipulation (Critical)
 * - flash-loan-price-manipulation-advanced (Critical)
 * - flash-loan-collateral-swap (High)
 * - flashmint-token-inflation (High)
 *
 * VULNERABILITIES:
 * 1. Spot price oracle vulnerable to flash loan manipulation
 * 2. Collateral value calculation using manipulable reserves
 * 3. Health factor based on single-block price
 * 4. Flash mint without minting limits
 * 5. Price calculation from current reserves (no TWAP)
 * 6. Liquidation triggered by manipulated price
 * 7. Collateral swap attack via flash loan
 * 8. No flash loan detection in price-sensitive operations
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

interface IPriceOracle {
    function getPrice(address token) external view returns (uint256);
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function token0() external view returns (address);
    function token1() external view returns (address);
}

/**
 * @notice Vulnerable lending protocol with flash loan price manipulation
 */
contract VulnerableLendingProtocol {
    struct UserAccount {
        mapping(address => uint256) collateral;
        mapping(address => uint256) borrowed;
    }

    mapping(address => UserAccount) public accounts;
    mapping(address => IUniswapV2Pair) public pricePairs;

    uint256 public constant COLLATERAL_FACTOR = 75; // 75%
    uint256 public constant LIQUIDATION_BONUS = 10; // 10%

    // ❌ VULNERABILITY 1: Spot price oracle (flashloan-price-oracle-manipulation)
    // Price fetched from current reserves - manipulable via flash loan
    function getPrice(address token) public view returns (uint256) {
        IUniswapV2Pair pair = pricePairs[token];

        // ❌ Uses current reserves!
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();

        // ❌ No TWAP, no multi-block average
        // Attacker can:
        // 1. Flash loan large amount
        // 2. Swap to manipulate reserves
        // 3. Trigger liquidation/borrow at manipulated price
        // 4. Unwind and profit

        if (pair.token0() == token) {
            return (uint256(reserve1) * 1e18) / uint256(reserve0);
        } else {
            return (uint256(reserve0) * 1e18) / uint256(reserve1);
        }
    }

    // ❌ VULNERABILITY 2: Collateral value using manipulable price (flash-loan-collateral-swap)
    function getCollateralValue(address user, address token) public view returns (uint256) {
        UserAccount storage account = accounts[user];

        // ❌ Uses spot price from getPrice()!
        uint256 price = getPrice(token);
        uint256 collateralAmount = account.collateral[token];

        // ❌ Value calculated with manipulated price
        return collateralAmount * price / 1e18;
    }

    // ❌ VULNERABILITY 3: Health factor based on manipulable price (flash-loan-price-manipulation-advanced)
    function getHealthFactor(address user) public view returns (uint256) {
        // ❌ Entire health factor calculation uses spot prices!
        // Can be manipulated in single transaction

        uint256 totalCollateralValue = 0;
        uint256 totalBorrowedValue = 0;

        // Simplified - real implementation would iterate all tokens
        // But vulnerability is the same: spot price usage

        if (totalCollateralValue == 0) return 0;
        return (totalCollateralValue * 100) / totalBorrowedValue;
    }

    // ❌ VULNERABILITY 4: Liquidation with manipulated price (flash-loan-price-manipulation-advanced)
    function liquidate(
        address user,
        address collateralToken,
        address debtToken,
        uint256 debtAmount
    ) external {
        // ❌ Health factor check uses manipulated price!
        uint256 healthFactor = getHealthFactor(user);
        require(healthFactor < 100, "Position healthy");

        UserAccount storage account = accounts[user];

        // ❌ Liquidation bonus calculated with manipulated price
        uint256 debtValue = debtAmount * getPrice(debtToken) / 1e18;
        uint256 collateralValue = (debtValue * (100 + LIQUIDATION_BONUS)) / 100;
        uint256 collateralAmount = collateralValue * 1e18 / getPrice(collateralToken);

        // Attack scenario:
        // 1. Flash loan to manipulate collateralToken price DOWN
        // 2. Trigger liquidation (health factor appears bad)
        // 3. Seize collateral at manipulated price
        // 4. Unwind flash loan
        // 5. Sell collateral at real price = profit

        account.collateral[collateralToken] -= collateralAmount;
        account.borrowed[debtToken] -= debtAmount;

        IERC20(collateralToken).transfer(msg.sender, collateralAmount);
    }

    // ❌ VULNERABILITY 5: Borrow with manipulated collateral value (flash-loan-collateral-swap)
    function borrow(address token, uint256 amount) external {
        // ❌ Collateral value check uses spot price!
        uint256 collateralValue = getCollateralValue(msg.sender, token);

        // Attacker can:
        // 1. Deposit collateral (e.g., WETH)
        // 2. Flash loan to pump WETH price UP
        // 3. Borrow maximum based on inflated price
        // 4. Unwind flash loan (price returns to normal)
        // 5. Never repay loan (collateral worth less than borrowed)

        require(collateralValue >= amount * 100 / COLLATERAL_FACTOR, "Insufficient collateral");

        accounts[msg.sender].borrowed[token] += amount;
        IERC20(token).transfer(msg.sender, amount);
    }

    function depositCollateral(address token, uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        accounts[msg.sender].collateral[token] += amount;
    }

    function setPricePair(address token, address pair) external {
        pricePairs[token] = IUniswapV2Pair(pair);
    }
}

/**
 * @notice Vulnerable flash mint implementation
 */
contract VulnerableFlashMintToken {
    string public name = "Vulnerable Flash Mint Token";
    string public symbol = "VFMT";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    event FlashMint(address indexed borrower, uint256 amount);

    // ❌ VULNERABILITY 6: Flash mint without limits (flashmint-token-inflation)
    function flashMint(uint256 amount, bytes calldata data) external {
        // ❌ No maximum mint limit!
        // ❌ No fee charged
        // ❌ No cooldown period

        // Attacker can:
        // 1. Flash mint enormous amount
        // 2. Dump tokens to manipulate price
        // 3. Execute attack on dependent protocols
        // 4. Return tokens (burn them)

        uint256 balanceBefore = balanceOf[msg.sender];

        // Mint tokens
        balanceOf[msg.sender] += amount;
        totalSupply += amount;

        emit FlashMint(msg.sender, amount);

        // Execute callback
        (bool success,) = msg.sender.call(data);
        require(success, "Flash mint callback failed");

        // ❌ Check tokens returned but no fee!
        uint256 balanceAfter = balanceOf[msg.sender];
        require(balanceAfter >= balanceBefore, "Tokens not returned");

        // Burn the minted tokens
        uint256 toBurn = balanceAfter - balanceBefore;
        balanceOf[msg.sender] -= toBurn;
        totalSupply -= toBurn;
    }

    // ❌ VULNERABILITY 7: Price calculation vulnerable to flash mint
    function getTokenPrice() public view returns (uint256) {
        // ❌ Price based on current total supply!
        // Flash mint can inflate totalSupply temporarily

        // Simplified price calculation
        // Real protocols might use reserves, but same vulnerability
        return (1e18 * 1000) / totalSupply; // Price inversely proportional to supply
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}

/**
 * @notice Vulnerable AMM with flash loan price manipulation
 */
contract VulnerableAMM {
    IERC20 public token0;
    IERC20 public token1;

    uint256 public reserve0;
    uint256 public reserve1;

    // ❌ VULNERABILITY 8: Single-block price oracle (flash-loan-price-manipulation-advanced)
    function getSpotPrice() public view returns (uint256) {
        // ❌ Returns spot price from current reserves!
        // No historical data, no TWAP

        // Other contracts using this for oracles are vulnerable:
        // 1. Flash loan to manipulate reserves
        // 2. Victim contract reads getSpotPrice()
        // 3. Victim executes at bad price
        // 4. Flash loan repaid

        return (reserve1 * 1e18) / reserve0;
    }

    // ❌ VULNERABILITY 9: Swap without flash loan detection
    function swap(uint256 amount0Out, uint256 amount1Out, address to) external {
        // ❌ No detection of flash loan activity!
        // ❌ Allows reserve manipulation in same transaction

        require(amount0Out > 0 || amount1Out > 0, "Invalid output");

        if (amount0Out > 0) token0.transfer(to, amount0Out);
        if (amount1Out > 0) token1.transfer(to, amount1Out);

        // Update reserves
        reserve0 = token0.balanceOf(address(this));
        reserve1 = token1.balanceOf(address(this));

        // ❌ K invariant check but no flash loan protection
        // Flash loans can still manipulate price temporarily
    }

    function addLiquidity(uint256 amount0, uint256 amount1) external {
        token0.transferFrom(msg.sender, address(this), amount0);
        token1.transferFrom(msg.sender, address(this), amount1);

        reserve0 += amount0;
        reserve1 += amount1;
    }
}

/**
 * @notice Secure implementation with TWAP
 */
contract SecureLendingWithTWAP {
    struct PriceObservation {
        uint256 timestamp;
        uint256 price;
    }

    mapping(address => PriceObservation[]) public priceHistory;
    uint256 public constant TWAP_PERIOD = 30 minutes;

    // ✅ TWAP price oracle resistant to flash loans
    function getTWAPPrice(address token) public view returns (uint256) {
        PriceObservation[] storage history = priceHistory[token];
        require(history.length > 0, "No price data");

        uint256 cutoffTime = block.timestamp - TWAP_PERIOD;
        uint256 weightedSum = 0;
        uint256 totalWeight = 0;

        // Calculate time-weighted average
        for (uint256 i = history.length; i > 0; i--) {
            PriceObservation memory obs = history[i - 1];
            if (obs.timestamp < cutoffTime) break;

            uint256 weight = block.timestamp - obs.timestamp;
            weightedSum += obs.price * weight;
            totalWeight += weight;
        }

        require(totalWeight > 0, "Insufficient price data");
        return weightedSum / totalWeight;
    }

    // ✅ Update price oracle (called periodically)
    function updatePrice(address token, uint256 price) external {
        priceHistory[token].push(PriceObservation({
            timestamp: block.timestamp,
            price: price
        }));
    }

    // ✅ Secure liquidation using TWAP
    function liquidate(address user, address collateralToken) external {
        // ✅ Uses TWAP instead of spot price
        uint256 twapPrice = getTWAPPrice(collateralToken);

        // Flash loan cannot manipulate TWAP in single transaction
        // Calculation logic here...
    }
}
