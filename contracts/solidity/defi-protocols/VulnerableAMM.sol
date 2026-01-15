// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableAMM
 * @notice Test contract for AMM (Automated Market Maker) vulnerabilities
 *
 * DETECTORS TO TEST:
 * - amm-invariant-manipulation (High)
 * - amm-k-invariant-violation (Critical)
 * - amm-liquidity-manipulation (Critical)
 * - defi-jit-liquidity-attacks (High)
 * - defi-liquidity-pool-manipulation (Critical)
 * - missing-slippage-protection (High)
 *
 * VULNERABILITIES:
 * 1. K invariant not enforced after swaps
 * 2. Missing TWAP (Time-Weighted Average Price)
 * 3. Spot price used for swaps (sandwich attack vulnerability)
 * 4. No minimum liquidity lock period (JIT attacks)
 * 5. Missing slippage protection (amountOutMin = 0)
 * 6. Reserve manipulation possible
 * 7. Fee-on-transfer tokens not handled safely
 * 8. Public reserve update functions
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract VulnerableAMMPair {
    IERC20 public token0;
    IERC20 public token1;

    uint112 public reserve0;
    uint112 public reserve1;
    uint32 public blockTimestampLast;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    uint256 private constant MINIMUM_LIQUIDITY = 1000;

    event Swap(address indexed sender, uint256 amount0In, uint256 amount1In, uint256 amount0Out, uint256 amount1Out);
    event Mint(address indexed sender, uint256 amount0, uint256 amount1);
    event Burn(address indexed sender, uint256 amount0, uint256 amount1, address indexed to);

    constructor(address _token0, address _token1) {
        token0 = IERC20(_token0);
        token1 = IERC20(_token1);
    }

    // ❌ VULNERABILITY 1: K invariant not enforced (amm-k-invariant-violation)
    // After swap, should verify: reserve0 * reserve1 >= k_before
    function swap(
        uint256 amount0Out,
        uint256 amount1Out,
        address to
    ) external {
        require(amount0Out > 0 || amount1Out > 0, "Insufficient output amount");
        require(amount0Out < reserve0 && amount1Out < reserve1, "Insufficient liquidity");

        // Transfer tokens out
        if (amount0Out > 0) token0.transfer(to, amount0Out);
        if (amount1Out > 0) token1.transfer(to, amount1Out);

        // Get balances
        uint256 balance0 = token0.balanceOf(address(this));
        uint256 balance1 = token1.balanceOf(address(this));

        // Calculate input amounts
        uint256 amount0In = balance0 > reserve0 - amount0Out ? balance0 - (reserve0 - amount0Out) : 0;
        uint256 amount1In = balance1 > reserve1 - amount1Out ? balance1 - (reserve1 - amount1Out) : 0;

        require(amount0In > 0 || amount1In > 0, "Insufficient input amount");

        // ❌ MISSING: K invariant check!
        // Should have:
        // uint256 balance0Adjusted = balance0 * 1000 - amount0In * 3; // 0.3% fee
        // uint256 balance1Adjusted = balance1 * 1000 - amount1In * 3;
        // require(balance0Adjusted * balance1Adjusted >= uint(reserve0) * reserve1 * (1000**2), "K");

        // Update reserves without K validation
        _update(balance0, balance1);

        emit Swap(msg.sender, amount0In, amount1In, amount0Out, amount1Out);
    }

    // ❌ VULNERABILITY 2: Missing slippage protection (missing-slippage-protection)
    // amountOutMin = 0 allows unlimited slippage and sandwich attacks
    function swapNoSlippage(
        uint256 amountIn,
        address tokenIn,
        address to
    ) external returns (uint256 amountOut) {
        require(tokenIn == address(token0) || tokenIn == address(token1), "Invalid token");

        bool isToken0 = tokenIn == address(token0);
        (uint112 reserveIn, uint112 reserveOut) = isToken0
            ? (reserve0, reserve1)
            : (reserve1, reserve0);

        // Transfer input tokens
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);

        // Calculate output using spot price
        amountOut = getAmountOut(amountIn, reserveIn, reserveOut);

        // ❌ NO slippage protection! Missing amountOutMin parameter
        // Anyone can sandwich attack this swap
        // Should have: require(amountOut >= amountOutMin, "Insufficient output");

        if (isToken0) {
            token1.transfer(to, amountOut);
        } else {
            token0.transfer(to, amountOut);
        }

        _update(token0.balanceOf(address(this)), token1.balanceOf(address(this)));
    }

    // ❌ VULNERABILITY 3: Spot price used for calculation (amm-liquidity-manipulation)
    // No TWAP, vulnerable to flash loan price manipulation
    function getPrice() external view returns (uint256) {
        // ❌ Using spot price directly from reserves
        // Should use TWAP (Time-Weighted Average Price)
        require(reserve1 > 0, "No liquidity");
        return (reserve0 * 1e18) / reserve1;
    }

    // ❌ VULNERABILITY 4: Price calculation without TWAP (amm-liquidity-manipulation)
    function swapBasedOnSpotPrice(
        uint256 amountIn,
        address tokenIn,
        address to
    ) external returns (uint256 amountOut) {
        // ❌ Uses current reserves for price calculation
        // Vulnerable to same-block manipulation
        uint256 price = this.getPrice();

        // Calculate output based on manipulable spot price
        amountOut = (amountIn * price) / 1e18;

        // Execute swap...
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);

        if (tokenIn == address(token0)) {
            token1.transfer(to, amountOut);
        } else {
            token0.transfer(to, amountOut);
        }

        _update(token0.balanceOf(address(this)), token1.balanceOf(address(this)));
    }

    // ❌ VULNERABILITY 5: No minimum liquidity lock (defi-jit-liquidity-attacks)
    // Allows JIT (Just-In-Time) liquidity attacks
    function addLiquidity(
        uint256 amount0Desired,
        uint256 amount1Desired,
        address to
    ) external returns (uint256 liquidity) {
        token0.transferFrom(msg.sender, address(this), amount0Desired);
        token1.transferFrom(msg.sender, address(this), amount1Desired);

        uint256 balance0 = token0.balanceOf(address(this));
        uint256 balance1 = token1.balanceOf(address(this));

        uint256 amount0 = balance0 - reserve0;
        uint256 amount1 = balance1 - reserve1;

        if (totalSupply == 0) {
            liquidity = sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY;
            balanceOf[address(0)] = MINIMUM_LIQUIDITY; // Lock minimum liquidity
        } else {
            liquidity = min((amount0 * totalSupply) / reserve0, (amount1 * totalSupply) / reserve1);
        }

        require(liquidity > 0, "Insufficient liquidity minted");

        balanceOf[to] = balanceOf[to] + liquidity;
        totalSupply = totalSupply + liquidity;

        _update(balance0, balance1);

        // ❌ NO minimum lock period!
        // User can add liquidity, wait for swap, then remove immediately
        // Should have: lockUntil[to] = block.timestamp + LOCK_PERIOD;

        emit Mint(msg.sender, amount0, amount1);
    }

    // ❌ VULNERABILITY 6: Immediate withdrawal allows JIT attacks (defi-jit-liquidity-attacks)
    function removeLiquidity(
        uint256 liquidity,
        address to
    ) external returns (uint256 amount0, uint256 amount1) {
        // ❌ No lock period check!
        // Should have: require(block.timestamp >= lockUntil[msg.sender], "Locked");

        require(balanceOf[msg.sender] >= liquidity, "Insufficient balance");

        uint256 balance0 = token0.balanceOf(address(this));
        uint256 balance1 = token1.balanceOf(address(this));

        amount0 = (liquidity * balance0) / totalSupply;
        amount1 = (liquidity * balance1) / totalSupply;

        require(amount0 > 0 && amount1 > 0, "Insufficient liquidity burned");

        balanceOf[msg.sender] = balanceOf[msg.sender] - liquidity;
        totalSupply = totalSupply - liquidity;

        token0.transfer(to, amount0);
        token1.transfer(to, amount1);

        _update(token0.balanceOf(address(this)), token1.balanceOf(address(this)));

        emit Burn(msg.sender, amount0, amount1, to);
    }

    // ❌ VULNERABILITY 7: Public update function (amm-invariant-manipulation)
    // Reserves can be manipulated directly without going through swap
    function updateReserves(uint112 _reserve0, uint112 _reserve1) external {
        // ❌ Public function allowing direct reserve manipulation!
        // Should be internal or private
        reserve0 = _reserve0;
        reserve1 = _reserve1;
    }

    // ❌ VULNERABILITY 8: Fee-on-transfer tokens not handled (amm-k-invariant-violation)
    function swapFeeOnTransfer(
        uint256 amountIn,
        address tokenIn,
        address to
    ) external returns (uint256 amountOut) {
        uint256 balanceBefore = IERC20(tokenIn).balanceOf(address(this));

        // ❌ Assumes full amountIn is received
        // Fee-on-transfer tokens will cause less to arrive
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);

        uint256 balanceAfter = IERC20(tokenIn).balanceOf(address(this));
        // Should use: uint256 actualAmountIn = balanceAfter - balanceBefore;

        bool isToken0 = tokenIn == address(token0);
        (uint112 reserveIn, uint112 reserveOut) = isToken0
            ? (reserve0, reserve1)
            : (reserve1, reserve0);

        // ❌ Uses amountIn instead of actualAmountIn
        amountOut = getAmountOut(amountIn, reserveIn, reserveOut);

        if (isToken0) {
            token1.transfer(to, amountOut);
        } else {
            token0.transfer(to, amountOut);
        }

        _update(token0.balanceOf(address(this)), token1.balanceOf(address(this)));
    }

    // ❌ VULNERABILITY 9: Reserve manipulation via donation (defi-liquidity-pool-manipulation)
    // Direct token transfers skew price without triggering K validation
    function sync() external {
        // ❌ Syncs reserves to current balance without K validation
        // Allows price manipulation via direct token donation
        _update(token0.balanceOf(address(this)), token1.balanceOf(address(this)));
    }

    function _update(uint256 balance0, uint256 balance1) private {
        require(balance0 <= type(uint112).max && balance1 <= type(uint112).max, "Overflow");

        reserve0 = uint112(balance0);
        reserve1 = uint112(balance1);
        blockTimestampLast = uint32(block.timestamp % 2**32);

        // ❌ No TWAP update!
        // Should accumulate price observations:
        // uint32 timeElapsed = blockTimestamp - blockTimestampLast;
        // if (timeElapsed > 0 && _reserve0 != 0 && _reserve1 != 0) {
        //     price0CumulativeLast += uint(UQ112x112.encode(_reserve1).uqdiv(_reserve0)) * timeElapsed;
        //     price1CumulativeLast += uint(UQ112x112.encode(_reserve0).uqdiv(_reserve1)) * timeElapsed;
        // }
    }

    function getAmountOut(
        uint256 amountIn,
        uint256 reserveIn,
        uint256 reserveOut
    ) public pure returns (uint256 amountOut) {
        require(amountIn > 0, "Insufficient input amount");
        require(reserveIn > 0 && reserveOut > 0, "Insufficient liquidity");

        uint256 amountInWithFee = amountIn * 997; // 0.3% fee
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = (reserveIn * 1000) + amountInWithFee;
        amountOut = numerator / denominator;
    }

    function sqrt(uint256 y) internal pure returns (uint256 z) {
        if (y > 3) {
            z = y;
            uint256 x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
    }

    function min(uint256 x, uint256 y) internal pure returns (uint256 z) {
        z = x < y ? x : y;
    }
}

/**
 * @notice Secure AMM implementation for comparison
 */
contract SecureAMMPair {
    IERC20 public token0;
    IERC20 public token1;

    uint112 private reserve0;
    uint112 private reserve1;
    uint32 private blockTimestampLast;

    uint256 public price0CumulativeLast;
    uint256 public price1CumulativeLast;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public lockUntil;

    uint256 private constant MINIMUM_LIQUIDITY = 1000;
    uint256 private constant LOCK_PERIOD = 10 minutes;

    uint256 private unlocked = 1;

    modifier lock() {
        require(unlocked == 1, "Locked");
        unlocked = 0;
        _;
        unlocked = 1;
    }

    constructor(address _token0, address _token1) {
        token0 = IERC20(_token0);
        token1 = IERC20(_token1);
    }

    // ✅ Secure swap with K invariant validation
    function swap(
        uint256 amount0Out,
        uint256 amount1Out,
        uint256 amountOutMin,
        address to
    ) external lock {
        require(amount0Out > 0 || amount1Out > 0, "Insufficient output amount");
        require(amount0Out + amount1Out >= amountOutMin, "Slippage exceeded");

        (uint112 _reserve0, uint112 _reserve1,) = getReserves();
        require(amount0Out < _reserve0 && amount1Out < _reserve1, "Insufficient liquidity");

        uint256 balance0Before = token0.balanceOf(address(this));
        uint256 balance1Before = token1.balanceOf(address(this));

        if (amount0Out > 0) token0.transfer(to, amount0Out);
        if (amount1Out > 0) token1.transfer(to, amount1Out);

        uint256 balance0 = token0.balanceOf(address(this));
        uint256 balance1 = token1.balanceOf(address(this));

        uint256 amount0In = balance0 > _reserve0 - amount0Out ? balance0 - (_reserve0 - amount0Out) : 0;
        uint256 amount1In = balance1 > _reserve1 - amount1Out ? balance1 - (_reserve1 - amount1Out) : 0;

        require(amount0In > 0 || amount1In > 0, "Insufficient input amount");

        // ✅ K invariant validation with fee
        {
            uint256 balance0Adjusted = balance0 * 1000 - amount0In * 3;
            uint256 balance1Adjusted = balance1 * 1000 - amount1In * 3;
            require(
                balance0Adjusted * balance1Adjusted >= uint(_reserve0) * _reserve1 * (1000**2),
                "K invariant violated"
            );
        }

        _update(balance0, balance1, _reserve0, _reserve1);
    }

    // ✅ Secure add liquidity with lock period
    function addLiquidity(
        uint256 amount0Desired,
        uint256 amount1Desired,
        address to
    ) external lock returns (uint256 liquidity) {
        (uint112 _reserve0, uint112 _reserve1,) = getReserves();

        token0.transferFrom(msg.sender, address(this), amount0Desired);
        token1.transferFrom(msg.sender, address(this), amount1Desired);

        uint256 balance0 = token0.balanceOf(address(this));
        uint256 balance1 = token1.balanceOf(address(this));

        uint256 amount0 = balance0 - _reserve0;
        uint256 amount1 = balance1 - _reserve1;

        if (totalSupply == 0) {
            liquidity = sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY;
            balanceOf[address(0)] = MINIMUM_LIQUIDITY;
        } else {
            liquidity = min((amount0 * totalSupply) / _reserve0, (amount1 * totalSupply) / _reserve1);
        }

        require(liquidity > 0, "Insufficient liquidity minted");

        balanceOf[to] += liquidity;
        totalSupply += liquidity;

        // ✅ Lock liquidity for minimum period
        lockUntil[to] = block.timestamp + LOCK_PERIOD;

        _update(balance0, balance1, _reserve0, _reserve1);
    }

    // ✅ Remove liquidity with lock period check
    function removeLiquidity(
        uint256 liquidity,
        address to
    ) external lock returns (uint256 amount0, uint256 amount1) {
        // ✅ Enforce lock period
        require(block.timestamp >= lockUntil[msg.sender], "Liquidity locked");
        require(balanceOf[msg.sender] >= liquidity, "Insufficient balance");

        uint256 balance0 = token0.balanceOf(address(this));
        uint256 balance1 = token1.balanceOf(address(this));

        amount0 = (liquidity * balance0) / totalSupply;
        amount1 = (liquidity * balance1) / totalSupply;

        require(amount0 > 0 && amount1 > 0, "Insufficient liquidity burned");

        balanceOf[msg.sender] -= liquidity;
        totalSupply -= liquidity;

        token0.transfer(to, amount0);
        token1.transfer(to, amount1);

        balance0 = token0.balanceOf(address(this));
        balance1 = token1.balanceOf(address(this));

        _update(balance0, balance1, reserve0, reserve1);
    }

    // ✅ TWAP price oracle
    function getTWAP(uint32 secondsAgo) external view returns (uint256 price) {
        require(secondsAgo > 0, "Invalid time window");

        uint32 currentTimestamp = uint32(block.timestamp % 2**32);
        uint32 timeElapsed = currentTimestamp - blockTimestampLast;

        require(timeElapsed >= secondsAgo, "Insufficient history");

        // Calculate TWAP from cumulative prices
        uint256 priceCumulative = price0CumulativeLast;
        price = priceCumulative / secondsAgo;
    }

    // ✅ Private update function with TWAP
    function _update(
        uint256 balance0,
        uint256 balance1,
        uint112 _reserve0,
        uint112 _reserve1
    ) private {
        require(balance0 <= type(uint112).max && balance1 <= type(uint112).max, "Overflow");

        uint32 blockTimestamp = uint32(block.timestamp % 2**32);
        uint32 timeElapsed = blockTimestamp - blockTimestampLast;

        // ✅ Update TWAP
        if (timeElapsed > 0 && _reserve0 != 0 && _reserve1 != 0) {
            unchecked {
                price0CumulativeLast += uint256(_reserve1) * 1e18 / _reserve0 * timeElapsed;
                price1CumulativeLast += uint256(_reserve0) * 1e18 / _reserve1 * timeElapsed;
            }
        }

        reserve0 = uint112(balance0);
        reserve1 = uint112(balance1);
        blockTimestampLast = blockTimestamp;
    }

    function getReserves() public view returns (uint112 _reserve0, uint112 _reserve1, uint32 _blockTimestampLast) {
        _reserve0 = reserve0;
        _reserve1 = reserve1;
        _blockTimestampLast = blockTimestampLast;
    }

    function sqrt(uint256 y) internal pure returns (uint256 z) {
        if (y > 3) {
            z = y;
            uint256 x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
    }

    function min(uint256 x, uint256 y) internal pure returns (uint256 z) {
        z = x < y ? x : y;
    }
}
