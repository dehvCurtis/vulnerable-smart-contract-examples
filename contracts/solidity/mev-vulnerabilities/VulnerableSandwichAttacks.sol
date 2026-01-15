// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableSandwichAttacks
 * @notice Test contract for sandwich attack and swap MEV vulnerabilities
 *
 * DETECTORS TO TEST:
 * - mev-sandwich-vulnerable-swaps (High)
 * - sandwich-attack (Medium)
 * - sandwich-resistant-swap (High)
 * - mev-extractable-value (High)
 * - front-running-mitigation (High)
 * - jit-liquidity-sandwich (High)
 *
 * VULNERABILITIES:
 * 1. Swap with zero minimum output
 * 2. No slippage parameter in swap function
 * 3. Large swaps without MEV protection (Flashbots)
 * 4. Deadline set to type(uint256).max
 * 5. No deadline parameter at all
 * 6. Swap using balanceOf() without slippage
 * 7. JIT liquidity without lock period
 * 8. Swap without TWAP or oracle protection
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IUniswapV2Router {
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
}

contract VulnerableSwapAggregator {
    IUniswapV2Router public router;

    constructor(address _router) {
        router = IUniswapV2Router(_router);
    }

    // ❌ VULNERABILITY 1: Swap with zero minimum output (mev-sandwich-vulnerable-swaps)
    // 100% vulnerable to sandwich attacks
    function swapWithZeroSlippage(
        uint256 amountIn,
        address[] calldata path
    ) external returns (uint256 amountOut) {
        IERC20(path[0]).transferFrom(msg.sender, address(this), amountIn);
        IERC20(path[0]).approve(address(router), amountIn);

        // ❌ amountOutMin: 0 means accept ANY output amount!
        // Attacker can: front-run with buy → victim swap → back-run with sell
        uint[] memory amounts = router.swapExactTokensForTokens(
            amountIn,
            0, // ❌ Zero slippage protection!
            path,
            msg.sender,
            block.timestamp + 300
        );

        return amounts[amounts.length - 1];
    }

    // ❌ VULNERABILITY 2: No slippage parameter (mev-sandwich-vulnerable-swaps)
    // Users cannot specify minimum output
    function swapNoSlippageParam(
        uint256 amountIn,
        address[] calldata path
    ) external returns (uint256) {
        // ❌ Missing minAmountOut parameter!
        // Should be: function swap(..., uint256 minAmountOut)

        IERC20(path[0]).transferFrom(msg.sender, address(this), amountIn);
        IERC20(path[0]).approve(address(router), amountIn);

        // Hard-coded zero slippage - users have no control
        uint[] memory amounts = router.swapExactTokensForTokens(
            amountIn,
            0, // ❌ Users cannot protect themselves!
            path,
            msg.sender,
            block.timestamp + 300
        );

        return amounts[amounts.length - 1];
    }

    // ❌ VULNERABILITY 3: Large swap without MEV protection (mev-sandwich-vulnerable-swaps)
    // High-value swaps should use Flashbots or private mempool
    function swapEntireBalance(
        address tokenIn,
        address[] calldata path
    ) external returns (uint256) {
        // ❌ Swapping entire balance without Flashbots/MEV protection!
        uint256 balance = IERC20(tokenIn).balanceOf(address(this));

        // ❌ No flashbots, no private mempool, no MEV-Share
        // Large swaps are prime targets for sandwich attacks
        // Should use: Flashbots RPC or MEV-Share

        IERC20(tokenIn).approve(address(router), balance);

        uint[] memory amounts = router.swapExactTokensForTokens(
            balance,
            0, // Also has zero slippage!
            path,
            msg.sender,
            block.timestamp + 300
        );

        return amounts[amounts.length - 1];
    }

    // ❌ VULNERABILITY 4: Deadline too far in future (mev-sandwich-vulnerable-swaps)
    // Transaction can be held and executed at worst price
    function swapWithMaxDeadline(
        uint256 amountIn,
        uint256 minAmountOut,
        address[] calldata path
    ) external returns (uint256) {
        IERC20(path[0]).transferFrom(msg.sender, address(this), amountIn);
        IERC20(path[0]).approve(address(router), amountIn);

        // ❌ deadline: type(uint256).max
        // Validator can hold transaction indefinitely and execute at unfavorable price
        uint[] memory amounts = router.swapExactTokensForTokens(
            amountIn,
            minAmountOut,
            path,
            msg.sender,
            type(uint256).max // ❌ No deadline protection!
        );

        return amounts[amounts.length - 1];
    }

    // ❌ VULNERABILITY 5: No deadline parameter at all (front-running-mitigation)
    // Function lacks time-based protection
    function swapNoDeadline(
        uint256 amountIn,
        uint256 minAmountOut,
        address[] calldata path
    ) external returns (uint256) {
        // ❌ Missing deadline parameter!
        // Should be: function swap(..., uint256 deadline)

        IERC20(path[0]).transferFrom(msg.sender, address(this), amountIn);
        IERC20(path[0]).approve(address(router), amountIn);

        uint[] memory amounts = router.swapExactTokensForTokens(
            amountIn,
            minAmountOut,
            path,
            msg.sender,
            block.timestamp // ❌ Uses current timestamp, no user control
        );

        return amounts[amounts.length - 1];
    }

    // ❌ VULNERABILITY 6: Swap calculates output without protection (sandwich-attack)
    function swapCalculated(
        uint256 amountIn,
        address[] calldata path
    ) external returns (uint256 amountOut) {
        // Calculate expected output
        uint256 expectedOut = getAmountOut(amountIn, path);

        // ❌ Uses calculated amount but no slippage tolerance!
        // Price can change between calculation and execution
        amountOut = executeSwap(amountIn, expectedOut, path);
    }

    function getAmountOut(uint256 amountIn, address[] memory path) internal view returns (uint256) {
        // Simplified price calculation
        // Real implementation would query reserves
        return amountIn * 99 / 100; // Assume 1% fee
    }

    function executeSwap(
        uint256 amountIn,
        uint256 minAmountOut,
        address[] calldata path
    ) internal returns (uint256) {
        IERC20(path[0]).transferFrom(msg.sender, address(this), amountIn);
        IERC20(path[0]).approve(address(router), amountIn);

        uint[] memory amounts = router.swapExactTokensForTokens(
            amountIn,
            minAmountOut,
            path,
            msg.sender,
            block.timestamp + 300
        );

        return amounts[amounts.length - 1];
    }

    // ❌ VULNERABILITY 7: No MEV protection for price-sensitive operation (mev-extractable-value)
    function buyToken(address token, uint256 ethAmount) external payable {
        // ❌ Price-sensitive purchase without TWAP or oracle
        // ❌ No slippage protection
        // ❌ No private mempool usage

        // This is vulnerable to:
        // 1. Sandwich attacks
        // 2. Front-running
        // 3. Price manipulation

        // Simplified swap logic
        require(msg.value >= ethAmount, "Insufficient ETH");
    }
}

/**
 * @notice JIT Liquidity Attack Vulnerability
 */
contract VulnerableJITLiquidity {
    mapping(address => uint256) public liquidity;
    mapping(address => uint256) public liquidityLockTime;

    uint256 public totalLiquidity;
    uint256 public reserve0;
    uint256 public reserve1;

    IERC20 public token0;
    IERC20 public token1;

    constructor(address _token0, address _token1) {
        token0 = IERC20(_token0);
        token1 = IERC20(_token1);
    }

    // ❌ VULNERABILITY 8: Add liquidity without lock period (jit-liquidity-sandwich)
    // JIT attack: add liquidity → swap happens → remove liquidity immediately
    function addLiquidity(uint256 amount0, uint256 amount1) external returns (uint256) {
        // ❌ NO minimum liquidity lock period!
        // User can: addLiquidity() → large swap occurs → removeLiquidity()
        // This allows capturing fees without providing long-term liquidity

        token0.transferFrom(msg.sender, address(this), amount0);
        token1.transferFrom(msg.sender, address(this), amount1);

        uint256 liquidityMinted = calculateLiquidity(amount0, amount1);

        liquidity[msg.sender] += liquidityMinted;
        totalLiquidity += liquidityMinted;

        reserve0 += amount0;
        reserve1 += amount1;

        // ❌ Missing: liquidityLockTime[msg.sender] = block.timestamp + LOCK_PERIOD;

        return liquidityMinted;
    }

    // ❌ VULNERABILITY 9: Remove liquidity immediately after adding (jit-liquidity-sandwich)
    function removeLiquidity(uint256 amount) external {
        // ❌ No check for minimum lock period!
        // Should have: require(block.timestamp >= liquidityLockTime[msg.sender]);

        require(liquidity[msg.sender] >= amount, "Insufficient liquidity");

        uint256 amount0 = (amount * reserve0) / totalLiquidity;
        uint256 amount1 = (amount * reserve1) / totalLiquidity;

        liquidity[msg.sender] -= amount;
        totalLiquidity -= amount;

        reserve0 -= amount0;
        reserve1 -= amount1;

        token0.transfer(msg.sender, amount0);
        token1.transfer(msg.sender, amount1);
    }

    function calculateLiquidity(uint256 amount0, uint256 amount1) internal view returns (uint256) {
        if (totalLiquidity == 0) {
            return sqrt(amount0 * amount1);
        }
        return min(
            (amount0 * totalLiquidity) / reserve0,
            (amount1 * totalLiquidity) / reserve1
        );
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

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    // Swap function for testing
    function swap(uint256 amount0Out, uint256 amount1Out, address to) external {
        require(amount0Out > 0 || amount1Out > 0, "Invalid output");

        if (amount0Out > 0) token0.transfer(to, amount0Out);
        if (amount1Out > 0) token1.transfer(to, amount1Out);

        // Update reserves
        uint256 balance0 = token0.balanceOf(address(this));
        uint256 balance1 = token1.balanceOf(address(this));

        reserve0 = balance0;
        reserve1 = balance1;
    }
}

/**
 * @notice Secure swap implementation
 */
contract SecureSwapAggregator {
    IUniswapV2Router public router;
    uint256 public constant MAX_SLIPPAGE_BPS = 1000; // 10% max

    constructor(address _router) {
        router = IUniswapV2Router(_router);
    }

    // ✅ Secure swap with all protections
    function secureSwap(
        uint256 amountIn,
        uint256 minAmountOut,
        address[] calldata path,
        uint256 deadline
    ) external returns (uint256) {
        // ✅ User provides minAmountOut
        // ✅ User provides deadline
        // ✅ Validation of parameters

        require(minAmountOut > 0, "Zero minimum output");
        require(deadline >= block.timestamp, "Deadline expired");
        require(deadline <= block.timestamp + 3600, "Deadline too far");

        IERC20(path[0]).transferFrom(msg.sender, address(this), amountIn);
        IERC20(path[0]).approve(address(router), amountIn);

        uint[] memory amounts = router.swapExactTokensForTokens(
            amountIn,
            minAmountOut,
            path,
            msg.sender,
            deadline
        );

        return amounts[amounts.length - 1];
    }

    // ✅ Helper to calculate minimum output with slippage
    function calculateMinOutput(
        uint256 expectedOut,
        uint256 slippageBps
    ) public pure returns (uint256) {
        require(slippageBps <= MAX_SLIPPAGE_BPS, "Slippage too high");
        return expectedOut * (10000 - slippageBps) / 10000;
    }
}
