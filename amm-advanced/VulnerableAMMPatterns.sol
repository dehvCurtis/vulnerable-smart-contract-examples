// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AMM Advanced Vulnerability Patterns
 * @notice Tests advanced Automated Market Maker security detectors
 * @dev Tests: amm-invariant-manipulation, amm-k-invariant-violation
 */

// =====================================================================
// 1. AMM INVARIANT MANIPULATION
// =====================================================================

/**
 * @dev Constant Product AMM (x * y = k) with invariant manipulation vulnerabilities
 */
contract VulnerableConstantProductAMM {
    uint256 public reserveA;
    uint256 public reserveB;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;

    // ❌ VULNERABILITY 1: Invariant not enforced after operations
    function swap(uint256 amountAIn, uint256 amountBOut) external {
        require(amountAIn > 0, "Invalid input");

        // Update reserves without checking invariant
        reserveA += amountAIn;
        reserveB -= amountBOut;

        // ❌ Missing: require(reserveA * reserveB >= k_before, "K decreased");
        // Invariant can be violated, allowing value extraction
    }

    // ❌ VULNERABILITY 2: Flash swap without invariant check
    function flashSwap(
        uint256 amountAOut,
        uint256 amountBOut,
        address to,
        bytes calldata data
    ) external {
        uint256 balanceA_before = reserveA;
        uint256 balanceB_before = reserveB;

        // Send tokens optimistically
        reserveA -= amountAOut;
        reserveB -= amountBOut;

        // Callback to receiver
        if (data.length > 0) {
            IFlashSwapCallback(to).flashSwapCallback(amountAOut, amountBOut, data);
        }

        // ❌ Missing: Verify invariant K increased or stayed same
        // Should check: reserveA * reserveB >= balanceA_before * balanceB_before

        // Only checks balances increased, not invariant
        require(reserveA >= balanceA_before, "Insufficient A");
        require(reserveB >= balanceB_before, "Insufficient B");
    }

    // ❌ VULNERABILITY 3: Add liquidity without minimum invariant check
    function addLiquidity(uint256 amountA, uint256 amountB) external returns (uint256 liquidity) {
        require(amountA > 0 && amountB > 0, "Invalid amounts");

        // ❌ No check that ratio preserves invariant
        // Attacker can add liquidity at bad ratio to manipulate K

        reserveA += amountA;
        reserveB += amountB;

        if (totalSupply == 0) {
            liquidity = sqrt(amountA * amountB);
        } else {
            // ❌ Liquidity calculation doesn't verify invariant preservation
            liquidity = min(
                (amountA * totalSupply) / reserveA,
                (amountB * totalSupply) / reserveB
            );
        }

        balanceOf[msg.sender] += liquidity;
        totalSupply += liquidity;

        // ❌ Missing: Verify K increased proportionally
    }

    // ❌ VULNERABILITY 4: Remove liquidity can violate invariant
    function removeLiquidity(uint256 liquidity) external returns (uint256 amountA, uint256 amountB) {
        require(liquidity > 0, "Invalid liquidity");
        require(balanceOf[msg.sender] >= liquidity, "Insufficient balance");

        amountA = (liquidity * reserveA) / totalSupply;
        amountB = (liquidity * reserveB) / totalSupply;

        balanceOf[msg.sender] -= liquidity;
        totalSupply -= liquidity;

        reserveA -= amountA;
        reserveB -= amountB;

        // ❌ No invariant check after withdrawal
        // With low liquidity, rounding can violate invariant
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
}

interface IFlashSwapCallback {
    function flashSwapCallback(uint256 amountA, uint256 amountB, bytes calldata data) external;
}

// =====================================================================
// 2. AMM K INVARIANT VIOLATION
// =====================================================================

/**
 * @dev Constant Product AMM with direct K invariant violations
 */
contract VulnerableKInvariant {
    uint256 public reserve0;
    uint256 public reserve1;
    uint256 public kLast; // K value from last operation

    // ❌ VULNERABILITY 1: K can decrease during swap
    function swap(uint256 amount0Out, uint256 amount1Out, address to) external {
        require(amount0Out > 0 || amount1Out > 0, "Insufficient output");

        uint256 balance0Before = reserve0;
        uint256 balance1Before = reserve1;

        // Send tokens
        reserve0 -= amount0Out;
        reserve1 -= amount1Out;

        // Get input amounts (simulated)
        uint256 balance0After = reserve0 + 100; // Simulated input
        uint256 balance1After = reserve1;

        uint256 amount0In = balance0After > balance0Before - amount0Out ?
            balance0After - (balance0Before - amount0Out) : 0;
        uint256 amount1In = balance1After > balance1Before - amount1Out ?
            balance1After - (balance1Before - amount1Out) : 0;

        require(amount0In > 0 || amount1In > 0, "Insufficient input");

        // ❌ CRITICAL: No K invariant check!
        // Should verify: balance0After * balance1After >= balance0Before * balance1Before
        // Without this, K can decrease and value can be extracted

        reserve0 = balance0After;
        reserve1 = balance1After;
    }

    // ❌ VULNERABILITY 2: Sync function allows K to decrease
    function sync() external {
        // Sync reserves to actual balances
        uint256 balance0 = getBalance0();
        uint256 balance1 = getBalance1();

        // ❌ No check that new K >= old K
        // Direct token transfers can decrease K

        reserve0 = balance0;
        reserve1 = balance1;
    }

    // ❌ VULNERABILITY 3: Skim function violates invariant
    function skim(address to) external {
        uint256 balance0 = getBalance0();
        uint256 balance1 = getBalance1();

        // Send excess tokens
        if (balance0 > reserve0) {
            // Transfer excess (simulated)
        }
        if (balance1 > reserve1) {
            // Transfer excess (simulated)
        }

        // ❌ After skim, K might be less than before
        // No invariant preservation
    }

    // ❌ VULNERABILITY 4: Fee calculation can decrease K
    function swapWithFee(uint256 amount0In, uint256 amount1Out) external {
        uint256 balance0Before = reserve0;
        uint256 balance1Before = reserve1;

        reserve0 += amount0In;
        reserve1 -= amount1Out;

        // Apply 0.3% fee
        uint256 balance0Adjusted = reserve0 * 1000 - (amount0In * 3);
        uint256 balance1Adjusted = reserve1 * 1000;

        // ❌ VULNERABILITY: Incorrect fee calculation can violate K
        // Should be: balance0Adjusted * balance1Adjusted >= balance0Before * balance1Before * (1000^2)
        require(balance0Adjusted * balance1Adjusted >= balance0Before * balance1Before, "K");
        // Missing multiplication by 1000^2 for proper scaling
    }

    function getBalance0() internal view returns (uint256) {
        return reserve0;
    }

    function getBalance1() internal view returns (uint256) {
        return reserve1;
    }
}

// =====================================================================
// 3. CURVE STABLESWAP INVARIANT
// =====================================================================

/**
 * @dev Curve-style StableSwap with invariant violations
 */
contract VulnerableStableSwap {
    uint256 public constant A = 100; // Amplification coefficient
    uint256[2] public balances;

    // StableSwap invariant: A * sum(x_i) * n^n + D = A * D * n^n + D^(n+1) / (n^n * prod(x_i))

    // ❌ VULNERABILITY 1: Swap without invariant check
    function swap(uint256 i, uint256 j, uint256 dx) external returns (uint256 dy) {
        require(i != j, "Same token");
        require(i < 2 && j < 2, "Invalid index");

        uint256 x = balances[i] + dx;
        // Calculate y using StableSwap formula (simplified)
        uint256 y = getY(i, j, x);

        dy = balances[j] - y;

        balances[i] = x;
        balances[j] = y;

        // ❌ Missing: Verify D (invariant) didn't decrease
        // StableSwap invariant must be preserved
    }

    // ❌ VULNERABILITY 2: Add liquidity without checking D
    function addLiquidity(uint256[2] memory amounts) external returns (uint256) {
        uint256 D0 = getD();

        for (uint256 i = 0; i < 2; i++) {
            balances[i] += amounts[i];
        }

        uint256 D1 = getD();

        // ❌ Should verify D1 > D0 (invariant increased)
        // But doesn't check this properly

        return D1 - D0; // Liquidity tokens
    }

    // Simplified D calculation (real Curve uses iterative Newton's method)
    function getD() internal view returns (uint256) {
        uint256 sum = balances[0] + balances[1];
        return sum; // Simplified
    }

    // Simplified y calculation
    function getY(uint256 i, uint256 j, uint256 x) internal view returns (uint256) {
        return balances[j] - (x - balances[i]); // Simplified
    }
}

// =====================================================================
// 4. BALANCER WEIGHTED POOL INVARIANT
// =====================================================================

/**
 * @dev Balancer-style weighted pool with invariant violations
 */
contract VulnerableWeightedPool {
    struct TokenInfo {
        uint256 balance;
        uint256 weight; // Normalized weight (sum = 1e18)
    }

    mapping(address => TokenInfo) public tokens;
    address[] public tokenList;

    // Balancer invariant: V = prod(B_i ^ W_i)
    // Where V is constant, B_i is balance, W_i is weight

    // ❌ VULNERABILITY 1: Swap without invariant check
    function swap(
        address tokenIn,
        address tokenOut,
        uint256 amountIn
    ) external returns (uint256 amountOut) {
        TokenInfo storage tokenInfoIn = tokens[tokenIn];
        TokenInfo storage tokenInfoOut = tokens[tokenOut];

        // Calculate amountOut using weighted product formula (simplified)
        amountOut = calcOutGivenIn(
            tokenInfoIn.balance,
            tokenInfoIn.weight,
            tokenInfoOut.balance,
            tokenInfoOut.weight,
            amountIn
        );

        tokenInfoIn.balance += amountIn;
        tokenInfoOut.balance -= amountOut;

        // ❌ Missing: Verify invariant V preserved
        // Should check: prod(B_i^W_i) after >= prod(B_i^W_i) before
    }

    // ❌ VULNERABILITY 2: Join pool without invariant verification
    function joinPool(uint256[] memory amountsIn) external {
        require(amountsIn.length == tokenList.length, "Invalid amounts");

        for (uint256 i = 0; i < tokenList.length; i++) {
            tokens[tokenList[i]].balance += amountsIn[i];
        }

        // ❌ No check that weighted product increased properly
    }

    // Simplified calculation (real Balancer uses complex math)
    function calcOutGivenIn(
        uint256 balanceIn,
        uint256 weightIn,
        uint256 balanceOut,
        uint256 weightOut,
        uint256 amountIn
    ) internal pure returns (uint256) {
        // Simplified version
        return (amountIn * balanceOut) / balanceIn;
    }
}

// =====================================================================
// 5. UNISWAP V3 CONCENTRATED LIQUIDITY
// =====================================================================

/**
 * @dev Uniswap V3 style with concentrated liquidity invariant issues
 */
contract VulnerableConcentratedLiquidity {
    struct Position {
        uint128 liquidity;
        int24 tickLower;
        int24 tickUpper;
    }

    uint160 public sqrtPriceX96;
    uint128 public liquidity;
    int24 public tick;

    mapping(bytes32 => Position) public positions;

    // ❌ VULNERABILITY 1: Swap can violate sqrt price invariant
    function swap(bool zeroForOne, int256 amountSpecified) external {
        uint160 sqrtPriceLimitX96 = zeroForOne ?
            4295128739 : // MIN_SQRT_RATIO
            1461446703485210103287273052203988822378723970342; // MAX_SQRT_RATIO

        // ❌ No verification that new price is within valid range for liquidity
        // Should check position bounds and liquidity depth

        sqrtPriceX96 = zeroForOne ?
            sqrtPriceX96 - 1000 :
            sqrtPriceX96 + 1000;

        // ❌ Missing: Verify sqrt price matches actual reserves
        // ❌ Missing: Check liquidity is sufficient for price movement
    }

    // ❌ VULNERABILITY 2: Mint position without range validation
    function mint(
        int24 tickLower,
        int24 tickUpper,
        uint128 amount
    ) external returns (bytes32 positionKey) {
        require(tickLower < tickUpper, "Invalid ticks");

        positionKey = keccak256(abi.encodePacked(msg.sender, tickLower, tickUpper));

        positions[positionKey] = Position({
            liquidity: amount,
            tickLower: tickLower,
            tickUpper: tickUpper
        });

        // ❌ No check that ticks are properly spaced
        // ❌ No verification of price impact on global state
        // ❌ Missing: Update global liquidity if position is in range
    }
}

/**
 * TESTING NOTES:
 *
 * Expected Detectors:
 * 1. amm-invariant-manipulation (8+ findings)
 *    - Swap without invariant check
 *    - Flash swap without K verification
 *    - Add/remove liquidity without invariant preservation
 *    - Sync/skim allowing invariant violations
 *
 * 2. amm-k-invariant-violation (10+ findings)
 *    - Direct K decrease during swap
 *    - Fee calculation violating K
 *    - Sync without K check
 *    - Incorrect invariant scaling
 *
 * Cross-Category Detectors Expected:
 * - defi-liquidity-pool-manipulation
 * - amm-liquidity-manipulation
 * - vault-donation-attack
 * - integer-overflow (potential in calculations)
 * - division-before-multiplication
 *
 * Real-World Relevance:
 * - Uniswap V2/V3: Constant product formula (x * y = k)
 * - Curve Finance: StableSwap invariant
 * - Balancer: Weighted product invariant
 * - Critical for preventing value extraction
 * - Invariant violations = free money for attackers
 */
