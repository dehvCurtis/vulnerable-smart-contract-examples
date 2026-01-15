// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableYieldFarming
 * @notice Test contract for yield farming and reward vulnerabilities
 *
 * DETECTORS TO TEST:
 * - defi-yield-farming-exploits (High)
 * - yield-farming-manipulation (Medium)
 * - reward-calculation-manipulation (Medium)
 * - liquidity-bootstrapping-abuse (Medium)
 * - emergency-withdrawal-abuse (Medium)
 * - uniswapv4-hook-issues (High)
 *
 * VULNERABILITIES:
 * 1. Reward calculation based on current TVL (manipulable)
 * 2. No minimum staking duration
 * 3. First depositor manipulation
 * 4. Deposit/withdrawal fees without validation
 * 5. Share price manipulation in rewards
 * 6. Emergency withdrawal bypasses locks and loses rewards
 * 7. LBP weight changes without rate limiting
 * 8. Uniswap V4 hook unsafe callbacks
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IPriceOracle {
    function getPrice(address token) external view returns (uint256);
}

contract VulnerableYieldFarm {
    IERC20 public stakingToken;
    IERC20 public rewardToken;
    IPriceOracle public oracle;

    struct UserInfo {
        uint256 amount;
        uint256 rewardDebt;
        uint256 depositTime;
    }

    mapping(address => UserInfo) public userInfo;
    uint256 public totalStaked;

    uint256 public rewardPerSecond = 1e18;
    uint256 public lastRewardTime;
    uint256 public accRewardPerShare;

    uint256 public depositFee = 200; // 2%
    uint256 public withdrawalFee = 500; // 5%

    constructor(address _stakingToken, address _rewardToken, address _oracle) {
        stakingToken = IERC20(_stakingToken);
        rewardToken = IERC20(_rewardToken);
        oracle = IPriceOracle(_oracle);
        lastRewardTime = block.timestamp;
    }

    // ❌ VULNERABILITY 1: Reward calculation based on current TVL (yield-farming-manipulation)
    // Attacker can flash loan to inflate TVL, claim huge rewards, then withdraw
    function updatePool() public {
        if (block.timestamp <= lastRewardTime) {
            return;
        }

        if (totalStaked == 0) {
            lastRewardTime = block.timestamp;
            return;
        }

        uint256 timeElapsed = block.timestamp - lastRewardTime;
        uint256 reward = timeElapsed * rewardPerSecond;

        // ❌ Rewards distributed based on current TVL, not time-weighted
        // Attacker can: deposit huge amount → updatePool → claim rewards → withdraw
        accRewardPerShare = accRewardPerShare + (reward * 1e12) / totalStaked;

        lastRewardTime = block.timestamp;
    }

    // ❌ VULNERABILITY 2: No minimum staking duration (yield-farming-manipulation)
    function deposit(uint256 amount) external {
        UserInfo storage user = userInfo[msg.sender];

        updatePool();

        if (user.amount > 0) {
            uint256 pending = (user.amount * accRewardPerShare) / 1e12 - user.rewardDebt;
            if (pending > 0) {
                rewardToken.transfer(msg.sender, pending);
            }
        }

        if (amount > 0) {
            // ❌ Missing deposit fee validation
            // Fee can be 100% (10000 basis points) if changed before transaction
            uint256 fee = (amount * depositFee) / 10000;
            uint256 amountAfterFee = amount - fee;

            stakingToken.transferFrom(msg.sender, address(this), amount);

            user.amount = user.amount + amountAfterFee;
            user.depositTime = block.timestamp; // Recorded but not enforced!
        }

        totalStaked = totalStaked + amount;
        user.rewardDebt = (user.amount * accRewardPerShare) / 1e12;
    }

    // ❌ VULNERABILITY 3: No staking duration requirement (yield-farming-manipulation)
    function withdraw(uint256 amount) external {
        UserInfo storage user = userInfo[msg.sender];

        // ❌ No minimum staking duration check!
        // Should have: require(block.timestamp >= user.depositTime + MIN_STAKE_DURATION);

        require(user.amount >= amount, "Insufficient balance");

        updatePool();

        uint256 pending = (user.amount * accRewardPerShare) / 1e12 - user.rewardDebt;
        if (pending > 0) {
            rewardToken.transfer(msg.sender, pending);
        }

        if (amount > 0) {
            user.amount = user.amount - amount;
            stakingToken.transfer(msg.sender, amount);
        }

        totalStaked = totalStaked - amount;
        user.rewardDebt = (user.amount * accRewardPerShare) / 1e12;
    }

    // ❌ VULNERABILITY 4: Emergency withdrawal bypasses locks (emergency-withdrawal-abuse)
    function emergencyWithdraw() external {
        UserInfo storage user = userInfo[msg.sender];

        uint256 amount = user.amount;

        // ❌ Bypasses any time locks or vesting
        // ❌ User loses all pending rewards (can be abused)
        user.amount = 0;
        user.rewardDebt = 0;

        totalStaked = totalStaked - amount;

        stakingToken.transfer(msg.sender, amount);

        // User loses rewards - this can be griefing vector or admin abuse
    }

    // ❌ VULNERABILITY 5: Reward calculation using spot price (reward-calculation-manipulation)
    function calculateRewardBonus(address user) public view returns (uint256) {
        UserInfo memory info = userInfo[user];

        // ❌ Uses spot price from oracle for reward multiplier
        // Price can be manipulated via flash loan
        uint256 tokenPrice = oracle.getPrice(address(stakingToken));

        // ❌ Rewards incentivize price deviation
        // Higher price = higher rewards = incentive to manipulate
        uint256 bonus = (info.amount * tokenPrice) / 1e18;

        return bonus;
    }

    // ❌ VULNERABILITY 6: Fee parameters unvalidated (defi-yield-farming-exploits)
    function setDepositFee(uint256 newFee) external {
        // ❌ No access control
        // ❌ No maximum fee limit
        // ❌ Can be set to 100% (10000 basis points)
        depositFee = newFee;
    }

    function setWithdrawalFee(uint256 newFee) external {
        // ❌ Same vulnerabilities as setDepositFee
        withdrawalFee = newFee;
    }
}

/**
 * @notice Liquidity Bootstrapping Pool with weight manipulation
 */
contract VulnerableLBP {
    IERC20 public token0;
    IERC20 public token1;

    uint256 public weight0 = 80; // 80% initially
    uint256 public weight1 = 20; // 20% initially

    uint256 public reserve0;
    uint256 public reserve1;

    address public owner;

    constructor(address _token0, address _token1) {
        token0 = IERC20(_token0);
        token1 = IERC20(_token1);
        owner = msg.sender;
    }

    // ❌ VULNERABILITY 7: Weight update without rate limiting (liquidity-bootstrapping-abuse)
    function updateWeights(uint256 newWeight0, uint256 newWeight1) external {
        require(msg.sender == owner, "Only owner");

        // ❌ No rate limiting on weight changes!
        // Owner can change from 80/20 to 20/80 instantly
        // This causes massive price impact
        // Should have: require(abs(newWeight0 - weight0) <= MAX_WEIGHT_CHANGE_PER_UPDATE)

        // ❌ No maximum weight change validation
        require(newWeight0 + newWeight1 == 100, "Weights must sum to 100");

        weight0 = newWeight0;
        weight1 = newWeight1;

        // Price changes dramatically without gradual transition
    }

    // ❌ VULNERABILITY 8: No per-address purchase cap (liquidity-bootstrapping-abuse)
    function buyTokens(uint256 amount1In) external {
        // ❌ No per-address cap!
        // Whale can buy entire supply in one transaction
        // Should have: require(purchases[msg.sender] + amount1In <= MAX_PER_ADDRESS);

        uint256 amount0Out = calculateOutput(amount1In);

        token1.transferFrom(msg.sender, address(this), amount1In);
        token0.transfer(msg.sender, amount0Out);

        reserve0 -= amount0Out;
        reserve1 += amount1In;
    }

    function calculateOutput(uint256 amountIn) internal view returns (uint256) {
        // Simplified LBP pricing using weights
        // Real implementation would use Balancer-style weighted math
        return (amountIn * reserve0 * weight1) / (reserve1 * weight0);
    }
}

/**
 * @notice Uniswap V4 Hook with vulnerabilities
 */
contract VulnerableUniswapV4Hook {
    address public poolManager;

    // ❌ VULNERABILITY 9: Unsafe callback without validation (uniswapv4-hook-issues)
    function beforeSwap(
        address sender,
        bytes calldata data
    ) external returns (bytes4) {
        // ❌ No validation of caller!
        // Should check: require(msg.sender == poolManager);

        // ❌ No validation of hook data
        // Malicious data can cause unexpected behavior

        // Execute arbitrary logic without safety checks
        (bool success,) = sender.call(data);
        require(success);

        return this.beforeSwap.selector;
    }

    // ❌ VULNERABILITY 10: Hook can extract fees without limits (uniswapv4-hook-issues)
    function afterSwap(
        address, /*sender*/
        uint256 amount0,
        uint256 amount1
    ) external returns (bytes4) {
        // ❌ No access control on who can call this
        // ❌ Hook can extract unlimited fees

        uint256 fee = (amount0 + amount1) / 100; // 1% fee extraction

        // Extract fee without validation or limits
        // In real implementation would transfer tokens

        return this.afterSwap.selector;
    }

    // ❌ VULNERABILITY 11: Missing access control (uniswapv4-hook-issues)
    function beforeAddLiquidity(
        address sender,
        uint256 amount0,
        uint256 amount1
    ) external returns (bytes4) {
        // ❌ Anyone can call this hook function!
        // Should validate msg.sender is pool manager

        // ❌ No validation of amounts
        // ❌ No validation of sender

        return this.beforeAddLiquidity.selector;
    }
}

/**
 * @notice Secure yield farming implementation
 */
contract SecureYieldFarm {
    IERC20 public stakingToken;
    IERC20 public rewardToken;

    struct UserInfo {
        uint256 amount;
        uint256 rewardDebt;
        uint256 depositTime;
        uint256 accumulatedTime; // Time-weighted staking
    }

    mapping(address => UserInfo) public userInfo;
    uint256 public totalStaked;
    uint256 public totalTimeWeightedStake;

    uint256 public constant REWARD_PER_SECOND = 1e18;
    uint256 public constant MIN_STAKE_DURATION = 1 days;
    uint256 public constant MAX_DEPOSIT_FEE = 500; // 5% max
    uint256 public constant MAX_WITHDRAWAL_FEE = 1000; // 10% max

    uint256 public depositFee = 100; // 1%
    uint256 public lastRewardTime;
    uint256 public accRewardPerShare;

    address public owner;

    constructor(address _stakingToken, address _rewardToken) {
        stakingToken = IERC20(_stakingToken);
        rewardToken = IERC20(_rewardToken);
        owner = msg.sender;
        lastRewardTime = block.timestamp;
    }

    // ✅ Time-weighted reward distribution
    function updatePool() public {
        if (block.timestamp <= lastRewardTime) {
            return;
        }

        if (totalTimeWeightedStake == 0) {
            lastRewardTime = block.timestamp;
            return;
        }

        uint256 timeElapsed = block.timestamp - lastRewardTime;
        uint256 reward = timeElapsed * REWARD_PER_SECOND;

        // ✅ Uses time-weighted stake, not current TVL
        accRewardPerShare += (reward * 1e12) / totalTimeWeightedStake;

        lastRewardTime = block.timestamp;
    }

    // ✅ Secure deposit with fee validation
    function deposit(uint256 amount) external {
        UserInfo storage user = userInfo[msg.sender];

        updatePool();

        if (user.amount > 0) {
            // Update time-weighted stake before claiming
            uint256 timeStaked = block.timestamp - user.depositTime;
            user.accumulatedTime += timeStaked;
        }

        require(amount > 0, "Cannot deposit 0");

        // ✅ Validate fee is within limits
        require(depositFee <= MAX_DEPOSIT_FEE, "Fee too high");

        uint256 fee = (amount * depositFee) / 10000;
        uint256 amountAfterFee = amount - fee;

        stakingToken.transferFrom(msg.sender, address(this), amount);

        user.amount += amountAfterFee;
        user.depositTime = block.timestamp;
        totalStaked += amountAfterFee;

        user.rewardDebt = (user.amount * accRewardPerShare) / 1e12;
    }

    // ✅ Secure withdrawal with minimum staking duration
    function withdraw(uint256 amount) external {
        UserInfo storage user = userInfo[msg.sender];

        // ✅ Enforce minimum staking duration
        require(
            block.timestamp >= user.depositTime + MIN_STAKE_DURATION,
            "Minimum stake duration not met"
        );

        require(user.amount >= amount, "Insufficient balance");

        updatePool();

        uint256 pending = (user.amount * accRewardPerShare) / 1e12 - user.rewardDebt;
        if (pending > 0) {
            rewardToken.transfer(msg.sender, pending);
        }

        if (amount > 0) {
            user.amount -= amount;
            stakingToken.transfer(msg.sender, amount);
        }

        totalStaked -= amount;
        user.rewardDebt = (user.amount * accRewardPerShare) / 1e12;
    }

    // ✅ Controlled fee updates with limits
    function setDepositFee(uint256 newFee) external {
        require(msg.sender == owner, "Only owner");
        require(newFee <= MAX_DEPOSIT_FEE, "Fee exceeds maximum");

        depositFee = newFee;
    }
}
