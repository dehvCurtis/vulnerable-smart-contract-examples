// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableFlashLoanStakingReentrancy
 * @notice Test contract for flash loan staking and reentrancy combo vulnerabilities
 *
 * DETECTORS TO TEST:
 * - flash-loan-staking (Critical)
 * - flash-loan-reentrancy-combo (Critical)
 * - flashloan-callback-reentrancy (Medium)
 *
 * VULNERABILITIES:
 * 1. Staking rewards based on current balance (flash loan attack)
 * 2. Yield farming without minimum staking duration
 * 3. Flash loan callback allows reentrancy
 * 4. Reward calculation during flash loan callback
 * 5. No reentrancy protection on flash loan functions
 * 6. State updates after external calls in flash loans
 * 7. Multiple flash loan reentrancy
 * 8. Flash loan + reentrancy combo to drain funds
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IFlashLoanReceiver {
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

/**
 * @notice Vulnerable staking pool with flash loan attack
 */
contract VulnerableStakingPool {
    IERC20 public stakingToken;
    IERC20 public rewardToken;

    struct UserInfo {
        uint256 amount;
        uint256 rewardDebt;
        uint256 lastStakeTime;
    }

    mapping(address => UserInfo) public userInfo;
    uint256 public totalStaked;
    uint256 public accRewardPerShare;
    uint256 public lastRewardBlock;
    uint256 public rewardPerBlock = 1e18;

    constructor(address _stakingToken, address _rewardToken) {
        stakingToken = IERC20(_stakingToken);
        rewardToken = IERC20(_rewardToken);
        lastRewardBlock = block.number;
    }

    // ❌ VULNERABILITY 1: Reward calculation based on current stake (flash-loan-staking)
    // No minimum staking duration required
    function stake(uint256 amount) external {
        UserInfo storage user = userInfo[msg.sender];

        updatePool();

        if (user.amount > 0) {
            // Calculate pending rewards
            uint256 pending = (user.amount * accRewardPerShare) / 1e12 - user.rewardDebt;
            if (pending > 0) {
                rewardToken.transfer(msg.sender, pending);
            }
        }

        if (amount > 0) {
            stakingToken.transferFrom(msg.sender, address(this), amount);
            user.amount += amount;
            user.lastStakeTime = block.timestamp; // ❌ Recorded but not enforced!
        }

        totalStaked += amount;
        user.rewardDebt = (user.amount * accRewardPerShare) / 1e12;
    }

    // ❌ VULNERABILITY 2: Withdraw without minimum duration (flash-loan-staking)
    function withdraw(uint256 amount) external {
        UserInfo storage user = userInfo[msg.sender];

        // ❌ NO minimum staking duration check!
        // Should have: require(block.timestamp >= user.lastStakeTime + MIN_DURATION);

        // Attacker can:
        // 1. Flash loan staking tokens
        // 2. Stake() to boost their share
        // 3. Trigger updatePool() or wait for next block
        // 4. Withdraw() with rewards
        // 5. Return flash loan
        // 6. Keep the rewards earned from temporary stake!

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

    // ❌ VULNERABILITY 3: Instant rewards (flash-loan-staking)
    function claimRewards() external {
        UserInfo storage user = userInfo[msg.sender];

        updatePool();

        // ❌ Can claim immediately after staking!
        uint256 pending = (user.amount * accRewardPerShare) / 1e12 - user.rewardDebt;
        require(pending > 0, "No rewards");

        // Flash loan attack:
        // 1. Flash loan tokens
        // 2. Stake
        // 3. ClaimRewards (get rewards based on huge stake)
        // 4. Unstake
        // 5. Return flash loan
        // 6. Profit from rewards

        rewardToken.transfer(msg.sender, pending);
        user.rewardDebt = (user.amount * accRewardPerShare) / 1e12;
    }

    function updatePool() public {
        if (block.number <= lastRewardBlock) {
            return;
        }

        if (totalStaked == 0) {
            lastRewardBlock = block.number;
            return;
        }

        uint256 blockDelta = block.number - lastRewardBlock;
        uint256 reward = blockDelta * rewardPerBlock;

        accRewardPerShare += (reward * 1e12) / totalStaked;
        lastRewardBlock = block.number;
    }
}

/**
 * @notice Vulnerable flash loan provider with reentrancy
 */
contract VulnerableFlashLoanProvider {
    IERC20 public lendingToken;
    uint256 public poolBalance;

    constructor(address _lendingToken) {
        lendingToken = IERC20(_lendingToken);
    }

    // ❌ VULNERABILITY 4: Flash loan callback without reentrancy protection (flashloan-callback-reentrancy)
    function flashLoan(
        address receiver,
        uint256 amount,
        bytes calldata params
    ) external {
        uint256 balanceBefore = lendingToken.balanceOf(address(this));
        require(balanceBefore >= amount, "Insufficient liquidity");

        // ❌ Transfer before callback - vulnerable to reentrancy!
        lendingToken.transfer(receiver, amount);

        // ❌ External call without reentrancy guard!
        // Receiver can re-enter flashLoan() or other functions
        address[] memory assets = new address[](1);
        assets[0] = address(lendingToken);

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = amount;

        uint256[] memory premiums = new uint256[](1);
        premiums[0] = amount / 100; // 1% fee

        IFlashLoanReceiver(receiver).executeOperation(
            assets,
            amounts,
            premiums,
            msg.sender,
            params
        );

        // ❌ State check after external call!
        uint256 balanceAfter = lendingToken.balanceOf(address(this));
        require(
            balanceAfter >= balanceBefore + premiums[0],
            "Flash loan not repaid"
        );

        poolBalance = balanceAfter;
    }

    // ❌ VULNERABILITY 5: Deposit during flash loan callback (flash-loan-reentrancy-combo)
    function deposit(uint256 amount) external {
        // ❌ No reentrancy protection!
        // Can be called during flash loan callback

        lendingToken.transferFrom(msg.sender, address(this), amount);
        poolBalance += amount;

        // Attack:
        // 1. Call flashLoan()
        // 2. In callback, deposit() borrowed funds
        // 3. poolBalance increases
        // 4. Return funds to pass flashLoan() check
        // 5. Now attacker has deposit credited but funds returned
    }

    // ❌ VULNERABILITY 6: Withdraw during flash loan (flash-loan-reentrancy-combo)
    function withdraw(uint256 amount) external {
        require(poolBalance >= amount, "Insufficient balance");

        // ❌ External call before state update!
        lendingToken.transfer(msg.sender, amount);

        // ❌ Can be re-entered during flash loan callback
        poolBalance -= amount;
    }
}

/**
 * @notice Vulnerable vault with flash loan reentrancy
 */
contract VulnerableVaultWithFlashLoan {
    IERC20 public asset;

    uint256 public totalSupply;
    uint256 public totalAssets;
    mapping(address => uint256) public balanceOf;

    constructor(address _asset) {
        asset = IERC20(_asset);
    }

    // ❌ VULNERABILITY 7: Flash loan + reentrancy combo (flash-loan-reentrancy-combo)
    function flashLoan(uint256 amount, bytes calldata data) external {
        uint256 balanceBefore = asset.balanceOf(address(this));

        // Transfer assets
        asset.transfer(msg.sender, amount);

        // ❌ Callback without reentrancy protection!
        (bool success,) = msg.sender.call(data);
        require(success, "Callback failed");

        // During callback, attacker can:
        // 1. Call deposit() with borrowed funds
        // 2. Mint shares
        // 3. Return funds for flashLoan check
        // 4. Shares remain minted but funds returned!

        uint256 balanceAfter = asset.balanceOf(address(this));
        uint256 fee = amount / 1000; // 0.1%
        require(balanceAfter >= balanceBefore + fee, "Flash loan not repaid");
    }

    // ❌ VULNERABILITY 8: Deposit callable during flash loan (flash-loan-reentrancy-combo)
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        // ❌ No reentrancy protection!

        if (totalSupply == 0) {
            shares = assets;
        } else {
            shares = (assets * totalSupply) / totalAssets;
        }

        // Reentrancy attack during flash loan:
        // 1. flashLoan(1000 tokens)
        // 2. In callback: deposit(1000 tokens)
        // 3. Mint shares based on inflated totalAssets
        // 4. Return 1000 tokens to flashLoan
        // 5. Attacker has shares but returned the funds!

        asset.transferFrom(msg.sender, address(this), assets);

        balanceOf[receiver] += shares;
        totalSupply += shares;
        totalAssets += assets;
    }

    function redeem(uint256 shares, address receiver) external returns (uint256 assets) {
        require(balanceOf[msg.sender] >= shares, "Insufficient shares");

        assets = (shares * totalAssets) / totalSupply;

        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        totalAssets -= assets;

        asset.transfer(receiver, assets);
    }
}

/**
 * @notice Attacker contract demonstrating flash loan + reentrancy
 */
contract FlashLoanReentrancyAttacker is IFlashLoanReceiver {
    VulnerableFlashLoanProvider public provider;
    VulnerableVaultWithFlashLoan public vault;

    // ❌ Example attack: Flash loan + reentrancy to drain vault
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        // During flash loan callback, attack the vault

        // 1. Deposit borrowed funds to vault
        IERC20(assets[0]).approve(address(vault), amounts[0]);
        vault.deposit(amounts[0], address(this));

        // 2. Vault mints shares to us
        // 3. We return funds below
        // 4. But shares remain!

        // Approve repayment
        uint256 amountOwed = amounts[0] + premiums[0];
        IERC20(assets[0]).approve(msg.sender, amountOwed);

        return true;
    }

    function attack() external {
        // Trigger the flash loan attack
        provider.flashLoan(address(this), 1000e18, "");

        // Now we have vault shares but returned the borrowed funds
        // We can redeem shares to steal from vault
    }
}

/**
 * @notice Secure staking with time locks
 */
contract SecureStakingPool {
    IERC20 public stakingToken;
    IERC20 public rewardToken;

    struct UserInfo {
        uint256 amount;
        uint256 rewardDebt;
        uint256 lockUntil; // ✅ Enforced lock period
    }

    mapping(address => UserInfo) public userInfo;
    uint256 public totalStaked;
    uint256 public constant MIN_LOCK_DURATION = 1 days;

    // ✅ Stake with mandatory lock period
    function stake(uint256 amount) external {
        UserInfo storage user = userInfo[msg.sender];

        stakingToken.transferFrom(msg.sender, address(this), amount);

        user.amount += amount;
        user.lockUntil = block.timestamp + MIN_LOCK_DURATION;
        totalStaked += amount;
    }

    // ✅ Withdraw with lock check
    function withdraw(uint256 amount) external {
        UserInfo storage user = userInfo[msg.sender];

        // ✅ Enforce minimum lock duration!
        require(block.timestamp >= user.lockUntil, "Still locked");
        require(user.amount >= amount, "Insufficient balance");

        user.amount -= amount;
        totalStaked -= amount;

        stakingToken.transfer(msg.sender, amount);
    }
}

/**
 * @notice Secure flash loan with reentrancy guard
 */
contract SecureFlashLoanProvider {
    IERC20 public lendingToken;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }

    // ✅ Flash loan with reentrancy protection
    function flashLoan(
        address receiver,
        uint256 amount,
        bytes calldata params
    ) external nonReentrant {
        uint256 balanceBefore = lendingToken.balanceOf(address(this));

        lendingToken.transfer(receiver, amount);

        // Callback is protected by nonReentrant modifier
        address[] memory assets = new address[](1);
        assets[0] = address(lendingToken);

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = amount;

        uint256[] memory premiums = new uint256[](1);
        premiums[0] = amount / 100;

        IFlashLoanReceiver(receiver).executeOperation(
            assets,
            amounts,
            premiums,
            msg.sender,
            params
        );

        uint256 balanceAfter = lendingToken.balanceOf(address(this));
        require(balanceAfter >= balanceBefore + premiums[0], "Not repaid");
    }
}
