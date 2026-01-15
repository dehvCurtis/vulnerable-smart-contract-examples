// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableRestakingRewards
 * @notice Test contract for restaking reward and withdrawal vulnerabilities
 *
 * DETECTORS TO TEST:
 * - restaking-reward-manipulation (Critical)
 * - restaking-withdrawal-bypass (Critical)
 * - restaking-share-inflation (Critical)
 * - restaking-operator-validation (High)
 * - restaking-stake-manipulation (Critical)
 *
 * VULNERABILITIES:
 * 1. Reward calculation manipulation
 * 2. Share inflation attacks
 * 3. Withdrawal delay bypass
 * 4. Withdrawal queue poisoning
 * 5. Reward theft from delegators
 * 6. Early withdrawal without penalty
 * 7. Unclaimed rewards manipulation
 */

/**
 * @notice Vulnerable restaking vault with reward issues
 */
contract VulnerableRestakingVault {
    struct UserStake {
        uint256 amount;
        uint256 shares;
        uint256 lastRewardClaim;
        uint256 rewardDebt;
    }

    mapping(address => UserStake) public stakes;

    uint256 public totalShares;
    uint256 public totalStaked;
    uint256 public rewardPerShare;
    uint256 public accumulatedRewards;

    // ❌ VULNERABILITY 1: Share inflation attack (restaking-share-inflation)
    function stake() external payable {
        uint256 sharesToMint;

        if (totalShares == 0) {
            // ❌ First depositor can manipulate share ratio!
            // Attack:
            // 1. Attacker deposits 1 wei, gets 1 share (totalShares = 1, totalStaked = 1)
            // 2. Attacker directly transfers 1 million ETH to contract
            //    (totalShares = 1, totalStaked = 1 million ETH)
            // 3. Next user deposits 1 ETH:
            //    shares = (1 ETH * 1 share) / 1 million ETH = 0 (rounds down!)
            // 4. User gets 0 shares, loses 1 ETH to attacker!

            sharesToMint = msg.value;
        } else {
            // ❌ Rounds down, can be exploited!
            sharesToMint = (msg.value * totalShares) / totalStaked;
        }

        stakes[msg.sender].amount += msg.value;
        stakes[msg.sender].shares += sharesToMint;

        totalShares += sharesToMint;
        totalStaked += msg.value;
    }

    // ❌ VULNERABILITY 2: Reward manipulation (restaking-reward-manipulation)
    function distributeRewards() external payable {
        // ❌ Anyone can call this function!
        // ❌ No validation of reward source!
        // ❌ Attacker can manipulate reward distribution timing!

        if (totalShares > 0) {
            // ❌ Reward per share calculated without proper scaling!
            rewardPerShare += msg.value / totalShares;
            accumulatedRewards += msg.value;
        }

        // Attack scenario:
        // 1. Attacker stakes 1 wei to get minimal shares
        // 2. Waits for other users to stake large amounts
        // 3. Right before reward distribution, attacker stakes huge amount
        // 4. Attacker claims disproportionate rewards
        // 5. Attacker withdraws immediately
    }

    // ❌ VULNERABILITY 3: Reward theft (restaking-reward-manipulation)
    function claimRewards() external {
        UserStake storage user = stakes[msg.sender];

        // ❌ Reward calculation doesn't account for deposit time!
        // ❌ No minimum staking period!
        // ❌ Flash loan attack possible!

        uint256 pendingReward = (user.shares * rewardPerShare) - user.rewardDebt;

        // Flash loan attack:
        // 1. Flash loan 1000 ETH
        // 2. Stake 1000 ETH, get shares
        // 3. Immediately claim rewards (based on total shares)
        // 4. Unstake and return flash loan
        // 5. Keep rewards without actually staking!

        user.rewardDebt = user.shares * rewardPerShare;
        payable(msg.sender).transfer(pendingReward);
    }

    // ❌ VULNERABILITY 4: Unclaimed rewards manipulation (restaking-reward-manipulation)
    function compound() external {
        UserStake storage user = stakes[msg.sender];

        uint256 pendingReward = (user.shares * rewardPerShare) - user.rewardDebt;

        // ❌ Compounding doesn't update shares correctly!
        // ❌ Can create accounting inconsistencies!

        user.amount += pendingReward;
        totalStaked += pendingReward;

        // ❌ Should mint new shares but doesn't!
        // This breaks the share/stake ratio for other users!
    }

    function unstake(uint256 shares) external {
        UserStake storage user = stakes[msg.sender];
        require(user.shares >= shares, "Insufficient shares");

        uint256 amountToWithdraw = (shares * totalStaked) / totalShares;

        user.shares -= shares;
        user.amount -= amountToWithdraw;
        totalShares -= shares;
        totalStaked -= amountToWithdraw;

        payable(msg.sender).transfer(amountToWithdraw);
    }
}

/**
 * @notice Vulnerable withdrawal queue system
 */
contract VulnerableWithdrawalQueue {
    struct WithdrawalRequest {
        address user;
        uint256 amount;
        uint256 requestTime;
        bool completed;
    }

    WithdrawalRequest[] public withdrawalQueue;
    mapping(address => uint256[]) public userWithdrawals;

    uint256 public constant WITHDRAWAL_DELAY = 7 days;
    uint256 public totalQueued;

    mapping(address => uint256) public stakedBalances;

    // ❌ VULNERABILITY 5: Withdrawal delay bypass (restaking-withdrawal-bypass)
    function requestWithdrawal(uint256 amount) external {
        require(stakedBalances[msg.sender] >= amount, "Insufficient balance");

        // ❌ No validation that user doesn't have pending withdrawal!
        // ❌ User can create multiple withdrawal requests!
        // Attack:
        // 1. User requests withdrawal for 100 ETH
        // 2. Before delay expires, user requests another 100 ETH withdrawal
        // 3. User can withdraw 200 ETH even though balance is only 100 ETH!

        WithdrawalRequest memory request = WithdrawalRequest({
            user: msg.sender,
            amount: amount,
            requestTime: block.timestamp,
            completed: false
        });

        withdrawalQueue.push(request);
        userWithdrawals[msg.sender].push(withdrawalQueue.length - 1);

        totalQueued += amount;
        stakedBalances[msg.sender] -= amount; // ❌ Reduces balance immediately!
    }

    // ❌ VULNERABILITY 6: Early withdrawal (restaking-withdrawal-bypass)
    function completeWithdrawal(uint256 requestIndex) external {
        WithdrawalRequest storage request = withdrawalQueue[requestIndex];

        require(request.user == msg.sender, "Not your withdrawal");
        require(!request.completed, "Already completed");

        // ❌ No time delay check!
        // ❌ Should require: block.timestamp >= request.requestTime + WITHDRAWAL_DELAY
        // User can complete withdrawal immediately without waiting!

        request.completed = true;
        totalQueued -= request.amount;

        payable(msg.sender).transfer(request.amount);
    }

    // ❌ VULNERABILITY 7: Queue poisoning (restaking-withdrawal-bypass)
    function cancelWithdrawal(uint256 requestIndex) external {
        WithdrawalRequest storage request = withdrawalQueue[requestIndex];

        // ❌ No validation that msg.sender is the requester!
        // ❌ Anyone can cancel anyone's withdrawal!

        // Attack:
        // 1. Attacker monitors mempool for withdrawal requests
        // 2. Front-runs and cancels victim's withdrawal
        // 3. Victim's funds stuck
        // 4. Repeat to DOS all withdrawals

        require(!request.completed, "Already completed");

        request.completed = true; // Mark as completed to prevent withdrawal
        totalQueued -= request.amount;

        // ❌ Funds returned to victim's stake, but victim wanted to withdraw!
        stakedBalances[request.user] += request.amount;
    }

    function stake() external payable {
        stakedBalances[msg.sender] += msg.value;
    }
}

/**
 * @notice Vulnerable operator commission system
 */
contract VulnerableOperatorCommission {
    struct Operator {
        address operatorAddress;
        uint256 commission; // Percentage (0-100)
        uint256 totalDelegated;
        uint256 earnedCommission;
    }

    struct Delegation {
        address delegator;
        address operator;
        uint256 amount;
        uint256 rewards;
    }

    mapping(address => Operator) public operators;
    mapping(address => Delegation) public delegations;

    // ❌ VULNERABILITY 8: Commission manipulation (restaking-reward-manipulation)
    function setCommission(uint256 newCommission) external {
        Operator storage op = operators[msg.sender];

        // ❌ No maximum commission limit!
        // ❌ Can set to 100% (steals all delegator rewards)!
        // ❌ No timelock on commission changes!
        // ❌ No notification to delegators!

        // Attack:
        // 1. Operator sets commission to 1% to attract delegators
        // 2. Users delegate large amounts
        // 3. Right before reward distribution, operator sets commission to 100%
        // 4. Operator steals all rewards
        // 5. Delegators get nothing

        op.commission = newCommission;
    }

    // ❌ VULNERABILITY 9: Reward theft via commission (restaking-reward-manipulation)
    function distributeRewards(address operator) external payable {
        Operator storage op = operators[operator];

        // ❌ Commission calculated on total rewards, not operator's own stake!
        // ❌ Operator earns commission even with 0 stake!

        uint256 commission = (msg.value * op.commission) / 100;
        uint256 delegatorRewards = msg.value - commission;

        op.earnedCommission += commission;

        // ❌ Delegator rewards distributed without proper accounting!
        // Multiple delegators share rewards but no per-delegator tracking!
    }

    // ❌ VULNERABILITY 10: Operator can steal specific delegator rewards
    function withdrawOperatorCommission(address delegator) external {
        Operator storage op = operators[msg.sender];
        Delegation storage delegation = delegations[delegator];

        require(delegation.operator == msg.sender, "Not your delegator");

        // ❌ Operator can withdraw based on ANY delegator's stake!
        // ❌ Can repeatedly withdraw from different delegators!

        uint256 amount = delegation.rewards; // ❌ Doesn't check if already withdrawn!

        payable(msg.sender).transfer(amount);

        // ❌ Doesn't update delegation.rewards, can withdraw multiple times!
    }

    function registerOperator(uint256 commission) external {
        operators[msg.sender] = Operator({
            operatorAddress: msg.sender,
            commission: commission,
            totalDelegated: 0,
            earnedCommission: 0
        });
    }

    function delegate(address operator) external payable {
        require(operators[operator].operatorAddress != address(0), "Operator not registered");

        delegations[msg.sender] = Delegation({
            delegator: msg.sender,
            operator: operator,
            amount: msg.value,
            rewards: 0
        });

        operators[operator].totalDelegated += msg.value;
    }
}

/**
 * @notice Vulnerable restaking strategy manager
 */
contract VulnerableStrategyManager {
    struct Strategy {
        address strategyAddress;
        uint256 totalDeposits;
        uint256 totalShares;
        bool active;
    }

    mapping(bytes32 => Strategy) public strategies;
    mapping(address => mapping(bytes32 => uint256)) public userStrategyShares;

    // ❌ VULNERABILITY 11: Strategy manipulation (restaking-stake-manipulation)
    function addStrategy(bytes32 strategyId, address strategyAddress) external {
        // ❌ Anyone can add strategies!
        // ❌ No validation of strategy contract!
        // ❌ Malicious strategy can steal funds!

        strategies[strategyId] = Strategy({
            strategyAddress: strategyAddress,
            totalDeposits: 0,
            totalShares: 0,
            active: true
        });

        // Attack:
        // 1. Attacker deploys malicious strategy contract
        // 2. Attacker calls addStrategy with malicious contract
        // 3. Users deposit into strategy
        // 4. Malicious contract steals all deposits
    }

    // ❌ VULNERABILITY 12: Deposit without validation (restaking-stake-manipulation)
    function depositIntoStrategy(bytes32 strategyId, uint256 amount) external payable {
        Strategy storage strategy = strategies[strategyId];

        // ❌ No validation that strategy is safe!
        // ❌ No limit on deposits per user!
        // ❌ No validation that msg.value matches amount!

        uint256 shares = strategy.totalShares == 0
            ? amount
            : (amount * strategy.totalShares) / strategy.totalDeposits;

        userStrategyShares[msg.sender][strategyId] += shares;
        strategy.totalShares += shares;
        strategy.totalDeposits += amount;

        // ❌ Sends funds to unvalidated strategy contract!
        (bool success,) = strategy.strategyAddress.call{value: msg.value}("");
        require(success);
    }

    // ❌ VULNERABILITY 13: Operator can change strategy (restaking-stake-manipulation)
    function migrateStrategy(
        bytes32 oldStrategyId,
        bytes32 newStrategyId,
        address user
    ) external {
        // ❌ Anyone can migrate anyone's funds!
        // ❌ No user consent required!

        uint256 oldShares = userStrategyShares[user][oldStrategyId];

        Strategy storage oldStrategy = strategies[oldStrategyId];
        Strategy storage newStrategy = strategies[newStrategyId];

        uint256 amount = (oldShares * oldStrategy.totalDeposits) / oldStrategy.totalShares;

        // ❌ Force migration without user approval!
        userStrategyShares[user][oldStrategyId] = 0;
        oldStrategy.totalShares -= oldShares;
        oldStrategy.totalDeposits -= amount;

        uint256 newShares = newStrategy.totalShares == 0
            ? amount
            : (amount * newStrategy.totalShares) / newStrategy.totalDeposits;

        userStrategyShares[user][newStrategyId] = newShares;
        newStrategy.totalShares += newShares;
        newStrategy.totalDeposits += amount;

        // Attacker can migrate all users to malicious strategy!
    }
}

/**
 * @notice Secure restaking vault with proper protections
 */
contract SecureRestakingVault {
    struct UserStake {
        uint256 amount;
        uint256 shares;
        uint256 depositTime;
        uint256 rewardDebt;
    }

    mapping(address => UserStake) public stakes;

    uint256 public totalShares;
    uint256 public totalStaked;
    uint256 public rewardPerShare;

    uint256 public constant MINIMUM_STAKE = 1e18; // 1 ETH minimum
    uint256 public constant MINIMUM_SHARES = 1e3; // Prevent share inflation
    uint256 public constant MIN_STAKE_PERIOD = 1 days;

    // ✅ Prevent share inflation attack
    function stake() external payable {
        require(msg.value >= MINIMUM_STAKE, "Below minimum");

        uint256 sharesToMint;

        if (totalShares == 0) {
            // ✅ Mint shares with high precision
            sharesToMint = msg.value * MINIMUM_SHARES;
            require(sharesToMint >= MINIMUM_SHARES, "Insufficient initial deposit");
        } else {
            sharesToMint = (msg.value * totalShares) / totalStaked;
            require(sharesToMint > 0, "Shares round to zero");
        }

        stakes[msg.sender].amount += msg.value;
        stakes[msg.sender].shares += sharesToMint;
        stakes[msg.sender].depositTime = block.timestamp;

        totalShares += sharesToMint;
        totalStaked += msg.value;
    }

    // ✅ Secure reward claiming with time lock
    function claimRewards() external {
        UserStake storage user = stakes[msg.sender];

        // ✅ Require minimum staking period
        require(
            block.timestamp >= user.depositTime + MIN_STAKE_PERIOD,
            "Minimum stake period not met"
        );

        uint256 pendingReward = (user.shares * rewardPerShare) / 1e18 - user.rewardDebt;

        user.rewardDebt = (user.shares * rewardPerShare) / 1e18;

        payable(msg.sender).transfer(pendingReward);
    }

    function distributeRewards() external payable {
        require(totalShares > 0, "No stakes");

        // ✅ Scale with 1e18 precision
        rewardPerShare += (msg.value * 1e18) / totalShares;
    }
}
