// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableClassicReentrancy
 * @notice Test contract for classic reentrancy attack vulnerabilities
 *
 * DETECTORS TO TEST:
 * - classic-reentrancy (High)
 * - readonly-reentrancy (Medium)
 *
 * VULNERABILITIES:
 * 1. External call before state update (classic reentrancy)
 * 2. Transfer before balance update
 * 3. Call without reentrancy guard
 * 4. Delegatecall reentrancy
 * 5. Cross-function reentrancy
 * 6. Read-only reentrancy via view functions
 * 7. Reentrancy in withdrawal pattern
 * 8. Multiple withdrawal reentrancy
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/**
 * @notice Classic reentrancy vulnerability (DAO hack pattern)
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // ❌ VULNERABILITY 1: Classic reentrancy (classic-reentrancy)
    // External call before state update - The DAO hack pattern
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // ❌ External call BEFORE state update!
        // Attacker can re-enter withdraw() during this call
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // ❌ State updated AFTER external call
        // During reentrancy, balance is still high
        balances[msg.sender] -= amount;

        emit Withdrawal(msg.sender, amount);
    }

    // ❌ VULNERABILITY 2: Transfer ETH without reentrancy guard
    function withdrawAll() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");

        // ❌ Balance check but state updated after
        payable(msg.sender).transfer(balance);

        // ❌ Too late - attacker already re-entered
        balances[msg.sender] = 0;
    }

    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
}

/**
 * @notice Cross-function reentrancy
 */
contract VulnerableCrossFunctionReentrancy {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    // ❌ VULNERABILITY 3: Cross-function reentrancy (classic-reentrancy)
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // ❌ External call before updating ANY state
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);

        // Attacker can re-enter deposit() or transfer() during callback
        balances[msg.sender] -= amount;
    }

    // ❌ Can be called during withdraw() reentrancy
    function transfer(address to, uint256 amount) external {
        // ❌ No reentrancy protection!
        // During withdraw() callback, attacker can transfer their balance
        // Then complete withdraw() - double spend!

        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
    }
}

/**
 * @notice Read-only reentrancy vulnerability
 */
contract VulnerablePriceOracle {
    mapping(address => uint256) public balances;
    uint256 public totalBalance;

    // ❌ VULNERABILITY 4: Read-only reentrancy (readonly-reentrancy)
    // View function returns stale state during reentrancy
    function getPrice() external view returns (uint256) {
        // ❌ During reentrancy, totalBalance is NOT updated yet
        // Other contracts reading this will get STALE state!

        if (totalBalance == 0) return 0;

        // Price calculation using potentially stale totalBalance
        return (address(this).balance * 1e18) / totalBalance;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);

        // ❌ External call before updating totalBalance
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);

        // During callback:
        // - balances[attacker] still shows high value
        // - totalBalance NOT decremented yet
        // - getPrice() returns WRONG price
        // - Other contracts using getPrice() get bad data!

        balances[msg.sender] -= amount;
        totalBalance -= amount; // ❌ Updated too late
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalBalance += msg.value;
    }
}

/**
 * @notice Delegatecall reentrancy
 */
contract VulnerableDelegatecall {
    address public implementation;
    mapping(address => uint256) public balances;

    // ❌ VULNERABILITY 5: Delegatecall reentrancy (classic-reentrancy)
    function execute(address target, bytes calldata data) external {
        require(balances[msg.sender] > 0, "No balance");

        // ❌ Delegatecall to user-controlled target!
        // Attacker can execute arbitrary code in this contract's context
        (bool success,) = target.delegatecall(data);
        require(success, "Delegatecall failed");

        // Attacker can:
        // 1. Delegatecall to malicious contract
        // 2. Malicious code modifies storage directly
        // 3. Re-enter other functions
        // 4. Drain contract
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);

        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}

/**
 * @notice Reentrancy in token interactions
 */
contract VulnerableTokenVault {
    IERC20 public token;
    mapping(address => uint256) public deposits;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // ❌ VULNERABILITY 6: External token call before state update (classic-reentrancy)
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient deposit");

        // ❌ External call to token (might be malicious ERC-777!)
        token.transfer(msg.sender, amount);

        // ❌ State updated after external call
        // ERC-777 tokens can call back via tokensReceived hook
        deposits[msg.sender] -= amount;
    }

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;
    }
}

/**
 * @notice Multiple reentrancy attack vectors
 */
contract VulnerableMultiFunction {
    mapping(address => uint256) public balances;
    mapping(address => bool) public hasReward;

    // ❌ VULNERABILITY 7: Multiple reentrancy vectors (classic-reentrancy)
    function withdrawAndClaimReward() external {
        uint256 balance = balances[msg.sender];
        bool reward = hasReward[msg.sender];

        // ❌ Multiple external calls before state updates!

        if (balance > 0) {
            (bool success,) = msg.sender.call{value: balance}("");
            require(success);
        }

        if (reward) {
            // Second external call!
            (bool success,) = msg.sender.call{value: 1 ether}("");
            require(success);
        }

        // ❌ State updates after ALL external calls
        // Attacker can re-enter between or during any call
        balances[msg.sender] = 0;
        hasReward[msg.sender] = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function setReward(address user) external {
        hasReward[user] = true;
    }
}

/**
 * @notice Batch operations reentrancy
 */
contract VulnerableBatchWithdraw {
    mapping(address => uint256) public balances;

    // ❌ VULNERABILITY 8: Batch operation with reentrancy (classic-reentrancy)
    function batchWithdraw(address[] calldata users, uint256[] calldata amounts) external {
        require(users.length == amounts.length, "Length mismatch");

        // ❌ External calls in loop before state updates!
        for (uint256 i = 0; i < users.length; i++) {
            require(balances[users[i]] >= amounts[i], "Insufficient balance");

            // ❌ Transfer before updating state
            (bool success,) = users[i].call{value: amounts[i]}("");
            require(success);

            // ❌ State update after external call
            // User can re-enter and manipulate other indices
            balances[users[i]] -= amounts[i];
        }
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}

/**
 * @notice Secure implementation with Checks-Effects-Interactions pattern
 */
contract SecureBank {
    mapping(address => uint256) public balances;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // ✅ Checks-Effects-Interactions pattern
    function withdraw(uint256 amount) external nonReentrant {
        // ✅ CHECKS: Validate conditions
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // ✅ EFFECTS: Update state BEFORE external calls
        balances[msg.sender] -= amount;

        // ✅ INTERACTIONS: External calls LAST
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // ✅ Pull payment pattern (even safer)
    mapping(address => uint256) public withdrawable;

    function initiateWithdrawal(uint256 amount) external {
        require(balances[msg.sender] >= amount);

        balances[msg.sender] -= amount;
        withdrawable[msg.sender] += amount;
    }

    function completeWithdrawal() external nonReentrant {
        uint256 amount = withdrawable[msg.sender];
        require(amount > 0);

        withdrawable[msg.sender] = 0;

        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
    }
}
