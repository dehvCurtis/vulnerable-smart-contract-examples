// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableLending
 * @notice Test contract for lending protocol vulnerabilities
 *
 * DETECTORS TO TEST:
 * - lending-borrow-bypass (Critical)
 * - lending-liquidation-abuse (Critical)
 *
 * VULNERABILITIES:
 * 1. Missing health factor validation before borrow
 * 2. Collateral checks can be bypassed
 * 3. Flash loan integration without proper checks
 * 4. Reentrancy in borrow/repay flow
 * 5. Spot price used for health factor (liquidation manipulation)
 * 6. No liquidation cooldown (front-running attacks)
 * 7. Excessive liquidation bonus
 * 8. Borrowing without collateral check
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IPriceOracle {
    function getPrice(address token) external view returns (uint256);
}

contract VulnerableLendingProtocol {
    struct UserAccount {
        mapping(address => uint256) collateral;
        mapping(address => uint256) borrowed;
    }

    mapping(address => UserAccount) public accounts;
    mapping(address => uint256) public totalBorrowed;
    mapping(address => uint256) public totalCollateral;

    IPriceOracle public oracle;
    uint256 public constant COLLATERAL_FACTOR = 75; // 75%
    uint256 public constant LIQUIDATION_THRESHOLD = 80; // 80%
    uint256 public constant LIQUIDATION_BONUS = 25; // 25% bonus!

    constructor(address _oracle) {
        oracle = IPriceOracle(_oracle);
    }

    // ❌ VULNERABILITY 1: Missing health factor validation (lending-borrow-bypass)
    function borrow(address token, uint256 amount) external {
        // ❌ No health factor check!
        // User can borrow without sufficient collateral
        // Should have: require(getHealthFactor(msg.sender) >= 1e18, "Insufficient collateral");

        accounts[msg.sender].borrowed[token] += amount;
        totalBorrowed[token] += amount;

        IERC20(token).transfer(msg.sender, amount);
    }

    // ❌ VULNERABILITY 2: Collateral check can be bypassed (lending-borrow-bypass)
    function borrowUnsafe(address token, uint256 amount) external {
        UserAccount storage account = accounts[msg.sender];

        // ❌ Checks borrowed amount but doesn't validate against collateral value!
        require(account.borrowed[token] + amount > 0, "Invalid amount");

        // Missing: collateral value check
        // Missing: price feed validation
        // Missing: health factor calculation

        account.borrowed[token] += amount;
        totalBorrowed[token] += amount;

        IERC20(token).transfer(msg.sender, amount);
    }

    // ❌ VULNERABILITY 3: Flash loan integration without reentrancy protection (lending-borrow-bypass)
    function borrowFlashLoan(
        address token,
        uint256 amount,
        bytes calldata data
    ) external {
        uint256 balanceBefore = IERC20(token).balanceOf(address(this));

        // ❌ External call before state updates!
        IERC20(token).transfer(msg.sender, amount);

        // Execute flash loan callback
        // ❌ Reentrancy possible here!
        (bool success,) = msg.sender.call(data);
        require(success, "Flash loan callback failed");

        // ❌ State updated after external call
        uint256 balanceAfter = IERC20(token).balanceOf(address(this));
        require(balanceAfter >= balanceBefore, "Flash loan not repaid");
    }

    // ❌ VULNERABILITY 4: Spot price used for health factor (lending-liquidation-abuse)
    function getHealthFactor(address user) public view returns (uint256) {
        UserAccount storage account = accounts[user];

        uint256 totalCollateralValue = 0;
        uint256 totalBorrowedValue = 0;

        // ❌ Uses spot price from oracle!
        // Price can be manipulated in same block via flash loans
        // Should use TWAP (Time-Weighted Average Price)

        // This is simplified - real implementation would iterate all tokens
        // But the key vulnerability is using spot price

        if (totalCollateralValue == 0) return 0;
        return (totalCollateralValue * COLLATERAL_FACTOR) / totalBorrowedValue;
    }

    // ❌ VULNERABILITY 5: No liquidation cooldown (lending-liquidation-abuse)
    function liquidate(
        address user,
        address collateralToken,
        address debtToken,
        uint256 debtAmount
    ) external {
        // ❌ No cooldown period!
        // Liquidator can front-run price updates to liquidate at favorable price

        // ❌ Uses spot price for health factor check
        uint256 healthFactor = getHealthFactor(user);
        require(healthFactor < 1e18, "Position healthy");

        UserAccount storage account = accounts[user];

        // Calculate collateral to seize
        uint256 debtValue = debtAmount * oracle.getPrice(debtToken);

        // ❌ VULNERABILITY 6: Excessive liquidation bonus (lending-liquidation-abuse)
        // 25% bonus is very high, incentivizes aggressive liquidations
        uint256 collateralValue = (debtValue * (100 + LIQUIDATION_BONUS)) / 100;
        uint256 collateralAmount = collateralValue / oracle.getPrice(collateralToken);

        // Transfer debt from liquidator to protocol
        IERC20(debtToken).transferFrom(msg.sender, address(this), debtAmount);

        // Transfer collateral to liquidator (with bonus)
        account.collateral[collateralToken] -= collateralAmount;
        account.borrowed[debtToken] -= debtAmount;

        IERC20(collateralToken).transfer(msg.sender, collateralAmount);
    }

    // ❌ VULNERABILITY 7: Liquidation price manipulation (lending-liquidation-abuse)
    function liquidateWithManipulation(
        address user,
        address collateralToken,
        address debtToken,
        uint256 debtAmount
    ) external {
        // ❌ Checks health factor using manipulable spot price
        uint256 collateralValue = accounts[user].collateral[collateralToken] * oracle.getPrice(collateralToken);
        uint256 borrowedValue = accounts[user].borrowed[debtToken] * oracle.getPrice(debtToken);

        // ❌ Attacker can:
        // 1. Manipulate oracle price via flash loan
        // 2. Trigger liquidation at manipulated price
        // 3. Profit from liquidation bonus
        // 4. Restore price in same transaction

        require(collateralValue < borrowedValue, "Not liquidatable");

        // Liquidation logic...
    }

    // ❌ VULNERABILITY 8: Reentrancy in repay (lending-borrow-bypass)
    function repay(address token, uint256 amount) external {
        UserAccount storage account = accounts[msg.sender];

        // ❌ External call before state update!
        IERC20(token).transferFrom(msg.sender, address(this), amount);

        // ❌ State updated after external call - vulnerable to reentrancy
        account.borrowed[token] -= amount;
        totalBorrowed[token] -= amount;
    }

    function depositCollateral(address token, uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, address(this), amount);

        accounts[msg.sender].collateral[token] += amount;
        totalCollateral[token] += amount;
    }

    function withdrawCollateral(address token, uint256 amount) external {
        UserAccount storage account = accounts[msg.sender];

        // ❌ No health factor check after withdrawal!
        // User can withdraw collateral even if it makes them underwater
        // Should check: require(getHealthFactorAfter(msg.sender) >= 1e18);

        account.collateral[token] -= amount;
        totalCollateral[token] -= amount;

        IERC20(token).transfer(msg.sender, amount);
    }
}

/**
 * @notice Secure lending protocol implementation
 */
contract SecureLendingProtocol {
    struct UserAccount {
        mapping(address => uint256) collateral;
        mapping(address => uint256) borrowed;
        uint256 lastLiquidationTime;
    }

    mapping(address => UserAccount) public accounts;
    mapping(address => uint256) public totalBorrowed;
    mapping(address => uint256) public totalCollateral;

    IPriceOracle public oracle;

    uint256 public constant COLLATERAL_FACTOR = 75; // 75%
    uint256 public constant LIQUIDATION_THRESHOLD = 80; // 80%
    uint256 public constant LIQUIDATION_BONUS = 5; // 5% reasonable bonus
    uint256 public constant LIQUIDATION_COOLDOWN = 1 hours;
    uint256 public constant MIN_HEALTH_FACTOR = 1.1e18; // 110%

    bool private locked;

    modifier nonReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }

    constructor(address _oracle) {
        oracle = IPriceOracle(_oracle);
    }

    // ✅ Secure borrow with health factor validation
    function borrow(address token, uint256 amount) external nonReentrant {
        UserAccount storage account = accounts[msg.sender];

        // ✅ Validate health factor BEFORE borrowing
        uint256 healthFactorBefore = getHealthFactor(msg.sender);
        require(healthFactorBefore >= MIN_HEALTH_FACTOR, "Insufficient collateral");

        // Update state first
        account.borrowed[token] += amount;
        totalBorrowed[token] += amount;

        // ✅ Validate health factor AFTER borrowing
        uint256 healthFactorAfter = getHealthFactor(msg.sender);
        require(healthFactorAfter >= MIN_HEALTH_FACTOR, "Borrow would make position unhealthy");

        // External call last
        IERC20(token).transfer(msg.sender, amount);
    }

    // ✅ Secure liquidation with cooldown and TWAP
    function liquidate(
        address user,
        address collateralToken,
        address debtToken,
        uint256 debtAmount
    ) external nonReentrant {
        UserAccount storage account = accounts[user];

        // ✅ Enforce liquidation cooldown
        require(
            block.timestamp >= account.lastLiquidationTime + LIQUIDATION_COOLDOWN,
            "Liquidation cooldown active"
        );

        // ✅ Use TWAP for price (implementation would call oracle.getTWAP())
        uint256 healthFactor = getHealthFactor(user);
        require(healthFactor < 1e18, "Position healthy");

        // ✅ Reasonable liquidation bonus (5% instead of 25%)
        uint256 debtValue = debtAmount * oracle.getPrice(debtToken);
        uint256 collateralValue = (debtValue * (100 + LIQUIDATION_BONUS)) / 100;
        uint256 collateralAmount = collateralValue / oracle.getPrice(collateralToken);

        // Update state
        account.collateral[collateralToken] -= collateralAmount;
        account.borrowed[debtToken] -= debtAmount;
        account.lastLiquidationTime = block.timestamp;

        // External calls last
        IERC20(debtToken).transferFrom(msg.sender, address(this), debtAmount);
        IERC20(collateralToken).transfer(msg.sender, collateralAmount);
    }

    // ✅ Secure repay with state updates before external calls
    function repay(address token, uint256 amount) external nonReentrant {
        UserAccount storage account = accounts[msg.sender];

        require(account.borrowed[token] >= amount, "Repay amount exceeds debt");

        // ✅ Update state before external call
        account.borrowed[token] -= amount;
        totalBorrowed[token] -= amount;

        // External call after state update
        IERC20(token).transferFrom(msg.sender, address(this), amount);
    }

    // ✅ Secure collateral withdrawal with health factor validation
    function withdrawCollateral(address token, uint256 amount) external nonReentrant {
        UserAccount storage account = accounts[msg.sender];

        require(account.collateral[token] >= amount, "Insufficient collateral");

        // Update state
        account.collateral[token] -= amount;
        totalCollateral[token] -= amount;

        // ✅ Validate health factor after withdrawal
        uint256 healthFactor = getHealthFactor(msg.sender);
        require(healthFactor >= MIN_HEALTH_FACTOR, "Withdrawal would make position unhealthy");

        // External call last
        IERC20(token).transfer(msg.sender, amount);
    }

    function getHealthFactor(address user) public view returns (uint256) {
        UserAccount storage account = accounts[user];

        // Implementation would iterate all tokens and use TWAP prices
        // For simplicity, returning a placeholder
        return 1.5e18; // 150%
    }

    function depositCollateral(address token, uint256 amount) external nonReentrant {
        IERC20(token).transferFrom(msg.sender, address(this), amount);

        accounts[msg.sender].collateral[token] += amount;
        totalCollateral[token] += amount;
    }
}
