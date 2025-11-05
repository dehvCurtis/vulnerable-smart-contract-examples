// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableVault
 * @notice Test contract for ERC-4626 Vault vulnerabilities
 *
 * DETECTORS TO TEST:
 * - vault-donation-attack (High)
 * - vault-fee-manipulation (Medium)
 * - vault-share-inflation (Critical)
 * - vault-withdrawal-dos (High)
 * - pool-donation-enhanced (High)
 *
 * VULNERABILITIES:
 * 1. Share price manipulation via donation (inflation attack)
 * 2. First depositor can manipulate share price
 * 3. Using balanceOf() instead of internal accounting
 * 4. No minimum deposit/shares requirement
 * 5. Fee parameters can be front-run
 * 6. Withdrawal DOS via queue manipulation
 * 7. No virtual shares/assets for rounding protection
 * 8. Rounding down to zero shares
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function decimals() external view returns (uint8);
}

contract VulnerableVault {
    IERC20 public asset;
    string public name;
    string public symbol;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    uint256 public depositFee = 100; // 1% in basis points
    uint256 public withdrawalFee = 100; // 1%
    address public feeRecipient;

    event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed caller, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);

    constructor(address _asset, string memory _name, string memory _symbol) {
        asset = IERC20(_asset);
        name = _name;
        symbol = _symbol;
        feeRecipient = msg.sender;
    }

    // ❌ VULNERABILITY 1: Share inflation attack (vault-share-inflation)
    // First depositor can manipulate share price by depositing 1 wei then donating assets
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        // ❌ No minimum deposit requirement!
        // Attacker can: deposit(1), donate(1e18), making 1 share = 1e18 assets
        // Then victim's deposit rounds down to 0 shares
        // require(assets >= MIN_DEPOSIT, "Below minimum");

        // ❌ Uses balanceOf() which can be manipulated via donation
        // Should use internal accounting
        uint256 supply = totalSupply;

        if (supply == 0) {
            // ❌ No dead shares minted!
            // Should mint initial dead shares to prevent manipulation:
            // shares = assets - DEAD_SHARES;
            // balanceOf[address(0)] = DEAD_SHARES;
            shares = assets;
        } else {
            // ❌ Uses balanceOf() instead of internal balance tracking
            uint256 totalAssets = asset.balanceOf(address(this));
            shares = (assets * supply) / totalAssets;
        }

        // ❌ No minimum shares check!
        // Small deposits can round down to 0 shares
        // require(shares > 0, "Zero shares");

        require(asset.transferFrom(msg.sender, address(this), assets), "Transfer failed");

        balanceOf[receiver] += shares;
        totalSupply += shares;

        emit Deposit(msg.sender, receiver, assets, shares);
    }

    // ❌ VULNERABILITY 2: Donation attack (vault-donation-attack, pool-donation-enhanced)
    // Share price can be inflated by direct token donation
    function convertToShares(uint256 assets) public view returns (uint256 shares) {
        uint256 supply = totalSupply;

        if (supply == 0) {
            return assets;
        }

        // ❌ Uses balanceOf() which includes donations!
        // Direct token transfers inflate totalAssets, reducing shares minted
        uint256 totalAssets = asset.balanceOf(address(this));
        return (assets * supply) / totalAssets;
    }

    // ❌ VULNERABILITY 3: Rounding down to zero shares (pool-donation-enhanced)
    function depositSmall(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = convertToShares(assets);

        // ❌ No check for zero shares!
        // If assets is small and share price is high, this rounds to 0
        // User loses their assets!

        require(asset.transferFrom(msg.sender, address(this), assets), "Transfer failed");

        // ❌ This does nothing if shares = 0!
        balanceOf[receiver] += shares;
        totalSupply += shares;

        emit Deposit(msg.sender, receiver, assets, shares);
    }

    // ❌ VULNERABILITY 4: Fee manipulation (vault-fee-manipulation)
    // Fee parameters can be changed and front-run user transactions
    function setDepositFee(uint256 newFee) external {
        // ❌ No access control!
        // ❌ No timelock or delay!
        // Admin can front-run deposits with high fee, then lower it after
        // require(msg.sender == owner);
        // require(newFee <= MAX_FEE);
        depositFee = newFee;
    }

    function setWithdrawalFee(uint256 newFee) external {
        // ❌ Same issues as setDepositFee
        withdrawalFee = newFee;
    }

    // ❌ VULNERABILITY 5: Fees applied without limits (vault-fee-manipulation)
    function depositWithFees(uint256 assets, address receiver) external returns (uint256 shares) {
        // ❌ Fee can be set to 100% (10000 basis points) right before this tx!
        uint256 fee = (assets * depositFee) / 10000;
        uint256 assetsAfterFee = assets - fee;

        shares = convertToShares(assetsAfterFee);

        require(asset.transferFrom(msg.sender, address(this), assets), "Transfer failed");

        if (fee > 0) {
            asset.transfer(feeRecipient, fee);
        }

        balanceOf[receiver] += shares;
        totalSupply += shares;

        emit Deposit(msg.sender, receiver, assetsAfterFee, shares);
    }

    // ❌ VULNERABILITY 6: Withdrawal DOS (vault-withdrawal-dos)
    // Withdrawal can be blocked if assets locked in strategy
    function withdraw(
        uint256 assets,
        address receiver,
        address owner
    ) external returns (uint256 shares) {
        if (msg.sender != owner) {
            // Allowance check would go here
        }

        shares = convertToAssets(assets);

        balanceOf[owner] -= shares;
        totalSupply -= shares;

        // ❌ No check if vault has enough liquid assets!
        // If assets are in a strategy or locked, this reverts and DOS withdrawals
        // Should have: require(asset.balanceOf(address(this)) >= assets, "Insufficient liquidity");

        require(asset.transfer(receiver, assets), "Transfer failed");

        emit Withdraw(msg.sender, receiver, owner, assets, shares);
    }

    function convertToAssets(uint256 shares) public view returns (uint256 assets) {
        uint256 supply = totalSupply;

        if (supply == 0) {
            return shares;
        }

        uint256 totalAssets = asset.balanceOf(address(this));
        return (shares * totalAssets) / supply;
    }
}

/**
 * @notice Vault with withdrawal queue DOS vulnerability
 */
contract VulnerableWithdrawalQueueVault {
    IERC20 public asset;

    struct WithdrawalRequest {
        address user;
        uint256 shares;
        uint256 timestamp;
    }

    WithdrawalRequest[] public withdrawalQueue;
    uint256 public queueIndex;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    // ❌ VULNERABILITY 7: Unbounded withdrawal queue (vault-withdrawal-dos)
    function requestWithdrawal(uint256 shares) external {
        require(balanceOf[msg.sender] >= shares, "Insufficient balance");

        // ❌ Queue can grow unbounded!
        // Attacker can spam small withdrawal requests to fill queue
        // Making it expensive or impossible to process withdrawals
        withdrawalQueue.push(WithdrawalRequest({
            user: msg.sender,
            shares: shares,
            timestamp: block.timestamp
        }));

        // Lock shares
        balanceOf[msg.sender] -= shares;
    }

    // ❌ VULNERABILITY 8: DOS via queue manipulation (vault-withdrawal-dos)
    function processWithdrawals(uint256 count) external {
        // ❌ Processing many small withdrawals can consume all gas
        // No protection against griefing attacks
        for (uint256 i = 0; i < count; i++) {
            if (queueIndex >= withdrawalQueue.length) break;

            WithdrawalRequest memory request = withdrawalQueue[queueIndex];

            // Process withdrawal...
            uint256 assets = convertToAssets(request.shares);
            asset.transfer(request.user, assets);

            queueIndex++;
        }
    }

    function convertToAssets(uint256 shares) internal view returns (uint256) {
        if (totalSupply == 0) return shares;
        return (shares * asset.balanceOf(address(this))) / totalSupply;
    }
}

/**
 * @notice Secure ERC-4626 Vault implementation
 */
contract SecureVault {
    IERC20 public asset;
    string public name;
    string public symbol;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    // ✅ Internal balance tracking instead of balanceOf()
    uint256 private totalAssets;

    // ✅ Configuration with limits
    uint256 public constant MIN_DEPOSIT = 1000;
    uint256 public constant DEAD_SHARES = 1000;
    uint256 public constant MAX_FEE = 500; // 5% maximum
    uint256 public depositFee = 100;

    // ✅ Virtual shares for rounding protection
    uint256 private constant VIRTUAL_SHARES = 1e8;
    uint256 private constant VIRTUAL_ASSETS = 1;

    address public owner;
    address public feeRecipient;

    event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);

    constructor(address _asset) {
        asset = IERC20(_asset);
        owner = msg.sender;
        feeRecipient = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // ✅ Secure deposit with all protections
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        // ✅ Minimum deposit requirement
        require(assets >= MIN_DEPOSIT, "Below minimum deposit");

        uint256 supply = totalSupply;

        if (supply == 0) {
            // ✅ Mint dead shares to prevent first-depositor attack
            shares = assets - DEAD_SHARES;
            require(shares > 0, "Insufficient initial deposit");

            balanceOf[address(0)] = DEAD_SHARES;
            totalSupply = DEAD_SHARES;
            totalAssets = DEAD_SHARES;

            supply = DEAD_SHARES;
        }

        // ✅ Use internal balance tracking with virtual shares
        shares = (assets * (supply + VIRTUAL_SHARES)) / (totalAssets + VIRTUAL_ASSETS);

        // ✅ Ensure minimum shares minted
        require(shares > 0, "Zero shares");

        require(asset.transferFrom(msg.sender, address(this), assets), "Transfer failed");

        // ✅ Update internal accounting
        totalAssets += assets;
        balanceOf[receiver] += shares;
        totalSupply += shares;

        emit Deposit(msg.sender, receiver, assets, shares);
    }

    // ✅ Fee changes with timelock and limits
    uint256 public pendingFee;
    uint256 public feeChangeTime;
    uint256 public constant FEE_CHANGE_DELAY = 2 days;

    function proposeFeeChange(uint256 newFee) external onlyOwner {
        require(newFee <= MAX_FEE, "Fee too high");

        pendingFee = newFee;
        feeChangeTime = block.timestamp + FEE_CHANGE_DELAY;
    }

    function executeFeeChange() external onlyOwner {
        require(block.timestamp >= feeChangeTime, "Too early");
        require(pendingFee <= MAX_FEE, "Invalid fee");

        depositFee = pendingFee;
        pendingFee = 0;
        feeChangeTime = 0;
    }

    // ✅ Secure withdrawal with liquidity check
    function withdraw(
        uint256 assets,
        address receiver,
        address _owner
    ) external returns (uint256 shares) {
        // ✅ Check available liquidity
        uint256 availableLiquidity = asset.balanceOf(address(this));
        require(availableLiquidity >= assets, "Insufficient liquidity");

        shares = convertToShares(assets);

        require(balanceOf[_owner] >= shares, "Insufficient shares");

        balanceOf[_owner] -= shares;
        totalSupply -= shares;
        totalAssets -= assets;

        require(asset.transfer(receiver, assets), "Transfer failed");
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply + VIRTUAL_SHARES;
        uint256 _totalAssets = totalAssets + VIRTUAL_ASSETS;

        return (assets * supply) / _totalAssets;
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        uint256 supply = totalSupply + VIRTUAL_SHARES;
        uint256 _totalAssets = totalAssets + VIRTUAL_ASSETS;

        return (shares * _totalAssets) / supply;
    }
}
