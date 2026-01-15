// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableERC20
 * @notice Test contract for ERC-20 token vulnerabilities
 *
 * DETECTORS TO TEST:
 * - erc20-approve-race (Medium)
 * - erc20-infinite-approval (Low)
 * - erc20-transfer-return-bomb (Medium)
 * - token-decimal-confusion (High)
 * - token-supply-manipulation (Critical)
 * - token-permit-front-running (Medium)
 *
 * VULNERABILITIES:
 * 1. Approve race condition (front-running approve changes)
 * 2. Infinite approvals
 * 3. Transfer return value bomb (gas griefing)
 * 4. Decimal confusion (token bridging, pricing)
 * 5. Supply manipulation
 * 6. Permit front-running
 * 7. Fee-on-transfer token issues
 * 8. Rebasing token issues
 */

/**
 * @notice Vulnerable ERC-20 with approve race condition
 */
contract VulnerableERC20ApproveRace {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    string public name = "Vulnerable Token";
    string public symbol = "VULN";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor() {
        totalSupply = 1000000 * 10**18;
        balanceOf[msg.sender] = totalSupply;
    }

    // ❌ VULNERABILITY 1: Approve race condition (erc20-approve-race)
    function approve(address spender, uint256 amount) external returns (bool) {
        // ❌ No check for existing allowance!
        // ❌ Standard ERC-20 approve is vulnerable to front-running!

        // Attack scenario:
        // 1. Alice approves Bob for 100 tokens
        // 2. Alice wants to change to 50 tokens, calls approve(Bob, 50)
        // 3. Bob sees tx in mempool, front-runs with transferFrom(Alice, Bob, 100)
        // 4. Alice's approve(Bob, 50) executes
        // 5. Bob now has 100 tokens + 50 token allowance = can steal 150 total!

        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");

        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;

        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");

        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;

        emit Transfer(from, to, amount);
        return true;
    }
}

/**
 * @notice Contract using infinite approval pattern
 */
contract VulnerableInfiniteApproval {
    mapping(address => uint256) public balances;

    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // ❌ VULNERABILITY 2: Infinite approval (erc20-infinite-approval)
    function depositTokens(uint256 amount) external {
        // ❌ Approves uint256.max (infinite approval)!
        // ❌ If token contract is compromised, all user tokens can be drained!
        // ❌ If this contract is compromised, all approved tokens can be stolen!

        token.approve(address(this), type(uint256).max);

        // Infinite approval risks:
        // 1. Token contract upgrade introduces bug → all approved tokens drained
        // 2. This contract hacked → attacker drains all user approvals
        // 3. User forgets about approval → passive security risk
        // 4. Phishing: users approve malicious contracts with max approval

        token.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
    }

    // ❌ Common infinite approval pattern in DeFi protocols
    function approveRouter(address router) external {
        // ❌ Approves router for infinite amount!
        token.approve(router, type(uint256).max);
    }
}

/**
 * @notice Token with transfer return bomb
 */
contract VulnerableReturnBombToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public totalSupply;

    // ❌ VULNERABILITY 3: Return bomb (erc20-transfer-return-bomb)
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount);

        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;

        // ❌ Return bomb: returns huge amount of data!
        // ❌ Wastes gas for caller, can cause out-of-gas errors!
        // ❌ Used in gas griefing attacks!

        assembly {
            // Return 10KB of data (gas bomb!)
            mstore(0x00, 1)
            return(0x00, 10000)
        }
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;

        // ❌ Another return bomb
        assembly {
            mstore(0x00, 1)
            return(0x00, 5000)
        }
    }
}

/**
 * @notice Contract vulnerable to decimal confusion
 */
contract VulnerableDecimalConfusion {
    // ❌ VULNERABILITY 4: Decimal confusion (token-decimal-confusion)

    IERC20 public token1; // 18 decimals
    IERC20 public token2; // 6 decimals (USDC)

    constructor(address _token1, address _token2) {
        token1 = IERC20(_token1);
        token2 = IERC20(_token2);
    }

    // ❌ Assumes both tokens have same decimals!
    function swap(uint256 amount) external {
        // ❌ No decimal normalization!
        // ❌ If token1 = DAI (18 decimals), token2 = USDC (6 decimals):
        // User swaps 1 DAI (1e18) for 1 USDC (1e6)
        // But receives 1e18 USDC (worth 1 trillion dollars!)

        token1.transferFrom(msg.sender, address(this), amount);
        token2.transfer(msg.sender, amount); // ❌ Same amount, different decimals!
    }

    // ❌ Price calculation without decimal adjustment
    function getPrice() external view returns (uint256) {
        uint256 balance1 = token1.balanceOf(address(this));
        uint256 balance2 = token2.balanceOf(address(this));

        // ❌ Divides 18-decimal by 6-decimal without normalization!
        // Result is off by 10^12!
        return balance1 / balance2;
    }

    // ❌ Bridge transfer without decimal conversion
    function bridgeTokens(address token, uint256 amount, uint256 destChainId) external {
        IERC20(token).transferFrom(msg.sender, address(this), amount);

        // ❌ Sends amount to destination chain without checking decimals!
        // ❌ If source token is 18 decimals, dest token is 6 decimals,
        // user loses 99.9999% of their tokens!

        // Bridge logic...
    }
}

/**
 * @notice Token with supply manipulation
 */
contract VulnerableSupplyManipulation {
    mapping(address => uint256) public balanceOf;

    uint256 public totalSupply;
    address public owner;

    constructor() {
        owner = msg.sender;
        totalSupply = 1000000 * 10**18;
        balanceOf[msg.sender] = totalSupply;
    }

    // ❌ VULNERABILITY 5: Unrestricted minting (token-supply-manipulation)
    function mint(address to, uint256 amount) external {
        // ❌ No access control!
        // ❌ Anyone can mint unlimited tokens!

        balanceOf[to] += amount;
        totalSupply += amount;

        // Impacts:
        // 1. Token price crashes to zero
        // 2. Existing holders diluted
        // 3. DeFi protocols using token get drained
        // 4. Governance voting power manipulated
    }

    // ❌ VULNERABILITY 6: Unrestricted burning (token-supply-manipulation)
    function burn(address from, uint256 amount) external {
        // ❌ No authorization check!
        // ❌ Anyone can burn anyone's tokens!

        balanceOf[from] -= amount;
        totalSupply -= amount;
    }

    // ❌ VULNERABILITY 7: Owner can mint unlimited (token-supply-manipulation)
    function ownerMint(address to, uint256 amount) external {
        require(msg.sender == owner);

        // ❌ No maximum supply cap!
        // ❌ Owner can print infinite tokens!
        // ❌ Centralization risk!

        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/**
 * @notice ERC-20 with permit (EIP-2612) vulnerable to front-running
 */
contract VulnerablePermitToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;

    string public name = "Permit Token";
    bytes32 public DOMAIN_SEPARATOR;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    // ❌ VULNERABILITY 8: Permit front-running (token-permit-front-running)
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= deadline, "Permit expired");

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                owner,
                spender,
                value,
                nonces[owner]++,
                deadline
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = ecrecover(digest, v, r, s);

        require(signer == owner, "Invalid signature");

        allowance[owner][spender] = value;

        // ❌ Attack scenario:
        // 1. User creates permit signature for spending 100 tokens
        // 2. User submits permit + transferFrom transaction
        // 3. Attacker sees permit in mempool
        // 4. Attacker front-runs with permit + transferFrom (higher gas)
        // 5. Attacker steals 100 tokens before user's tx executes
        // 6. User's tx fails (nonce already used)
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount);
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;
        return true;
    }
}

/**
 * @notice Protocol vulnerable to fee-on-transfer tokens
 */
contract VulnerableFeeOnTransfer {
    IERC20 public token;
    mapping(address => uint256) public deposits;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // ❌ VULNERABILITY 9: Doesn't account for transfer fees
    function deposit(uint256 amount) external {
        // ❌ Assumes full amount is received!
        // ❌ If token has 2% transfer fee, only 98% arrives!

        token.transferFrom(msg.sender, address(this), amount);

        // ❌ Credits user for 100% but only received 98%!
        deposits[msg.sender] += amount;

        // Attack:
        // 1. User deposits 100 tokens (2% fee)
        // 2. Contract receives 98 tokens
        // 3. User credited for 100 tokens
        // 4. User withdraws 100 tokens
        // 5. Contract loses 2 tokens per deposit/withdrawal cycle
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount);

        deposits[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}

/**
 * @notice Protocol vulnerable to rebasing tokens
 */
contract VulnerableRebasingToken {
    IERC20 public token;
    mapping(address => uint256) public shares;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // ❌ VULNERABILITY 10: Doesn't account for token rebasing
    function stake(uint256 amount) external {
        uint256 balanceBefore = token.balanceOf(address(this));

        token.transferFrom(msg.sender, address(this), amount);

        // ❌ If token is rebasing (like stETH, aTokens):
        // ❌ Token balance increases/decreases automatically!
        // ❌ Shares calculated at one moment become incorrect!

        shares[msg.sender] += amount;

        // Issues:
        // 1. Positive rebase → protocol keeps extra tokens (user loss)
        // 2. Negative rebase → protocol insolvent (can't pay all withdrawals)
        // 3. No accounting for rebase rewards
    }

    function unstake(uint256 shareAmount) external {
        require(shares[msg.sender] >= shareAmount);

        shares[msg.sender] -= shareAmount;

        // ❌ Transfers based on shares, but token balance may have rebased!
        token.transfer(msg.sender, shareAmount);
    }
}

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/**
 * @notice Secure ERC-20 implementations
 */
contract SecureERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // ✅ Secure approve: use increaseAllowance/decreaseAllowance
    function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
        allowance[msg.sender][spender] += addedValue;
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {
        uint256 currentAllowance = allowance[msg.sender][spender];
        require(currentAllowance >= subtractedValue, "Decreased below zero");
        allowance[msg.sender][spender] = currentAllowance - subtractedValue;
        return true;
    }

    // ✅ Or: require current allowance is 0 or matches expected
    function approve(address spender, uint256 amount) external returns (bool) {
        // Option 1: Require 0 allowance first
        require(allowance[msg.sender][spender] == 0, "Approve from non-zero");

        allowance[msg.sender][spender] = amount;
        return true;
    }
}

contract SecureDecimalHandling {
    function normalizeDecimals(
        uint256 amount,
        uint8 fromDecimals,
        uint8 toDecimals
    ) internal pure returns (uint256) {
        if (fromDecimals == toDecimals) {
            return amount;
        } else if (fromDecimals < toDecimals) {
            return amount * (10 ** (toDecimals - fromDecimals));
        } else {
            return amount / (10 ** (fromDecimals - toDecimals));
        }
    }
}
