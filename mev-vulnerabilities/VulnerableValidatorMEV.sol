// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableValidatorMEV
 * @notice Test contract for validator MEV, permit front-running, and EIP-7702 vulnerabilities
 *
 * DETECTORS TO TEST:
 * - validator-front-running (High)
 * - token-permit-front-running (Medium)
 * - eip7702-init-frontrun (Critical)
 *
 * VULNERABILITIES:
 * 1. Validator can reorder transactions for profit
 * 2. ERC-2612 permit can be front-run
 * 3. Permit signature reuse vulnerability
 * 4. EIP-7702 account initialization can be front-run
 * 5. EIP-7702 delegation without authorization
 * 6. Block producer can extract MEV from transaction ordering
 * 7. Permit with no nonce validation
 * 8. EOA to contract conversion vulnerable to front-running
 */

interface IERC20Permit {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function nonces(address owner) external view returns (uint256);
}

/**
 * @notice Vulnerable permit usage (ERC-2612)
 */
contract VulnerablePermitUser {
    IERC20Permit public token;

    constructor(address _token) {
        token = IERC20Permit(_token);
    }

    // ❌ VULNERABILITY 1: Permit front-running (token-permit-front-running)
    // Attacker can steal the permit signature and use it themselves
    function depositWithPermit(
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // ❌ Permit parameters visible in mempool!
        // Attacker can:
        // 1. See your permit transaction
        // 2. Extract v, r, s signature
        // 3. Front-run with their own transaction using same signature
        // 4. Use the approval themselves

        token.permit(msg.sender, address(this), amount, deadline, v, r, s);
        token.transferFrom(msg.sender, address(this), amount);

        // You intended to deposit, but attacker used your approval!
    }

    // ❌ VULNERABILITY 2: Batch permit without nonce check (token-permit-front-running)
    function batchDepositWithPermit(
        address[] calldata users,
        uint256[] calldata amounts,
        uint256[] calldata deadlines,
        uint8[] calldata vs,
        bytes32[] calldata rs,
        bytes32[] calldata ss
    ) external {
        // ❌ Multiple permits in single transaction
        // ❌ No nonce validation

        for (uint256 i = 0; i < users.length; i++) {
            // All signatures visible in transaction data
            token.permit(users[i], address(this), amounts[i], deadlines[i], vs[i], rs[i], ss[i]);
            token.transferFrom(users[i], address(this), amounts[i]);
        }

        // Attacker can extract ALL signatures and use them
    }

    // ❌ VULNERABILITY 3: Permit with long deadline (token-permit-front-running)
    function depositWithLongDeadline(
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // ❌ Deadline = max uint256
        uint256 deadline = type(uint256).max;

        // Signature remains valid forever!
        // Attacker can use it at any time in the future

        token.permit(msg.sender, address(this), amount, deadline, v, r, s);
        token.transferFrom(msg.sender, address(this), amount);
    }

    // ❌ VULNERABILITY 4: Reusable permit signature (token-permit-front-running)
    mapping(bytes32 => bool) public usedSignatures;

    function depositWithSignatureTracking(
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 sigHash = keccak256(abi.encodePacked(v, r, s));

        // ❌ Tracking signature but AFTER permit call!
        token.permit(msg.sender, address(this), amount, deadline, v, r, s);

        // ❌ Too late - signature already used!
        require(!usedSignatures[sigHash], "Signature used");
        usedSignatures[sigHash] = true;

        token.transferFrom(msg.sender, address(this), amount);
    }
}

/**
 * @notice Vulnerable validator MEV extraction
 */
contract VulnerableValidatorMEV {
    mapping(address => uint256) public balances;

    // ❌ VULNERABILITY 5: Validator can reorder for profit (validator-front-running)
    function swap(uint256 amountIn) external returns (uint256 amountOut) {
        // ❌ No protection against validator MEV!
        // ❌ No commit-reveal
        // ❌ No encrypted mempool

        // Validator (block producer) can:
        // 1. See your swap transaction
        // 2. Insert their own swap before yours
        // 3. Reorder transactions for maximum profit
        // 4. Extract MEV without being detected

        amountOut = calculateOutput(amountIn);

        balances[msg.sender] -= amountIn;
        balances[msg.sender] += amountOut;

        return amountOut;
    }

    // ❌ VULNERABILITY 6: Time-sensitive operation (validator-front-running)
    function claimReward() external returns (uint256 reward) {
        // ❌ Reward based on block.timestamp
        // Validator controls timestamp within bounds

        reward = calculateReward(block.timestamp);

        // Validator can:
        // 1. Manipulate block.timestamp (±15 seconds)
        // 2. Include/exclude transactions to affect reward
        // 3. Reorder transactions for optimal timing

        balances[msg.sender] += reward;
    }

    // ❌ VULNERABILITY 7: First-come reward (validator-front-running)
    bool public rewardClaimed;

    function claimFirstReward() external {
        require(!rewardClaimed, "Already claimed");

        // ❌ Validator controls transaction ordering!
        // Validator can:
        // 1. See multiple claim transactions
        // 2. Order their own transaction first
        // 3. Claim reward themselves

        rewardClaimed = true;
        balances[msg.sender] += 100 ether;
    }

    function calculateOutput(uint256 amountIn) internal pure returns (uint256) {
        return amountIn * 99 / 100;
    }

    function calculateReward(uint256 timestamp) internal pure returns (uint256) {
        return timestamp % 1000;
    }
}

/**
 * @notice EIP-7702 vulnerable account
 */
contract VulnerableEIP7702Account {
    address public owner;
    address public delegatedImplementation;
    bool public initialized;

    // ❌ VULNERABILITY 8: Unprotected initialization (eip7702-init-frontrun)
    // EIP-7702 allows EOAs to temporarily become smart contracts
    function initialize(address _owner) external {
        // ❌ No initialization protection!
        // ❌ No require(!initialized)
        // ❌ No access control

        // Attacker can:
        // 1. See EOA converting to contract via EIP-7702
        // 2. Front-run the initialization
        // 3. Initialize with their own address as owner
        // 4. Take control of the account

        owner = _owner;
        initialized = true;
    }

    // ❌ VULNERABILITY 9: Delegation without authorization (eip7702-init-frontrun)
    function setDelegation(address implementation) external {
        // ❌ Anyone can set delegation!
        // ❌ No owner check
        // ❌ No authorization

        delegatedImplementation = implementation;

        // In EIP-7702, EOA delegates calls to this implementation
        // Attacker can front-run and set malicious implementation
    }

    // ❌ VULNERABILITY 10: Initialization without nonce (eip7702-init-frontrun)
    function initializeWithNonce(address _owner, uint256 nonce) external {
        // ❌ Nonce not validated against msg.sender!
        require(!initialized, "Already initialized");

        // Attacker can use same nonce in front-run transaction
        owner = _owner;
        initialized = true;
    }

    function execute(address target, bytes calldata data) external returns (bytes memory) {
        require(msg.sender == owner, "Not owner");

        (bool success, bytes memory result) = target.call(data);
        require(success, "Execution failed");

        return result;
    }
}

/**
 * @notice Vulnerable EOA to contract conversion
 */
contract VulnerableEOAConversion {
    mapping(address => address) public accountImplementations;

    // ❌ VULNERABILITY 11: Public account setup (eip7702-init-frontrun)
    function setupAccount(address account, address implementation) external {
        // ❌ No signature validation!
        // ❌ No require(msg.sender == account)
        // ❌ Anyone can setup any account

        accountImplementations[account] = implementation;

        // Attacker can:
        // 1. Front-run legitimate setup
        // 2. Set malicious implementation for victim's EOA
        // 3. Steal funds when victim converts EOA to contract
    }

    // ❌ VULNERABILITY 12: Batch account setup (eip7702-init-frontrun)
    function batchSetupAccounts(
        address[] calldata accounts,
        address[] calldata implementations
    ) external {
        // ❌ No authorization for any account!

        for (uint256 i = 0; i < accounts.length; i++) {
            accountImplementations[accounts[i]] = implementations[i];
        }

        // All account setups visible and can be front-run
    }
}

/**
 * @notice Secure permit usage
 */
contract SecurePermitUser {
    IERC20Permit public token;
    mapping(address => mapping(bytes32 => bool)) public usedPermitSignatures;

    constructor(address _token) {
        token = IERC20Permit(_token);
    }

    // ✅ Secure permit with replay protection
    function depositWithPermit(
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // ✅ Check permit signature not already used
        bytes32 permitHash = keccak256(abi.encodePacked(
            msg.sender,
            address(this),
            amount,
            deadline,
            token.nonces(msg.sender)
        ));

        require(!usedPermitSignatures[msg.sender][permitHash], "Permit already used");
        usedPermitSignatures[msg.sender][permitHash] = true;

        // ✅ Use try-catch to handle front-running gracefully
        try token.permit(msg.sender, address(this), amount, deadline, v, r, s) {
            // Permit succeeded
        } catch {
            // Permit may have been front-run, but we tracked it
            // Check if we have approval
            // Real implementation would check allowance here
        }

        token.transferFrom(msg.sender, address(this), amount);
    }

    // ✅ Alternative: Use permit2 (EIP-2612 extension)
    // Or meta-transactions with signed messages
}

/**
 * @notice Secure EIP-7702 account
 */
contract SecureEIP7702Account {
    address public owner;
    bool public initialized;

    // ✅ Secure initialization with signature
    function initialize(
        address _owner,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(!initialized, "Already initialized");

        // ✅ Verify signature from expected owner
        bytes32 message = keccak256(abi.encodePacked(
            "Initialize account",
            address(this),
            _owner,
            block.chainid
        ));

        bytes32 ethSignedMessage = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            message
        ));

        address signer = ecrecover(ethSignedMessage, v, r, s);
        require(signer == _owner, "Invalid signature");

        // ✅ Now safe to initialize
        owner = _owner;
        initialized = true;
    }

    // ✅ Protected delegation
    function setDelegation(address implementation) external {
        require(msg.sender == owner, "Not owner");
        // Set delegation safely
    }
}
