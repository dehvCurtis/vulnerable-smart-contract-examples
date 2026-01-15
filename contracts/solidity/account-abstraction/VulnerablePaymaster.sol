// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerablePaymaster
 * @notice Test contract for ERC-4337 Paymaster vulnerabilities
 *
 * DETECTORS TO TEST:
 * - aa-paymaster-fund-drain (Critical)
 * - erc4337-paymaster-abuse (Critical)
 *
 * VULNERABILITIES:
 * 1. No gas limit cap on sponsored operations
 * 2. Missing user whitelist or rate limiting
 * 3. No paymaster balance validation
 * 4. Missing per-user spending limits
 * 5. UserOp hash replay attacks
 * 6. Gas griefing vectors
 */

interface IEntryPoint {
    function depositTo(address account) external payable;
    function getDeposit(address account) external view returns (uint256);
}

struct UserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}

contract VulnerablePaymaster {
    IEntryPoint public immutable entryPoint;
    address public owner;

    constructor(address _entryPoint) {
        entryPoint = IEntryPoint(_entryPoint);
        owner = msg.sender;
    }

    // ❌ VULNERABILITY 1: No gas limit cap (aa-paymaster-fund-drain)
    // Attacker can request UNLIMITED gas to be sponsored, draining the paymaster
    function validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData) {
        // Missing: require(userOp.callGasLimit <= MAX_GAS_LIMIT, "Gas limit too high");
        // Missing: require(userOp.verificationGasLimit <= MAX_VERIFICATION_GAS, "Verification gas too high");

        // ❌ VULNERABILITY 2: No whitelist or rate limiting (aa-paymaster-fund-drain)
        // Anyone can use this paymaster without restrictions!
        // Missing: require(isWhitelisted[userOp.sender], "Not whitelisted");
        // Missing: require(requestsPerUser[userOp.sender] < MAX_REQUESTS_PER_HOUR, "Rate limit exceeded");

        // ❌ VULNERABILITY 3: No balance check (aa-paymaster-fund-drain)
        // Paymaster might accept sponsorship even if it doesn't have enough funds
        // Missing: require(entryPoint.getDeposit(address(this)) >= maxCost, "Insufficient paymaster balance");

        // ❌ VULNERABILITY 4: No per-user spending limit (aa-paymaster-fund-drain)
        // A single user could drain all paymaster funds
        // Missing:
        // require(accountSpent[userOp.sender] + maxCost <= MAX_PER_ACCOUNT, "Per-account limit exceeded");
        // accountSpent[userOp.sender] += maxCost;

        return ("", 0); // Accept all operations
    }

    // ❌ VULNERABILITY 5: UserOp hash not tracked for replay prevention (erc4337-paymaster-abuse)
    // Same userOpHash could be replayed to drain funds
    // mapping(bytes32 => bool) public usedHashes; // MISSING!
    function sponsorOperation(bytes32 userOpHash) external returns (bool) {
        // Missing: require(!usedHashes[userOpHash], "Already used");
        // Missing: usedHashes[userOpHash] = true;

        return true;
    }

    // ❌ VULNERABILITY 6: No validation in postOp (erc4337-paymaster-abuse)
    function postOp(
        uint8 mode,
        bytes calldata context,
        uint256 actualGasCost
    ) external {
        // Missing: Validation that gas costs are within expected range
        // Missing: Refund mechanism if actual cost is much lower than maxCost
        // Missing: Track actual spending per account

        // Just accept any cost without validation
    }

    receive() external payable {}
}

/**
 * @notice Vulnerable verifying paymaster that checks signatures but has other flaws
 */
contract VulnerableVerifyingPaymaster {
    IEntryPoint public immutable entryPoint;
    address public verifyingSigner;

    // ❌ VULNERABILITY 7: Missing replay protection (erc4337-paymaster-abuse)
    // mapping(bytes32 => bool) public usedHashes; // MISSING!

    constructor(address _entryPoint, address _signer) {
        entryPoint = IEntryPoint(_entryPoint);
        verifyingSigner = _signer;
    }

    function validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData) {
        // Extract signature from paymasterAndData
        require(userOp.paymasterAndData.length >= 84, "Invalid paymasterAndData");

        bytes memory signature = userOp.paymasterAndData[20:]; // Skip paymaster address

        // Verify signature
        bytes32 hash = keccak256(abi.encodePacked(userOpHash, maxCost));
        address signer = recoverSigner(hash, signature);
        require(signer == verifyingSigner, "Invalid signature");

        // ❌ VULNERABILITY 8: No replay protection after signature verification (erc4337-paymaster-abuse)
        // The same signed userOp could be submitted multiple times!
        // Missing: require(!usedHashes[userOpHash], "Already sponsored");
        // Missing: usedHashes[userOpHash] = true;

        // ❌ VULNERABILITY 9: No gas limits (aa-paymaster-fund-drain)
        // Even with valid signature, gas could be unlimited

        // ❌ VULNERABILITY 10: No spending limits (aa-paymaster-fund-drain)
        // Valid signer could drain entire paymaster

        return (abi.encode(userOp.sender, maxCost), 0);
    }

    function recoverSigner(bytes32 hash, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        return ecrecover(hash, v, r, s);
    }

    receive() external payable {}
}

/**
 * @notice Secure Paymaster implementation for comparison
 */
contract SecurePaymaster {
    IEntryPoint public immutable entryPoint;
    address public owner;

    // ✅ Gas limits
    uint256 public constant MAX_CALL_GAS_LIMIT = 1000000;
    uint256 public constant MAX_VERIFICATION_GAS = 500000;

    // ✅ Spending limits
    uint256 public constant MAX_PER_ACCOUNT = 0.1 ether;
    uint256 public constant MAX_PER_OPERATION = 0.01 ether;

    // ✅ Rate limiting
    uint256 public constant MAX_REQUESTS_PER_HOUR = 10;
    uint256 public constant RATE_LIMIT_WINDOW = 1 hours;

    // ✅ Tracking
    mapping(address => bool) public isWhitelisted;
    mapping(address => uint256) public accountSpent;
    mapping(bytes32 => bool) public usedHashes;
    mapping(address => uint256) public lastRequestTime;
    mapping(address => uint256) public requestCount;

    event UserWhitelisted(address indexed user);
    event UserRemoved(address indexed user);
    event PaymasterUsed(address indexed user, uint256 cost);

    constructor(address _entryPoint) {
        entryPoint = IEntryPoint(_entryPoint);
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    function addToWhitelist(address user) external onlyOwner {
        isWhitelisted[user] = true;
        emit UserWhitelisted(user);
    }

    function removeFromWhitelist(address user) external onlyOwner {
        isWhitelisted[user] = false;
        emit UserRemoved(user);
    }

    function validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData) {
        // ✅ Gas limit validation
        require(userOp.callGasLimit <= MAX_CALL_GAS_LIMIT, "Call gas too high");
        require(userOp.verificationGasLimit <= MAX_VERIFICATION_GAS, "Verification gas too high");

        // ✅ Cost validation
        require(maxCost <= MAX_PER_OPERATION, "Cost too high");

        // ✅ Whitelist check
        require(isWhitelisted[userOp.sender], "Not whitelisted");

        // ✅ Replay protection
        require(!usedHashes[userOpHash], "Already sponsored");
        usedHashes[userOpHash] = true;

        // ✅ Per-account spending limit
        require(
            accountSpent[userOp.sender] + maxCost <= MAX_PER_ACCOUNT,
            "Per-account limit exceeded"
        );

        // ✅ Rate limiting
        if (block.timestamp - lastRequestTime[userOp.sender] > RATE_LIMIT_WINDOW) {
            requestCount[userOp.sender] = 0;
            lastRequestTime[userOp.sender] = block.timestamp;
        }
        require(requestCount[userOp.sender] < MAX_REQUESTS_PER_HOUR, "Rate limit exceeded");
        requestCount[userOp.sender]++;

        // ✅ Balance check
        require(
            entryPoint.getDeposit(address(this)) >= maxCost,
            "Insufficient paymaster balance"
        );

        // Track spending
        accountSpent[userOp.sender] += maxCost;

        emit PaymasterUsed(userOp.sender, maxCost);

        return (abi.encode(userOp.sender, maxCost), 0);
    }

    function postOp(
        uint8 mode,
        bytes calldata context,
        uint256 actualGasCost
    ) external {
        (address sender, uint256 maxCost) = abi.decode(context, (address, uint256));

        // ✅ Refund if actual cost was lower
        if (actualGasCost < maxCost) {
            accountSpent[sender] -= (maxCost - actualGasCost);
        }
    }

    receive() external payable {}
}
