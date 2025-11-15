// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Common Vulnerability Patterns Testing
 * @notice Tests general-purpose detectors not covered in specialized categories
 */

// =====================================================================
// 1. DANGEROUS DELEGATECALL
// =====================================================================

contract VulnerableDelegatecall {
    address public implementation;

    // ❌ VULNERABILITY: User-controlled delegatecall target
    function execute(address target, bytes calldata data) external payable {
        // Dangerous: delegatecall to arbitrary address
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    // ❌ VULNERABILITY: Delegatecall to zero address
    function executeToImplementation(bytes calldata data) external payable {
        // Dangerous if implementation is zero or malicious
        (bool success, ) = implementation.delegatecall(data);
        require(success, "Failed");
    }
}

// =====================================================================
// 2. DOS VIA FAILED TRANSFER
// =====================================================================

contract VulnerableDoSTransfer {
    mapping(address => uint256) public balances;

    // ❌ VULNERABILITY: Transfer can fail and revert entire transaction
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;

        // DOS: If transfer fails, user can never withdraw
        payable(msg.sender).transfer(amount);
    }

    // ❌ VULNERABILITY: Batch transfer can fail if one fails
    function batchTransfer(address[] calldata recipients, uint256[] calldata amounts) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            // DOS: One failed transfer blocks all subsequent transfers
            payable(recipients[i]).transfer(amounts[i]);
        }
    }
}

// =====================================================================
// 3. EXTERNAL CALLS IN LOOP
// =====================================================================

interface IToken {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract VulnerableExternalCallsLoop {
    address[] public users;
    mapping(address => uint256) public rewards;

    // ❌ VULNERABILITY: External calls in unbounded loop
    function distributeRewards() external {
        for (uint256 i = 0; i < users.length; i++) {
            // DOS: External call in loop, one failure reverts all
            payable(users[i]).transfer(rewards[users[i]]);
        }
    }

    // ❌ VULNERABILITY: External contract calls in loop
    function batchTransferTokens(IToken token, address[] calldata recipients) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            // External call in loop - gas griefing
            token.transfer(recipients[i], 100);
        }
    }
}

// =====================================================================
// 4. ARRAY LENGTH MISMATCH
// =====================================================================

contract VulnerableArrayMismatch {
    // ❌ VULNERABILITY: No length check on input arrays
    function batchProcess(
        address[] calldata addresses,
        uint256[] calldata amounts
    ) external {
        // Missing: require(addresses.length == amounts.length)
        for (uint256 i = 0; i < addresses.length; i++) {
            // Will revert or process incorrectly if lengths differ
            payable(addresses[i]).transfer(amounts[i]);
        }
    }

    // ❌ VULNERABILITY: Parallel arrays without length validation
    function updateBalances(
        address[] calldata users,
        uint256[] calldata newBalances,
        bool[] calldata isActive
    ) external {
        // Missing validation of array lengths
        for (uint256 i = 0; i < users.length; i++) {
            if (isActive[i]) { // Could be out of bounds
                // Process
            }
        }
    }
}

// =====================================================================
// 5. DIVISION BEFORE MULTIPLICATION
// =====================================================================

contract VulnerableDivisionOrder {
    uint256 public constant FEE_DENOMINATOR = 10000;

    // ❌ VULNERABILITY: Division before multiplication loses precision
    function calculateReward(uint256 amount, uint256 feeNumerator) public pure returns (uint256) {
        // Wrong: division first causes precision loss
        return (amount / FEE_DENOMINATOR) * feeNumerator;
    }

    // ❌ VULNERABILITY: Multiple divisions compound precision loss
    function complexCalculation(uint256 value) public pure returns (uint256) {
        uint256 step1 = value / 100;  // First precision loss
        uint256 step2 = step1 / 50;   // Second precision loss
        return step2 * 75;            // Magnifies the error
    }
}

// =====================================================================
// 6. INSUFFICIENT RANDOMNESS
// =====================================================================

contract VulnerableRandomness {
    // ❌ VULNERABILITY: Predictable randomness from block data
    function getRandomNumber() public view returns (uint256) {
        // Miners can manipulate this
        return uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.prevrandao,
            msg.sender
        )));
    }

    // ❌ VULNERABILITY: Lottery using predictable randomness
    address[] public participants;

    function drawWinner() external returns (address) {
        // Vulnerable: miners can predict and manipulate
        uint256 random = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.prevrandao
        )));
        uint256 winnerIndex = random % participants.length;
        return participants[winnerIndex];
    }
}

// =====================================================================
// 7. SIGNATURE MALLEABILITY
// =====================================================================

contract VulnerableSignatureMalleability {
    mapping(address => uint256) public nonces;

    // ❌ VULNERABILITY: ECDSA signature malleability
    function executeWithSignature(
        address to,
        uint256 amount,
        uint256 nonce,
        bytes memory signature
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(to, amount, nonce));

        // ❌ Missing: EIP-191 prefix
        // ❌ Missing: s-value check (should be in lower half)
        address signer = recoverSigner(messageHash, signature);

        require(nonces[signer] == nonce, "Invalid nonce");
        nonces[signer]++;

        payable(to).transfer(amount);
    }

    function recoverSigner(bytes32 hash, bytes memory signature) internal pure returns (address) {
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
}

// =====================================================================
// 8. FRONT-RUNNING VULNERABILITIES
// =====================================================================

contract VulnerableFrontRunning {
    mapping(address => uint256) public balances;
    uint256 public secretValue;

    // ❌ VULNERABILITY: Front-runnable secret reveal
    function revealSecret(uint256 secret) external {
        // Anyone can see this in mempool and front-run
        secretValue = secret;
        balances[msg.sender] += 1000 ether;
    }

    // ❌ VULNERABILITY: Front-runnable purchase
    uint256 public itemPrice = 1 ether;

    function buyItem() external payable {
        // Seller can see tx and front-run to increase price
        require(msg.value >= itemPrice, "Insufficient payment");
        // Process purchase
    }

    // ❌ VULNERABILITY: Approval front-running
    mapping(address => mapping(address => uint256)) public allowances;

    function approve(address spender, uint256 amount) external {
        // Spender can front-run approval changes
        allowances[msg.sender][spender] = amount;
    }
}

// =====================================================================
// 9. EMERGENCY CONTROLS
// =====================================================================

contract VulnerableEmergencyControls {
    address public owner;
    bool public paused;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    // ❌ VULNERABILITY: Emergency withdrawal with no restrictions
    function emergencyWithdraw() external {
        require(msg.sender == owner, "Not owner");
        // No timelock, no limits, owner can rug pull anytime
        payable(owner).transfer(address(this).balance);
    }

    // ❌ VULNERABILITY: Centralized pause with no unpause protection
    function pause() external {
        require(msg.sender == owner, "Not owner");
        paused = true;
        // Funds can be locked forever if owner malicious
    }

    // ❌ VULNERABILITY: Emergency function abuse
    function emergencyBurn(address user) external {
        require(msg.sender == owner, "Not owner");
        // Owner can burn anyone's balance without justification
        balances[user] = 0;
    }
}

// =====================================================================
// 10. GAS PRICE MANIPULATION
// =====================================================================

contract VulnerableGasPrice {
    uint256 public constant MIN_GAS_PRICE = 10 gwei;

    // ❌ VULNERABILITY: Tx.gasprice can be manipulated
    function executeIfHighGas() external {
        // Vulnerable: users can bypass by setting higher gas price
        require(tx.gasprice >= MIN_GAS_PRICE, "Gas price too low");
        // Exclusive action
    }

    // ❌ VULNERABILITY: Using gas price for randomness
    function randomAction() external {
        // Users can manipulate tx.gasprice for desired outcome
        if (tx.gasprice % 2 == 0) {
            // Action A
        } else {
            // Action B
        }
    }
}

// =====================================================================
// 11. BLOCK DEPENDENCY
// =====================================================================

contract VulnerableBlockDependency {
    // ❌ VULNERABILITY: Critical logic depends on block.number
    function isActionAllowed() public view returns (bool) {
        // Miners can manipulate when this returns true
        return block.number % 10 == 0;
    }

    // ❌ VULNERABILITY: Using block.timestamp for critical logic
    mapping(address => uint256) public lastAction;
    uint256 public constant COOLDOWN = 1 hours;

    function criticalAction() external {
        // Block timestamp can be manipulated by miners (~900s variance)
        require(block.timestamp >= lastAction[msg.sender] + COOLDOWN, "Cooldown");
        lastAction[msg.sender] = block.timestamp;
    }
}

// =====================================================================
// 12. TX.ORIGIN AUTHENTICATION
// =====================================================================

contract VulnerableTxOrigin {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // ❌ VULNERABILITY: Using tx.origin for authentication
    function withdrawAll() external {
        require(tx.origin == owner, "Not owner");
        // Phishing attack possible - owner calls malicious contract
        payable(owner).transfer(address(this).balance);
    }

    // ❌ VULNERABILITY: tx.origin in access control
    modifier onlyOwner() {
        require(tx.origin == owner, "Not authorized");
        _;
    }

    function criticalFunction() external onlyOwner {
        // Vulnerable to phishing
    }
}

/**
 * TESTING NOTES:
 *
 * Expected Detectors (untested detectors):
 * 1. dangerous-delegatecall (10+ findings)
 * 2. dos-failed-transfer (4+ findings)
 * 3. external-calls-loop (3+ findings)
 * 4. array-length-mismatch (2+ findings)
 * 5. division-before-multiplication (3+ findings)
 * 6. insufficient-randomness (3+ findings)
 * 7. signature-malleability (2+ findings)
 * 8. front-running (4+ findings)
 * 9. front-running-mitigation (cross-check)
 * 10. emergency-withdrawal-abuse (3+ findings)
 * 11. emergency-pause-centralization (1+ findings)
 * 12. gas-price-manipulation (2+ findings)
 * 13. block-dependency (3+ findings)
 * 14. tx-origin-authentication (3+ findings)
 *
 * Cross-Category Detectors Expected:
 * - missing-access-modifiers
 * - unchecked-external-call
 * - parameter-consistency
 * - missing-input-validation
 * - reentrancy patterns
 * - centralization-risk
 */
