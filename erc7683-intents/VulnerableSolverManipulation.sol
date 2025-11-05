// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Vulnerable ERC-7683 Intent Contract - Solver Manipulation
 * @notice This contract demonstrates MISSING solver authentication and validation
 * @dev Should be detected by: intent-solver-manipulation detector
 *
 * VULNERABILITIES:
 * 1. No solver whitelist or authentication
 * 2. Solvers can front-run each other
 * 3. No minimum reputation or stake requirement
 * 4. Allows malicious solvers to extract MEV
 */

contract VulnerableSolverManipulation {
    struct CrossChainIntent {
        address initiator;
        address recipient;
        address inputToken;
        address outputToken;
        uint256 inputAmount;
        uint256 outputAmount;
        uint256 deadline;
        uint256 nonce;
        uint256 chainId;
        bytes signature;
    }

    mapping(address => mapping(uint256 => bool)) public usedNonces;

    // ❌ VULNERABILITY 1: No solver whitelist!
    // Should have: mapping(address => bool) public approvedSolvers;

    // ❌ VULNERABILITY 2: No solver staking/bonding!
    // Should have: mapping(address => uint256) public solverStakes;

    event IntentFilled(bytes32 indexed intentHash, address indexed solver, uint256 profit);

    // ❌ VULNERABILITY 3: fillIntent has no solver authentication
    function fillIntent(CrossChainIntent calldata intent) external {
        bytes32 intentHash = getIntentHash(intent);
        address signer = recoverSigner(intentHash, intent.signature);
        require(signer == intent.initiator, "Invalid signature");

        require(block.timestamp <= intent.deadline, "Intent expired");
        require(!usedNonces[intent.initiator][intent.nonce], "Nonce used");
        usedNonces[intent.initiator][intent.nonce] = true;

        // ❌ VULNERABILITY 4: No solver validation!
        // Any address can act as solver, including malicious actors
        // Should have: require(approvedSolvers[msg.sender], "Solver not approved");

        // ❌ VULNERABILITY 5: No stake requirement!
        // Should have: require(solverStakes[msg.sender] >= minStake, "Insufficient stake");

        emit IntentFilled(intentHash, msg.sender, 0);
    }

    // ❌ VULNERABILITY 6: Competitive fill allows front-running
    function competitiveFill(
        CrossChainIntent calldata intent,
        uint256 bidAmount  // Solver's bid
    ) external {
        bytes32 intentHash = getIntentHash(intent);

        // ❌ VULNERABILITY 7: No protection against solver front-running!
        // Solver can see pending txs and front-run with higher gas price
        // No fair ordering mechanism (no commit-reveal, no auction)

        require(!usedNonces[intent.initiator][intent.nonce], "Nonce used");
        usedNonces[intent.initiator][intent.nonce] = true;

        // ❌ VULNERABILITY 8: No minimum bid validation!
        // Malicious solver can bid 0 or negative amount
        // Should have: require(bidAmount >= intent.outputAmount, "Bid too low");

        emit IntentFilled(intentHash, msg.sender, bidAmount);
    }

    // ❌ VULNERABILITY 9: priorityFill allows MEV extraction
    function priorityFill(
        CrossChainIntent calldata intent,
        uint256 priorityFee
    ) external payable {
        // ❌ VULNERABILITY 10: Priority fee creates MEV opportunity!
        // Searchers can pay higher priorityFee to front-run legitimate solvers
        require(msg.value >= priorityFee, "Insufficient priority fee");

        bytes32 intentHash = getIntentHash(intent);
        require(!usedNonces[intent.initiator][intent.nonce], "Nonce used");
        usedNonces[intent.initiator][intent.nonce] = true;

        // ❌ VULNERABILITY 11: No slashing for solver misbehavior!
        // If solver fails to deliver, no penalty

        emit IntentFilled(intentHash, msg.sender, priorityFee);
    }

    // ❌ VULNERABILITY 12: partialFill allows solver to game system
    function partialFill(
        CrossChainIntent calldata intent,
        uint256 fillPercentage  // Solver chooses how much to fill
    ) external {
        bytes32 intentHash = getIntentHash(intent);

        // ❌ VULNERABILITY 13: No validation of fillPercentage!
        // Solver can fill 1% and block intent for others
        // Should have: require(fillPercentage >= minFillPercentage, "Fill too small");

        // ❌ VULNERABILITY 14: No mechanism to handle remaining amount
        // Intent becomes stuck after partial fill

        emit IntentFilled(intentHash, msg.sender, fillPercentage);
    }

    function getIntentHash(CrossChainIntent calldata intent) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            intent.initiator,
            intent.recipient,
            intent.inputToken,
            intent.outputToken,
            intent.inputAmount,
            intent.outputAmount,
            intent.deadline,
            intent.nonce,
            intent.chainId
        ));
    }

    function recoverSigner(bytes32 hash, bytes memory signature) internal pure returns (address) {
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);
        return ecrecover(ethSignedHash, v, r, s);
    }

    function splitSignature(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    /**
     * EXPLOIT SCENARIOS:
     * 1. Front-running - Malicious solver sees profitable intent in mempool, front-runs
     * 2. Sandwich attack - Solver front-runs user intent, manipulates price, back-runs
     * 3. Griefing - Solver partially fills tiny amount, blocking legitimate solvers
     * 4. MEV extraction - Searchers compete with priority fees, users pay more
     * 5. No accountability - Malicious solver fills but doesn't deliver, no slashing
     */
}
