// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Vulnerable ERC-7683 Intent Contract - Missing Settlement Validation
 * @notice This contract demonstrates MISSING validation of settlement parameters
 * @dev Should be detected by: intent-settlement-validation detector
 *
 * VULNERABILITIES:
 * 1. No deadline validation
 * 2. No minimum output amount validation
 * 3. No validation of fill instructions
 * 4. Allows settlement with unfavorable terms
 */

contract VulnerableSettlementValidation {
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

    struct FillInstruction {
        address destinationChainReceiver;
        uint256 destinationChainId;
        bytes additionalData;
    }

    mapping(address => mapping(uint256 => bool)) public usedNonces;

    event IntentFilled(bytes32 indexed intentHash, address indexed filler, uint256 actualOutput);

    // ❌ VULNERABILITY 1: settle() doesn't validate deadline
    function settle(
        CrossChainIntent calldata intent,
        FillInstruction calldata fillInstruction
    ) external {
        // Verify signature
        bytes32 intentHash = getIntentHash(intent);
        address signer = recoverSigner(intentHash, intent.signature);
        require(signer == intent.initiator, "Invalid signature");

        // ❌ VULNERABILITY 2: No deadline validation!
        // Should have: require(block.timestamp <= intent.deadline, "Intent expired");

        // Check nonce
        require(!usedNonces[intent.initiator][intent.nonce], "Nonce used");
        usedNonces[intent.initiator][intent.nonce] = true;

        // ❌ VULNERABILITY 3: No validation of fillInstruction!
        // Should validate:
        // - destinationChainId matches intent.chainId
        // - destinationChainReceiver matches intent.recipient
        // - additionalData is properly formatted

        emit IntentFilled(intentHash, msg.sender, intent.outputAmount);
    }

    // ❌ VULNERABILITY 4: fillWithSlippage doesn't validate minimum output
    function fillWithSlippage(
        CrossChainIntent calldata intent,
        uint256 actualOutputAmount  // Solver can provide any amount!
    ) external {
        bytes32 intentHash = getIntentHash(intent);
        address signer = recoverSigner(intentHash, intent.signature);
        require(signer == intent.initiator, "Invalid signature");

        require(!usedNonces[intent.initiator][intent.nonce], "Nonce used");
        usedNonces[intent.initiator][intent.nonce] = true;

        // ❌ VULNERABILITY 5: No validation that actualOutputAmount >= intent.outputAmount!
        // Solver can give user less than expected!
        // Should have: require(actualOutputAmount >= intent.outputAmount, "Insufficient output");

        emit IntentFilled(intentHash, msg.sender, actualOutputAmount);
    }

    // ❌ VULNERABILITY 6: batchSettle doesn't validate individual settlements
    function batchSettle(
        CrossChainIntent[] calldata intents,
        FillInstruction[] calldata fillInstructions
    ) external {
        // ❌ VULNERABILITY 7: No length validation!
        // Should have: require(intents.length == fillInstructions.length, "Length mismatch");

        for (uint256 i = 0; i < intents.length; i++) {
            // ❌ VULNERABILITY 8: No try-catch or validation per intent
            // One failing intent can revert entire batch
            this.settle(intents[i], fillInstructions[i]);
        }
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
     * 1. Expired intent settlement - attacker settles after deadline passes
     * 2. Slippage exploit - solver gives less output than promised
     * 3. Wrong destination - funds sent to attacker's address on destination chain
     * 4. Batch DOS - attacker includes failing intent to revert entire batch
     */
}
