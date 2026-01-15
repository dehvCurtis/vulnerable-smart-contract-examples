// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Vulnerable ERC-7683 Intent Contract - Missing Nonce Management
 * @notice This contract demonstrates MISSING nonce validation vulnerability
 * @dev Should be detected by: intent-nonce-management detector
 *
 * VULNERABILITIES:
 * 1. No nonce tracking for intents
 * 2. No nonce validation in fillOrder
 * 3. Allows replay attacks - same intent can be filled multiple times
 * 4. Missing usedNonces mapping
 */

contract VulnerableNonceManagement {
    // ERC-7683 Intent structure
    struct CrossChainIntent {
        address initiator;
        address recipient;
        address inputToken;
        address outputToken;
        uint256 inputAmount;
        uint256 outputAmount;
        uint256 deadline;
        uint256 chainId;
        bytes signature;
    }

    event IntentFilled(bytes32 indexed intentHash, address indexed filler);

    // ❌ VULNERABILITY 1: No nonce storage!
    // Should have: mapping(address => mapping(uint256 => bool)) public usedNonces;

    // ❌ VULNERABILITY 2: fillOrder doesn't validate or track nonces
    function fillOrder(CrossChainIntent calldata intent) external {
        // Verify signature
        bytes32 intentHash = getIntentHash(intent);
        address signer = recoverSigner(intentHash, intent.signature);
        require(signer == intent.initiator, "Invalid signature");

        // Check deadline
        require(block.timestamp <= intent.deadline, "Intent expired");

        // ❌ VULNERABILITY 3: No nonce validation!
        // Should have: require(!usedNonces[intent.initiator][intent.nonce], "Nonce already used");
        // Should have: usedNonces[intent.initiator][intent.nonce] = true;

        // Execute intent (simplified)
        // In real implementation: transfer tokens, cross-chain message, etc.

        emit IntentFilled(intentHash, msg.sender);

        // ❌ VULNERABILITY 4: Same intent can be filled multiple times (replay attack)
    }

    // ❌ VULNERABILITY 5: Intent hash doesn't include nonce for uniqueness
    function getIntentHash(CrossChainIntent calldata intent) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            intent.initiator,
            intent.recipient,
            intent.inputToken,
            intent.outputToken,
            intent.inputAmount,
            intent.outputAmount,
            intent.deadline,
            intent.chainId
            // Missing: nonce parameter for uniqueness
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
}
