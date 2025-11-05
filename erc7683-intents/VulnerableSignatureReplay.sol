// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Vulnerable ERC-7683 Intent Contract - Cross-Chain Signature Replay
 * @notice This contract demonstrates MISSING chainId validation vulnerability
 * @dev Should be detected by: intent-signature-replay detector
 *
 * VULNERABILITIES:
 * 1. No chainId validation in signature
 * 2. Missing EIP-712 domain separator with chainId
 * 3. Allows cross-chain replay attacks
 * 4. Signature can be reused on different chains
 */

contract VulnerableSignatureReplay {
    struct CrossChainIntent {
        address initiator;
        address recipient;
        address inputToken;
        address outputToken;
        uint256 inputAmount;
        uint256 outputAmount;
        uint256 deadline;
        uint256 nonce;
        // ❌ VULNERABILITY 1: chainId not in struct!
        bytes signature;
    }

    mapping(address => mapping(uint256 => bool)) public usedNonces;

    event IntentFilled(bytes32 indexed intentHash, address indexed filler);

    // ❌ VULNERABILITY 2: No chainId validation in fillOrder
    function fillOrder(CrossChainIntent calldata intent) external {
        // Verify signature
        bytes32 intentHash = getIntentHash(intent);
        address signer = recoverSigner(intentHash, intent.signature);
        require(signer == intent.initiator, "Invalid signature");

        // Check deadline
        require(block.timestamp <= intent.deadline, "Intent expired");

        // Check nonce (but nonce alone doesn't prevent cross-chain replay!)
        require(!usedNonces[intent.initiator][intent.nonce], "Nonce used");
        usedNonces[intent.initiator][intent.nonce] = true;

        // ❌ VULNERABILITY 3: No chainId validation!
        // Should have: require(intent.chainId == block.chainid, "Wrong chain");

        emit IntentFilled(intentHash, msg.sender);
    }

    // ❌ VULNERABILITY 4: Intent hash doesn't include chainId
    function getIntentHash(CrossChainIntent calldata intent) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            intent.initiator,
            intent.recipient,
            intent.inputToken,
            intent.outputToken,
            intent.inputAmount,
            intent.outputAmount,
            intent.deadline,
            intent.nonce
            // Missing: chainId for cross-chain uniqueness
        ));
    }

    // ❌ VULNERABILITY 5: No EIP-712 domain separator with chainId
    // Should use EIP-712 typed data with domain separator including chainId:
    // bytes32 DOMAIN_SEPARATOR = keccak256(abi.encode(
    //     keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
    //     keccak256(bytes("CrossChainIntent")),
    //     keccak256(bytes("1")),
    //     block.chainid,
    //     address(this)
    // ));

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
     * EXPLOIT SCENARIO:
     * 1. User signs intent on Ethereum mainnet (chainId 1)
     * 2. Intent gets filled on mainnet
     * 3. Attacker takes same signature and replays it on Polygon (chainId 137)
     * 4. Intent gets filled again on Polygon (double-spend!)
     * 5. User loses funds on both chains
     */
}
