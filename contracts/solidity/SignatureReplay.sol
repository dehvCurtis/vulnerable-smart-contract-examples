// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Signature Replay Vulnerability Example
 * @dev VULNERABLE - DO NOT USE IN PRODUCTION
 *
 * This contract is vulnerable to signature replay attacks where
 * a valid signature can be reused multiple times or across contracts.
 */
contract VulnerableMetaTransaction {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: No nonce or replay protection
    function metaTransfer(
        address from,
        address to,
        uint256 amount,
        bytes memory signature
    ) public {
        // VULNERABILITY: Signature can be replayed multiple times
        bytes32 messageHash = keccak256(abi.encodePacked(from, to, amount));
        bytes32 ethSignedHash = getEthSignedMessageHash(messageHash);

        require(recoverSigner(ethSignedHash, signature) == from, "Invalid signature");
        require(balances[from] >= amount, "Insufficient balance");

        balances[from] -= amount;
        balances[to] += amount;
    }

    function getEthSignedMessageHash(bytes32 _messageHash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash));
    }

    function recoverSigner(bytes32 _ethSignedHash, bytes memory _signature) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);
        return ecrecover(_ethSignedHash, v, r, s);
    }

    function splitSignature(bytes memory sig) public pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}

/**
 * @title Cross-Contract Replay Vulnerability
 * @dev Shows vulnerability where signatures work across different contracts
 */
contract VulnerableVoucherSystem {
    mapping(address => bool) public voucherUsed;
    address public verifier;

    constructor() {
        verifier = msg.sender;
    }

    // VULNERABLE: No contract address in signature
    function redeemVoucher(
        uint256 amount,
        bytes memory signature
    ) public {
        // VULNERABILITY: Same signature works on deployed copy of this contract
        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender, amount));
        bytes32 ethSignedHash = getEthSignedMessageHash(messageHash);

        address signer = recoverSigner(ethSignedHash, signature);
        require(signer == verifier, "Invalid signature");
        require(!voucherUsed[msg.sender], "Voucher already used");

        voucherUsed[msg.sender] = true;
        payable(msg.sender).transfer(amount);
    }

    function getEthSignedMessageHash(bytes32 _messageHash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash));
    }

    function recoverSigner(bytes32 _ethSignedHash, bytes memory _signature) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);
        return ecrecover(_ethSignedHash, v, r, s);
    }

    function splitSignature(bytes memory sig) public pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    receive() external payable {}
}

/**
 * @title Signature Malleability
 * @dev Shows ECDSA signature malleability vulnerability
 */
contract VulnerableSignatureChecker {
    mapping(bytes32 => bool) public signatureUsed;

    // VULNERABLE: Signature malleability not prevented
    function executeWithSignature(
        address target,
        uint256 value,
        bytes memory data,
        bytes memory signature
    ) public {
        bytes32 messageHash = keccak256(abi.encodePacked(target, value, data));
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));

        // VULNERABILITY: Signature can be modified (s -> -s mod n) to create different
        // signature with same validity, bypassing the signatureUsed check
        bytes32 sigHash = keccak256(signature);
        require(!signatureUsed[sigHash], "Signature already used");

        address signer = recoverSigner(ethSignedHash, signature);
        require(signer == target, "Invalid signature");

        signatureUsed[sigHash] = true;

        (bool success, ) = target.call{value: value}(data);
        require(success, "Execution failed");
    }

    function recoverSigner(bytes32 _ethSignedHash, bytes memory _signature) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);
        return ecrecover(_ethSignedHash, v, r, s);
    }

    function splitSignature(bytes memory sig) public pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    receive() external payable {}
}

/**
 * @title Missing Chain ID in Signature
 * @dev Shows vulnerability across different chains
 */
contract VulnerableCrossChain {
    mapping(address => uint256) public nonces;

    // VULNERABLE: No chain ID in signature
    function executeMetaTransaction(
        address user,
        address target,
        uint256 value,
        uint256 nonce,
        bytes memory signature
    ) public {
        // VULNERABILITY: Signature can be replayed on different chains (mainnet, testnet, etc.)
        bytes32 messageHash = keccak256(abi.encodePacked(user, target, value, nonce));
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));

        require(recoverSigner(ethSignedHash, signature) == user, "Invalid signature");
        require(nonces[user] == nonce, "Invalid nonce");

        nonces[user]++;

        (bool success, ) = target.call{value: value}("");
        require(success, "Transaction failed");
    }

    function recoverSigner(bytes32 _ethSignedHash, bytes memory _signature) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);
        return ecrecover(_ethSignedHash, v, r, s);
    }

    function splitSignature(bytes memory sig) public pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    receive() external payable {}
}
