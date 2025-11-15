// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableZKProofs
 * @notice Test contracts for Zero-Knowledge proof vulnerabilities
 * @dev Intentionally vulnerable for testing SolidityDefend ZK detectors
 */

// ============================================================================
// VULNERABILITY 1: ZK Proof Verification Bypass
// ============================================================================

interface IVerifier {
    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory input
    ) external view returns (bool);
}

/// @notice ❌ VULNERABLE: Proof verification can be bypassed
contract VulnerableZKProofBypass {
    IVerifier public verifier;
    mapping(address => uint256) public balances;

    // ❌ VULNERABILITY 1: Verification can be disabled
    bool public verificationEnabled = true;

    constructor(address _verifier) {
        verifier = IVerifier(_verifier);
    }

    /// @notice ❌ Admin can disable verification entirely!
    function disableVerification() external {
        verificationEnabled = false;
    }

    /// @notice ❌ VULNERABILITY 2: Verification bypass via conditional
    function withdraw(
        uint256 amount,
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory input
    ) external {
        // ❌ Verification can be bypassed by admin!
        if (verificationEnabled) {
            require(verifier.verifyProof(a, b, c, input), "Invalid proof");
        }

        // ❌ Withdrawal proceeds even if verification disabled
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    /// @notice ❌ VULNERABILITY 3: No proof verification at all
    function emergencyWithdraw(uint256 amount) external {
        // ❌ No proof required for "emergency" withdrawals!
        // Attacker can drain funds without valid proof
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    /// @notice ❌ VULNERABILITY 4: Weak proof validation (zero proof accepted)
    function withdrawWithWeakCheck(
        uint256 amount,
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory input
    ) external {
        // ❌ Accepts zero values as valid proof!
        if (a[0] != 0 || a[1] != 0) {
            require(verifier.verifyProof(a, b, c, input), "Invalid proof");
        }
        // Zero proof bypasses verification

        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}

// ============================================================================
// VULNERABILITY 2: Under-Constrained ZK Circuit
// ============================================================================

/// @notice ❌ VULNERABLE: Circuit lacks sufficient constraints
contract VulnerableUnderConstrainedCircuit {
    IVerifier public verifier;

    struct PrivateTransfer {
        bytes32 commitment;
        bytes32 nullifier;
        uint256 amount;
    }

    mapping(bytes32 => bool) public usedNullifiers;
    mapping(bytes32 => bool) public commitments;

    constructor(address _verifier) {
        verifier = IVerifier(_verifier);
    }

    /// @notice ❌ VULNERABILITY 1: Missing nullifier constraint
    /// Circuit doesn't constrain nullifier = hash(commitment, secret)
    /// Attacker can use same commitment with different nullifiers!
    function privateTransfer(
        bytes32 commitment,
        bytes32 nullifier,
        uint256 amount,
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory input
    ) external {
        // ❌ Circuit doesn't enforce: nullifier = hash(commitment, secret)
        // Attacker can reuse commitment with new nullifier
        require(!usedNullifiers[nullifier], "Nullifier used");
        require(commitments[commitment], "Invalid commitment");

        // Verify proof (but circuit is under-constrained!)
        require(verifier.verifyProof(a, b, c, input), "Invalid proof");

        usedNullifiers[nullifier] = true;

        // Double-spending possible: same commitment, different nullifiers
        payable(msg.sender).transfer(amount);
    }

    /// @notice ❌ VULNERABILITY 2: Missing range constraint
    /// Circuit doesn't constrain amount to valid range
    /// Attacker can prove negative amounts or overflow!
    function mint(
        uint256 amount,
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory input
    ) external {
        // ❌ Circuit doesn't enforce: 0 < amount < MAX_AMOUNT
        // Attacker can prove amount = type(uint256).max
        require(verifier.verifyProof(a, b, c, input), "Invalid proof");

        // Mint without proper range constraint
        bytes32 commitment = keccak256(abi.encodePacked(msg.sender, amount));
        commitments[commitment] = true;
    }

    /// @notice ❌ VULNERABILITY 3: Missing input consistency
    /// Circuit doesn't enforce public inputs match on-chain values
    function withdraw(
        address recipient,
        uint256 amount,
        bytes32 merkleRoot,
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory input
    ) external {
        // ❌ Circuit doesn't constrain: input[0] == hash(recipient, amount)
        // Attacker can prove for different recipient/amount
        require(verifier.verifyProof(a, b, c, input), "Invalid proof");

        // Withdraws to attacker even if proof is for different recipient
        payable(recipient).transfer(amount);
    }
}

// ============================================================================
// VULNERABILITY 3: ZK Proof Malleability
// ============================================================================

/// @notice ❌ VULNERABLE: Same witness can generate multiple valid proofs
contract VulnerableProofMalleability {
    IVerifier public verifier;

    mapping(bytes32 => bool) public executedProofs;

    constructor(address _verifier) {
        verifier = IVerifier(_verifier);
    }

    /// @notice ❌ VULNERABILITY 1: Proof replay via malleability
    /// Same witness can generate multiple valid proofs
    /// Proof hash doesn't include all elements
    function claimReward(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory input
    ) external {
        // ❌ Incomplete proof hash - doesn't include 'b' matrix
        bytes32 proofHash = keccak256(abi.encodePacked(a, c, input));
        require(!executedProofs[proofHash], "Proof used");

        require(verifier.verifyProof(a, b, c, input), "Invalid proof");

        executedProofs[proofHash] = true;

        // ❌ Attacker can modify 'b' matrix for same witness
        // Generate multiple valid proofs from one secret
        payable(msg.sender).transfer(1 ether);
    }

    /// @notice ❌ VULNERABILITY 2: Missing commitment to random
    /// Circuit doesn't bind proof to unique randomness
    function vote(
        uint256 proposalId,
        bool support,
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory input
    ) external {
        // ❌ Proof doesn't include nonce/randomness
        // Same vote can be submitted multiple times
        require(verifier.verifyProof(a, b, c, input), "Invalid proof");

        // Vote recorded multiple times with malleable proofs
        // No unique identifier for this specific proof
    }

    /// @notice ❌ VULNERABILITY 3: Public input substitution
    /// Proof valid for any public input (weak binding)
    function transferPrivate(
        address to,
        uint256 amount,
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory input
    ) external {
        // ❌ Circuit weakly binds public inputs
        // Attacker can substitute 'to' address in proof
        require(verifier.verifyProof(a, b, c, input), "Invalid proof");

        // Transfer to wrong recipient via malleability
        payable(to).transfer(amount);
    }
}

// ============================================================================
// VULNERABILITY 4: Trusted Setup Bypass
// ============================================================================

/// @notice ❌ VULNERABLE: Trusted setup parameters can be manipulated
contract VulnerableTrustedSetup {
    struct VerificationKey {
        uint256[2] alpha;
        uint256[2][2] beta;
        uint256[2][2] gamma;
        uint256[2][2] delta;
    }

    VerificationKey public vk;
    bool public setupComplete;

    /// @notice ❌ VULNERABILITY 1: No access control on setup
    /// Anyone can overwrite trusted setup parameters!
    function initializeVerificationKey(
        uint256[2] memory alpha,
        uint256[2][2] memory beta,
        uint256[2][2] memory gamma,
        uint256[2][2] memory delta
    ) external {
        // ❌ No access control! Anyone can set malicious parameters
        vk.alpha = alpha;
        vk.beta = beta;
        vk.gamma = gamma;
        vk.delta = delta;
        setupComplete = true;
    }

    /// @notice ❌ VULNERABILITY 2: Setup can be changed after deployment
    function updateSetup(
        uint256[2] memory alpha,
        uint256[2][2] memory beta,
        uint256[2][2] memory gamma,
        uint256[2][2] memory delta
    ) external {
        // ❌ Trusted setup mutable! Attacker can change parameters
        // Previous valid proofs become invalid, attacker proofs valid
        vk.alpha = alpha;
        vk.beta = beta;
        vk.gamma = gamma;
        vk.delta = delta;
    }

    /// @notice ❌ VULNERABILITY 3: No validation of setup parameters
    function setVerificationKey(VerificationKey memory _vk) external {
        // ❌ No checks if parameters are valid elliptic curve points
        // ❌ No checks if parameters are on correct subgroup
        // Attacker can set invalid parameters to bypass verification
        vk = _vk;
        setupComplete = true;
    }

    /// @notice ❌ VULNERABILITY 4: Using setup without initialization
    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory input
    ) external view returns (bool) {
        // ❌ No check if setup is complete!
        // Verification with uninitialized parameters (all zeros)
        // All proofs may pass with zero key

        // Simplified verification (vulnerable)
        return true; // ❌ Always returns true if vk is zeros
    }
}

// ============================================================================
// VULNERABILITY 5: Recursive Proof Validation
// ============================================================================

/// @notice ❌ VULNERABLE: Recursive proof verification issues
contract VulnerableRecursiveProofs {
    IVerifier public innerVerifier;
    IVerifier public outerVerifier;

    uint256 public constant MAX_RECURSION_DEPTH = 10;

    struct RecursiveProof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
        uint256[2] input;
        uint256 depth;
    }

    constructor(address _innerVerifier, address _outerVerifier) {
        innerVerifier = IVerifier(_innerVerifier);
        outerVerifier = IVerifier(_outerVerifier);
    }

    /// @notice ❌ VULNERABILITY 1: No recursion depth validation
    /// Attacker can create infinite recursion chain
    function verifyRecursive(RecursiveProof[] memory proofs) external view returns (bool) {
        // ❌ No check on array length or depth
        // Stack overflow possible with deep recursion
        for (uint256 i = 0; i < proofs.length; i++) {
            RecursiveProof memory proof = proofs[i];

            // ❌ No depth limit enforced!
            // Attacker can nest proofs infinitely
            if (proof.depth > 0) {
                // Recursive verification without bounds
                innerVerifier.verifyProof(proof.a, proof.b, proof.c, proof.input);
            }
        }

        return true;
    }

    /// @notice ❌ VULNERABILITY 2: Missing inner proof validation
    /// Outer proof doesn't verify inner proof validity
    function verifyNested(
        uint256[2] memory outerA,
        uint256[2][2] memory outerB,
        uint256[2] memory outerC,
        uint256[2] memory outerInput,
        uint256[2] memory innerA,
        uint256[2][2] memory innerB,
        uint256[2] memory innerC,
        uint256[2] memory innerInput
    ) external view returns (bool) {
        // ❌ Verifies outer proof but doesn't check if it commits to inner proof
        bool outerValid = outerVerifier.verifyProof(outerA, outerB, outerC, outerInput);

        // ❌ Inner proof verified separately, no binding!
        // Attacker can use unrelated inner and outer proofs
        bool innerValid = innerVerifier.verifyProof(innerA, innerB, innerC, innerInput);

        return outerValid && innerValid;
    }

    /// @notice ❌ VULNERABILITY 3: Proof aggregation without uniqueness
    function verifyAggregated(
        uint256[2][] memory aProofs,
        uint256[2][2][] memory bProofs,
        uint256[2][] memory cProofs,
        uint256[2][] memory inputs
    ) external view returns (bool) {
        // ❌ No check for duplicate proofs in aggregation
        // Attacker can submit same proof multiple times
        // Claims N rewards with 1 valid proof

        for (uint256 i = 0; i < aProofs.length; i++) {
            bool valid = innerVerifier.verifyProof(
                aProofs[i],
                bProofs[i],
                cProofs[i],
                inputs[i]
            );

            if (!valid) {
                return false;
            }
        }

        return true;
    }
}

// ============================================================================
// VULNERABILITY 6: ZK Privacy Leakage
// ============================================================================

/// @notice ❌ VULNERABLE: Private data leaked through public inputs/events
contract VulnerableZKPrivacy {
    IVerifier public verifier;

    event PrivateTransfer(address indexed from, address indexed to, uint256 amount);
    event ProofSubmitted(bytes32 commitment, bytes32 nullifier, uint256 value);

    constructor(address _verifier) {
        verifier = IVerifier(_verifier);
    }

    /// @notice ❌ VULNERABILITY 1: Emitting private data in events
    function transferPrivate(
        address to,
        uint256 amount,
        uint256 secret,
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory input
    ) external {
        require(verifier.verifyProof(a, b, c, input), "Invalid proof");

        // ❌ Emits private transfer details publicly!
        // All "private" transfers can be tracked
        emit PrivateTransfer(msg.sender, to, amount);

        payable(to).transfer(amount);
    }

    /// @notice ❌ VULNERABILITY 2: Storing commitments predictably
    mapping(address => bytes32[]) public userCommitments; // ❌ Public mapping!

    function deposit(
        uint256 amount,
        bytes32 commitment,
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory input
    ) external {
        require(verifier.verifyProof(a, b, c, input), "Invalid proof");

        // ❌ Links user address to commitment publicly!
        // Privacy completely broken
        userCommitments[msg.sender].push(commitment);
    }

    /// @notice ❌ VULNERABILITY 3: Revealing secret through public input
    function withdraw(
        uint256 amount,
        uint256 secret, // ❌ Secret passed as public parameter!
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory input
    ) external {
        // ❌ Secret visible in transaction calldata
        bytes32 commitment = keccak256(abi.encodePacked(msg.sender, secret));

        require(verifier.verifyProof(a, b, c, input), "Invalid proof");

        payable(msg.sender).transfer(amount);
    }
}

// ============================================================================
// SECURE IMPLEMENTATION: Best Practices
// ============================================================================

/// @notice ✅ SECURE: Proper ZK proof verification
contract SecureZKProofs {
    IVerifier public immutable verifier; // ✅ Immutable verifier

    struct VerificationKey {
        uint256[2] alpha;
        uint256[2][2] beta;
        uint256[2][2] gamma;
        uint256[2][2] delta;
    }

    VerificationKey public immutable vk; // ✅ Immutable trusted setup

    mapping(bytes32 => bool) public nullifiers;
    uint256 public constant MAX_PROOF_AGE = 1 hours;

    constructor(address _verifier, VerificationKey memory _vk) {
        verifier = IVerifier(_verifier);
        vk = _vk;

        // ✅ Validate setup parameters at construction
        require(_vk.alpha[0] != 0 || _vk.alpha[1] != 0, "Invalid alpha");
    }

    /// @notice ✅ SECURE: Complete proof validation
    function secureWithdraw(
        uint256 amount,
        bytes32 nullifier,
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory input,
        uint256 timestamp
    ) external {
        // ✅ Check proof freshness (prevent old proof reuse)
        require(block.timestamp <= timestamp + MAX_PROOF_AGE, "Proof expired");

        // ✅ Check nullifier uniqueness
        require(!nullifiers[nullifier], "Nullifier used");

        // ✅ Verify proof with immutable verifier
        require(verifier.verifyProof(a, b, c, input), "Invalid proof");

        // ✅ Complete proof hash including all elements
        bytes32 proofHash = keccak256(abi.encodePacked(a, b, c, input, nullifier));

        // ✅ Mark nullifier as used
        nullifiers[nullifier] = true;

        // ✅ Transfer after all checks
        require(amount <= address(this).balance, "Insufficient balance");
        payable(msg.sender).transfer(amount);
    }

    /// @notice ✅ SECURE: Recursive proof with depth limit
    function secureRecursiveVerify(
        uint256[2][] memory aProofs,
        uint256[2][2][] memory bProofs,
        uint256[2][] memory cProofs,
        uint256[2][] memory inputs
    ) external view returns (bool) {
        // ✅ Enforce maximum recursion depth
        require(aProofs.length <= 10, "Exceeds max depth");

        // ✅ All arrays must match
        require(
            aProofs.length == bProofs.length &&
            bProofs.length == cProofs.length &&
            cProofs.length == inputs.length,
            "Length mismatch"
        );

        // ✅ Check for duplicate proofs
        for (uint256 i = 0; i < aProofs.length; i++) {
            for (uint256 j = i + 1; j < aProofs.length; j++) {
                require(
                    keccak256(abi.encodePacked(aProofs[i], cProofs[i])) !=
                    keccak256(abi.encodePacked(aProofs[j], cProofs[j])),
                    "Duplicate proof"
                );
            }

            // ✅ Verify each proof
            require(
                verifier.verifyProof(aProofs[i], bProofs[i], cProofs[i], inputs[i]),
                "Invalid proof"
            );
        }

        return true;
    }
}
