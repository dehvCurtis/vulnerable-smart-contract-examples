// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableBridgeTokenMinting
 * @notice Test contract for bridge token minting vulnerabilities
 *
 * DETECTORS TO TEST:
 * - bridge-token-mint-control (Critical)
 * - missing-access-modifiers (Critical)
 *
 * VULNERABILITIES:
 * 1. Unrestricted token minting (anyone can mint)
 * 2. Minting without message verification
 * 3. Minting without amount limits
 * 4. Missing access control on mint functions
 * 5. No burn validation on withdrawal
 * 6. Supply manipulation via bridge
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/**
 * @notice Vulnerable bridge token with unrestricted minting
 */
contract VulnerableBridgeTokenNoAccess {
    string public name = "Bridge Token";
    string public symbol = "BRIDGE";
    uint8 public decimals = 18;

    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Mint(address indexed to, uint256 amount);

    // ❌ VULNERABILITY 1: Unrestricted minting (bridge-token-mint-control)
    // Anyone can call this and mint unlimited tokens!
    function mint(address to, uint256 amount) external {
        // ❌ No access control!
        // ❌ No require(msg.sender == bridge)
        // ❌ No onlyBridge modifier!

        balanceOf[to] += amount;
        totalSupply += amount;

        emit Mint(to, amount);
        emit Transfer(address(0), to, amount);
    }

    // ❌ VULNERABILITY 2: Public mint function (bridge-token-mint-control)
    function issue(address recipient, uint256 value) public {
        // ❌ Public visibility allows anyone to mint!
        balanceOf[recipient] += value;
        totalSupply += value;

        emit Mint(recipient, value);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");

        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;

        emit Transfer(msg.sender, to, amount);
        return true;
    }
}

/**
 * @notice Bridge token with access control but no message verification
 */
contract VulnerableBridgeTokenNoVerification {
    string public name = "Bridge Token";
    string public symbol = "BRIDGE";

    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    address public bridge;

    constructor() {
        bridge = msg.sender;
    }

    modifier onlyBridge() {
        require(msg.sender == bridge, "Not bridge");
        _;
    }

    // ❌ VULNERABILITY 3: No message verification (bridge-token-mint-control)
    // Has access control but doesn't verify cross-chain message!
    function mint(address to, uint256 amount) external onlyBridge {
        // ✅ Has access control (onlyBridge)
        // ❌ But no message verification!
        // ❌ No signature validation
        // ❌ No proof validation
        // ❌ No replay protection

        // Should require:
        // - verifyMessage(messageHash, proof)
        // - require(!processed[messageHash])
        // - processed[messageHash] = true

        balanceOf[to] += amount;
        totalSupply += amount;
    }

    // ❌ VULNERABILITY 4: Mint with signature but no validation (bridge-token-mint-control)
    function mintWithSignature(
        address to,
        uint256 amount,
        bytes calldata signature // ❌ signature parameter but NOT validated!
    ) external onlyBridge {
        // ❌ Signature parameter exists but is completely ignored!
        // ❌ No ecrecover or verification logic!

        balanceOf[to] += amount;
        totalSupply += amount;
    }

    // ❌ VULNERABILITY 5: Mint with proof but no validation (bridge-token-mint-control)
    function mintWithProof(
        address to,
        uint256 amount,
        bytes32 messageHash,
        bytes32[] calldata proof // ❌ proof parameter but NOT validated!
    ) external onlyBridge {
        // ❌ Proof parameter exists but is NOT verified!
        // ❌ No Merkle proof validation!
        // ❌ messageHash not checked against anything!

        balanceOf[to] += amount;
        totalSupply += amount;
    }
}

/**
 * @notice Bridge token without minting limits
 */
contract VulnerableBridgeTokenNoLimits {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    address public bridge;
    mapping(bytes32 => bool) public processedMessages;

    constructor() {
        bridge = msg.sender;
    }

    modifier onlyBridge() {
        require(msg.sender == bridge, "Not bridge");
        _;
    }

    // ❌ VULNERABILITY 6: No amount limits (bridge-token-mint-control)
    function mint(
        address to,
        uint256 amount,
        bytes32 messageHash,
        bytes32[] calldata proof
    ) external onlyBridge {
        // ✅ Has access control
        require(!processedMessages[messageHash], "Already processed");

        // ✅ Validates proof (assume verifyProof is implemented correctly)
        require(verifyProof(messageHash, proof), "Invalid proof");

        processedMessages[messageHash] = true;

        // ❌ No amount limits!
        // ❌ Attacker can mint MAX_UINT256 tokens in single transaction!
        // Should have: require(amount <= MAX_MINT_AMOUNT)

        balanceOf[to] += amount;
        totalSupply += amount;
    }

    // ❌ VULNERABILITY 7: No daily/per-transaction limits
    function mintNoRateLimit(
        address to,
        uint256 amount,
        bytes32 messageHash,
        bytes32[] calldata proof
    ) external onlyBridge {
        require(!processedMessages[messageHash], "Already processed");
        require(verifyProof(messageHash, proof), "Invalid proof");

        processedMessages[messageHash] = true;

        // ❌ No rate limiting!
        // ❌ No daily mint cap!
        // ❌ Can drain all liquidity in single block!

        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function verifyProof(bytes32 messageHash, bytes32[] calldata proof)
        internal
        pure
        returns (bool)
    {
        // Placeholder - assume working proof verification
        return proof.length > 0;
    }
}

/**
 * @notice Vulnerable bridge with no burn validation
 */
contract VulnerableBridgeNoBurnValidation {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    address public bridge;

    event BridgeTransfer(address indexed from, uint256 amount, uint256 destinationChain);

    constructor() {
        bridge = msg.sender;
    }

    // ❌ VULNERABILITY 8: No validation on bridge withdrawal
    function bridgeOut(uint256 amount, uint256 destinationChain) external {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");

        // ❌ Burns tokens but no validation!
        // ❌ No minimum amount check
        // ❌ No maximum amount check
        // ❌ No validation of destinationChain
        // ❌ No confirmation of successful bridge message

        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;

        emit BridgeTransfer(msg.sender, amount, destinationChain);

        // If bridge message fails, tokens are permanently lost!
    }

    // ❌ VULNERABILITY 9: Burn without emit message
    function burn(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount);

        // ❌ Burns tokens but doesn't emit bridge message!
        // Tokens destroyed without corresponding mint on destination chain!

        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == bridge);
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}

/**
 * @notice Vulnerable bridge with supply manipulation
 */
contract VulnerableBridgeSupplyManipulation {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    address public bridge;
    mapping(bytes32 => bool) public processedMessages;

    constructor() {
        bridge = msg.sender;
    }

    // ❌ VULNERABILITY 10: Mint without checking totalSupply cap
    function mint(
        address to,
        uint256 amount,
        bytes32 messageHash,
        bytes32[] calldata proof
    ) external {
        require(msg.sender == bridge);
        require(!processedMessages[messageHash]);
        require(verifyProof(messageHash, proof));

        processedMessages[messageHash] = true;

        // ❌ No check against maximum supply!
        // ❌ Can mint beyond intended supply cap!
        // Should have: require(totalSupply + amount <= MAX_SUPPLY)

        balanceOf[to] += amount;
        totalSupply += amount;
    }

    // ❌ VULNERABILITY 11: Burn with underflow potential
    function burn(address from, uint256 amount) external {
        require(msg.sender == bridge);

        // ❌ Unchecked arithmetic could underflow totalSupply!
        // If amount > totalSupply, wraps around to MAX_UINT256!

        unchecked {
            totalSupply -= amount; // ❌ Unchecked underflow!
        }

        balanceOf[from] -= amount;
    }

    function verifyProof(bytes32 messageHash, bytes32[] calldata proof)
        internal
        pure
        returns (bool)
    {
        return proof.length > 0;
    }
}

/**
 * @notice Bridge with replay vulnerability in mint
 */
contract VulnerableBridgeMintReplay {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    address public bridge;

    constructor() {
        bridge = msg.sender;
    }

    // ❌ VULNERABILITY 12: Mint without replay protection (bridge-token-mint-control)
    function mint(
        address to,
        uint256 amount,
        bytes32 messageHash,
        bytes calldata signature
    ) external {
        require(msg.sender == bridge);

        // ❌ No replay protection!
        // ❌ Same message can be minted multiple times!
        // Should have: mapping(bytes32 => bool) processed

        require(verifySignature(messageHash, signature), "Invalid signature");

        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function verifySignature(bytes32 hash, bytes calldata signature)
        internal
        pure
        returns (bool)
    {
        // Placeholder - assume working signature verification
        return signature.length == 65;
    }
}

/**
 * @notice Secure bridge token implementation
 */
contract SecureBridgeToken {
    string public constant name = "Secure Bridge Token";
    string public constant symbol = "SECURE";
    uint8 public constant decimals = 18;

    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    address public immutable bridge;
    bytes32 public stateRoot;
    mapping(bytes32 => bool) public processedMessages;

    uint256 public constant MAX_MINT_PER_TX = 1_000_000 ether;
    uint256 public constant MAX_SUPPLY = 100_000_000 ether;

    event Mint(address indexed to, uint256 amount, bytes32 messageHash);
    event Burn(address indexed from, uint256 amount, uint256 destinationChain);

    constructor(address _bridge) {
        bridge = _bridge;
    }

    modifier onlyBridge() {
        require(msg.sender == bridge, "Not authorized bridge");
        _;
    }

    function updateStateRoot(bytes32 newRoot) external onlyBridge {
        stateRoot = newRoot;
    }

    // ✅ Secure mint implementation
    function mint(
        address to,
        uint256 amount,
        bytes32 messageHash,
        bytes32[] calldata merkleProof,
        bytes calldata signature
    ) external onlyBridge {
        // ✅ 1. Check replay protection
        require(!processedMessages[messageHash], "Already processed");

        // ✅ 2. Validate amount limits
        require(amount > 0, "Amount must be positive");
        require(amount <= MAX_MINT_PER_TX, "Exceeds per-tx limit");
        require(totalSupply + amount <= MAX_SUPPLY, "Exceeds max supply");

        // ✅ 3. Verify Merkle proof
        require(verifyMerkleProof(messageHash, merkleProof), "Invalid proof");

        // ✅ 4. Verify signature
        require(verifySignature(messageHash, signature), "Invalid signature");

        // ✅ 5. Mark as processed BEFORE state changes
        processedMessages[messageHash] = true;

        // ✅ 6. Update state
        balanceOf[to] += amount;
        totalSupply += amount;

        emit Mint(to, amount, messageHash);
    }

    function burn(uint256 amount, uint256 destinationChain) external {
        require(amount > 0, "Amount must be positive");
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        require(destinationChain != block.chainid, "Invalid destination");

        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;

        emit Burn(msg.sender, amount, destinationChain);
    }

    function verifyMerkleProof(bytes32 leaf, bytes32[] calldata proof)
        internal
        view
        returns (bool)
    {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];

            if (computedHash <= proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }

        return computedHash == stateRoot;
    }

    function verifySignature(bytes32 hash, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        if (signature.length != 65) return false;

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );

        address signer = ecrecover(ethSignedHash, v, r, s);
        return signer == bridge;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");

        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;

        return true;
    }
}
