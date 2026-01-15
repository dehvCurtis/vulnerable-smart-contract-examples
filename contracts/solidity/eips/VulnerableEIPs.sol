// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableEIPs
 * @notice Test contracts for EIP/ERC standard vulnerabilities
 * @dev Intentionally vulnerable for testing SolidityDefend EIP detectors
 */

// ============================================================================
// EIP-7702: Set EOA Account Code
// ============================================================================

/// @notice ❌ VULNERABLE: EIP-7702 delegate with missing access control
contract VulnerableEIP7702Delegate {
    address public owner;
    mapping(address => uint256) public balances;

    // ❌ VULNERABILITY 1: No access control on execute!
    // Anyone can call this after EOA delegates to this contract
    function execute(address target, bytes calldata data) external payable {
        // ❌ Missing: require(msg.sender == owner, "Not authorized");
        (bool success, ) = target.call{value: msg.value}(data);
        require(success, "Call failed");
    }

    // ❌ VULNERABILITY 2: Storage collision with EOA state
    // EOA may have data at these slots already!
    function setOwner(address _owner) external {
        owner = _owner; // ❌ Slot 0 collision risk
    }

    // ❌ VULNERABILITY 3: tx.origin bypass
    function withdraw(uint256 amount) external {
        // ❌ Uses tx.origin instead of msg.sender
        // With EIP-7702, EOA delegates, tx.origin ≠ contract address
        require(balances[tx.origin] >= amount, "Insufficient balance");
        balances[tx.origin] -= amount;
        payable(tx.origin).transfer(amount);
    }
}

/// @notice ❌ VULNERABLE: Malicious sweeper via EIP-7702
contract VulnerableEIP7702Sweeper {
    // ❌ VULNERABILITY 4: Initialization front-running
    bool public initialized;
    address public admin;

    function initialize(address _admin) external {
        // ❌ Anyone can initialize if not yet initialized!
        // Front-runner can claim admin before legitimate user
        require(!initialized, "Already initialized");
        admin = _admin;
        initialized = true;
    }

    // ❌ VULNERABILITY 5: Batch phishing
    // Malicious operator tricks users into delegating to this contract
    function batchTransfer(address[] calldata tokens, address to) external {
        // ❌ After user delegates EOA to this contract, sweeps all tokens!
        for (uint256 i = 0; i < tokens.length; i++) {
            IERC20 token = IERC20(tokens[i]);
            uint256 balance = token.balanceOf(msg.sender);
            token.transferFrom(msg.sender, to, balance); // ❌ Sweeps funds!
        }
    }

    // ❌ VULNERABILITY 6: Delegate address not validated
    function delegateCall(address target, bytes calldata data) external {
        // ❌ No validation of target address!
        // Can call malicious contracts
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }
}

// ============================================================================
// ERC-7821: Minimal Batch Executor
// ============================================================================

interface IERC7821 {
    struct Call {
        address target;
        bytes data;
        uint256 value;
    }

    function execute(Call[] calldata calls) external payable returns (bytes[] memory);
}

/// @notice ❌ VULNERABLE: ERC-7821 batch executor without authorization
contract VulnerableERC7821Executor is IERC7821 {
    // ❌ VULNERABILITY 1: No authorization check
    function execute(Call[] calldata calls) external payable returns (bytes[] memory) {
        bytes[] memory results = new bytes[](calls.length);

        for (uint256 i = 0; i < calls.length; i++) {
            // ❌ No check on who can execute batches!
            // ❌ No validation of target addresses!
            (bool success, bytes memory result) = calls[i].target.call{value: calls[i].value}(
                calls[i].data
            );
            require(success, "Call failed");
            results[i] = result;
        }

        return results;
    }

    // ❌ VULNERABILITY 2: msg.sender validation missing
    function batchApprove(address[] calldata tokens, address spender, uint256 amount) external {
        // ❌ Approves tokens on behalf of msg.sender without validation!
        // Should verify msg.sender has authority
        for (uint256 i = 0; i < tokens.length; i++) {
            IERC20(tokens[i]).approve(spender, amount);
        }
    }

    // ❌ VULNERABILITY 3: No replay protection
    function executeSigned(
        Call[] calldata calls,
        bytes calldata signature
    ) external payable returns (bytes[] memory) {
        // ❌ No nonce tracking!
        // Same signature can be replayed multiple times
        bytes32 hash = keccak256(abi.encode(calls));
        address signer = recoverSigner(hash, signature);

        // Execute without checking if already executed
        bytes[] memory results = new bytes[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            (bool success, bytes memory result) = calls[i].target.call{value: calls[i].value}(
                calls[i].data
            );
            require(success, "Call failed");
            results[i] = result;
        }

        return results;
    }

    function recoverSigner(bytes32 hash, bytes memory signature) internal pure returns (address) {
        // Simplified recovery
        return address(0); // ❌ Stub
    }
}

/// @notice ❌ VULNERABLE: Token approval in batch operations
contract VulnerableERC7821TokenApproval {
    // ❌ VULNERABILITY 4: Unlimited approvals in batch
    function batchTransferFrom(
        address[] calldata tokens,
        address from,
        address to,
        uint256[] calldata amounts
    ) external {
        require(tokens.length == amounts.length, "Length mismatch");

        for (uint256 i = 0; i < tokens.length; i++) {
            IERC20 token = IERC20(tokens[i]);

            // ❌ First approves unlimited amount!
            token.approve(address(this), type(uint256).max);

            // Then transfers
            token.transferFrom(from, to, amounts[i]);
        }
    }

    // ❌ VULNERABILITY 5: No validation of token addresses
    function batchCall(address[] calldata targets, bytes[] calldata data) external {
        // ❌ Can call any contract, including malicious tokens!
        for (uint256 i = 0; i < targets.length; i++) {
            (bool success, ) = targets[i].call(data[i]);
            require(success, "Call failed");
        }
    }
}

// ============================================================================
// EIP-2612: Permit (Gasless Approvals)
// ============================================================================

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
}

/// @notice ❌ VULNERABLE: Permit signature exploitation
contract VulnerablePermitToken {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public nonces;
    mapping(address => mapping(address => uint256)) public allowance;

    // ❌ VULNERABILITY 1: Permit front-running
    function deposit(address token, uint256 amount) external {
        IERC20Permit(token).permit(
            msg.sender,
            address(this),
            amount,
            block.timestamp + 1 hours,
            0, 0, bytes32(0), bytes32(0) // ❌ Dummy signature
        );

        // ❌ Attacker can front-run the permit transaction
        // Use the permit themselves before this tx executes
        IERC20(token).transferFrom(msg.sender, address(this), amount);
    }

    // ❌ VULNERABILITY 2: No deadline validation
    function permitAndTransfer(
        address owner,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // ❌ Doesn't check if deadline has passed!
        // Old signatures can be reused
        _permit(owner, msg.sender, value, deadline, v, r, s);

        IERC20(address(this)).transferFrom(owner, msg.sender, value);
    }

    function _permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        // ❌ Missing: require(deadline >= block.timestamp, "Expired");

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                owner,
                spender,
                value,
                nonces[owner]++,
                deadline
            )
        );

        // Simplified signature verification (vulnerable)
        allowance[owner][spender] = value;
    }

    // ❌ VULNERABILITY 3: Signature malleability
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // ❌ Doesn't check signature malleability!
        // ECDSA signatures can be modified (s -> -s mod n)
        // Same signer, different signature → replay possible

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                keccak256("EIP712Domain"),
                keccak256(abi.encode(owner, spender, value, nonces[owner]++, deadline))
            )
        );

        address recoveredAddress = ecrecover(digest, v, r, s);
        require(recoveredAddress == owner, "Invalid signature");

        allowance[owner][spender] = value;
    }
}

// ============================================================================
// ERC-777: Token with Hooks
// ============================================================================

interface IERC777Recipient {
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external;
}

/// @notice ❌ VULNERABLE: ERC-777 reentrancy via hooks
contract VulnerableERC777 {
    mapping(address => uint256) public balances;

    // ❌ VULNERABILITY 1: Reentrancy via tokensReceived hook
    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        balances[to] += amount;

        // ❌ External call BEFORE state finalization!
        // Recipient can reenter via tokensReceived hook
        if (isContract(to)) {
            IERC777Recipient(to).tokensReceived(
                msg.sender,
                msg.sender,
                to,
                amount,
                "",
                ""
            );
        }

        // ❌ More state updates after external call - vulnerable!
        emit Transfer(msg.sender, to, amount);
    }

    // ❌ VULNERABILITY 2: Operator reentrancy
    function operatorSend(
        address from,
        address to,
        uint256 amount
    ) external {
        // ❌ No reentrancy guard!
        balances[from] -= amount;
        balances[to] += amount;

        // Hook calls during state changes
        if (isContract(from)) {
            IERC777Recipient(from).tokensReceived(msg.sender, from, to, amount, "", "");
        }
        if (isContract(to)) {
            IERC777Recipient(to).tokensReceived(msg.sender, from, to, amount, "", "");
        }
    }

    function isContract(address account) internal view returns (bool) {
        return account.code.length > 0;
    }

    event Transfer(address indexed from, address indexed to, uint256 value);
}

// ============================================================================
// ERC-1155: Multi-Token Standard
// ============================================================================

/// @notice ❌ VULNERABLE: ERC-1155 batch validation bypass
contract VulnerableERC1155 {
    mapping(uint256 => mapping(address => uint256)) public balances;

    // ❌ VULNERABILITY 1: Missing batch array validation
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) external {
        // ❌ No validation that ids.length == amounts.length!
        // Can cause index out of bounds or incorrect transfers

        for (uint256 i = 0; i < ids.length; i++) {
            uint256 id = ids[i];
            uint256 amount = amounts[i]; // ❌ May be out of bounds!

            require(balances[id][from] >= amount, "Insufficient balance");
            balances[id][from] -= amount;
            balances[id][to] += amount;
        }

        // ❌ Missing hook call for onERC1155BatchReceived
    }

    // ❌ VULNERABILITY 2: No hook return value validation
    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) external {
        balances[id][from] -= amount;
        balances[id][to] += amount;

        if (to.code.length > 0) {
            // ❌ Doesn't validate return value!
            // Should check returns ERC1155TokenReceiver.onERC1155Received.selector
            (bool success, ) = to.call(
                abi.encodeWithSignature(
                    "onERC1155Received(address,address,uint256,uint256,bytes)",
                    msg.sender, from, id, amount, data
                )
            );
            // ❌ Only checks success, not return value
            require(success, "Receiver rejected");
        }
    }
}

// ============================================================================
// EIP-1271: Contract Signature Validation
// ============================================================================

interface IERC1271 {
    function isValidSignature(
        bytes32 hash,
        bytes memory signature
    ) external view returns (bytes4 magicValue);
}

/// @notice ❌ VULNERABLE: EIP-1271 signature validation bypass
contract VulnerableERC1271Wallet is IERC1271 {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    // ❌ VULNERABILITY 1: Weak signature validation
    function isValidSignature(
        bytes32 hash,
        bytes memory signature
    ) external view returns (bytes4) {
        // ❌ Always returns valid!
        // No actual signature verification
        return 0x1626ba7e; // EIP-1271 magic value
    }

    // ❌ VULNERABILITY 2: No nonce validation
    function executeWithSignature(
        address target,
        bytes calldata data,
        bytes memory signature
    ) external {
        bytes32 hash = keccak256(abi.encode(target, data));

        // ❌ Calls isValidSignature but doesn't enforce nonce
        // Same signature can be replayed!
        require(
            this.isValidSignature(hash, signature) == 0x1626ba7e,
            "Invalid signature"
        );

        (bool success, ) = target.call(data);
        require(success, "Call failed");
    }
}

// ============================================================================
// SECURE IMPLEMENTATIONS
// ============================================================================

/// @notice ✅ SECURE: EIP-7702 delegate with proper controls
contract SecureEIP7702Delegate {
    // ✅ Use EIP-7201 namespaced storage to avoid collisions
    bytes32 private constant STORAGE_LOCATION =
        keccak256("myprotocol.delegate.storage");

    struct DelegateStorage {
        address owner;
        mapping(address => uint256) balances;
        bool initialized;
    }

    function _getStorage() private pure returns (DelegateStorage storage $) {
        assembly { $.slot := STORAGE_LOCATION }
    }

    // ✅ Proper initialization with access control
    function initialize(address _owner) external {
        DelegateStorage storage $ = _getStorage();
        require(!$.initialized, "Already initialized");
        require(_owner != address(0), "Zero address");
        $.owner = _owner;
        $.initialized = true;
    }

    // ✅ Access control enforced
    function execute(address target, bytes calldata data) external payable {
        DelegateStorage storage $ = _getStorage();
        require(msg.sender == $.owner, "Not authorized");

        (bool success, ) = target.call{value: msg.value}(data);
        require(success, "Call failed");
    }

    // ✅ Uses msg.sender not tx.origin
    function withdraw(uint256 amount) external {
        DelegateStorage storage $ = _getStorage();
        require($.balances[msg.sender] >= amount, "Insufficient");
        $.balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}

/// @notice ✅ SECURE: ERC-7821 with authorization and replay protection
contract SecureERC7821Executor {
    mapping(address => uint256) public nonces;
    mapping(address => bool) public authorizedExecutors;

    struct Call {
        address target;
        bytes data;
        uint256 value;
    }

    // ✅ Authorization required
    modifier onlyAuthorized() {
        require(authorizedExecutors[msg.sender], "Not authorized");
        _;
    }

    // ✅ Replay protection with nonces
    function executeWithSignature(
        Call[] calldata calls,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external payable returns (bytes[] memory) {
        require(deadline >= block.timestamp, "Expired");
        require(nonce == nonces[msg.sender]++, "Invalid nonce");

        bytes32 hash = keccak256(abi.encode(calls, nonce, deadline));
        address signer = recoverSigner(hash, signature);
        require(authorizedExecutors[signer], "Not authorized");

        return _executeCalls(calls);
    }

    function _executeCalls(Call[] calldata calls) private returns (bytes[] memory) {
        bytes[] memory results = new bytes[](calls.length);

        for (uint256 i = 0; i < calls.length; i++) {
            // ✅ Validate target address
            require(calls[i].target != address(0), "Zero address");

            (bool success, bytes memory result) = calls[i].target.call{
                value: calls[i].value
            }(calls[i].data);

            require(success, "Call failed");
            results[i] = result;
        }

        return results;
    }

    function recoverSigner(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address) {
        // Proper signature recovery
        return address(0); // Stub
    }
}

// ============================================================================
// INTERFACES
// ============================================================================

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
