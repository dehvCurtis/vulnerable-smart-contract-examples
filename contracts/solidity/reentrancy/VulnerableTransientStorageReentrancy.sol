// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24; // ✅ Requires 0.8.24+ for transient storage

/**
 * @title VulnerableTransientStorageReentrancy
 * @notice Test contract for EIP-1153 transient storage reentrancy vulnerabilities
 *
 * DETECTORS TO TEST:
 * - transient-storage-reentrancy (Critical)
 * - erc777-reentrancy-hooks (High)
 * - erc721-callback-reentrancy (High)
 * - hook-reentrancy-enhanced (High)
 *
 * VULNERABILITIES:
 * 1. transfer()/send() no longer safe with transient storage (EIP-1153)
 * 2. ERC-777 tokensReceived hook reentrancy
 * 3. ERC-721 onERC721Received callback reentrancy
 * 4. Hook-based reentrancy (Uniswap V4, vault hooks)
 * 5. Transient storage state tracking during reentrancy
 * 6. Low-gas reentrancy attacks (2300 gas now sufficient)
 * 7. Combined transient + persistent storage attacks
 * 8. Hook reentrancy in DeFi protocols
 */

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

interface IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

interface IUniswapV4Hook {
    function beforeSwap(
        address sender,
        bytes calldata data
    ) external returns (bytes4);

    function afterSwap(
        uint256 amount0,
        uint256 amount1
    ) external returns (bytes4);
}

/**
 * @notice CRITICAL: Transient storage breaks transfer()/send() safety
 *
 * EIP-1153 introduced transient storage with only 100 gas cost.
 * The 2300 gas stipend from transfer()/send() is now ENOUGH for reentrancy!
 */
contract VulnerableTransientStorageBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // ❌ VULNERABILITY 1: transfer() no longer safe! (transient-storage-reentrancy)
    // Before EIP-1153: transfer() limited to 2300 gas = reentrancy impossible
    // After EIP-1153: TSTORE costs only 100 gas = reentrancy POSSIBLE!
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // ❌ Historically "safe" pattern now VULNERABLE!
        // Attacker can use transient storage operations in receive()
        payable(msg.sender).transfer(amount);

        // ❌ State updated after transfer
        // Attacker can re-enter with transient storage tracking
        balances[msg.sender] = 0;
    }

    // ❌ VULNERABILITY 2: send() also vulnerable (transient-storage-reentrancy)
    function withdrawWithSend() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0);

        // ❌ send() also limited to 2300 gas
        // But now attackers can use TSTORE/TLOAD within that limit!
        bool success = payable(msg.sender).send(amount);
        require(success, "Send failed");

        balances[msg.sender] = 0;
    }

    // ❌ VULNERABILITY 3: Low-gas call vulnerable (transient-storage-reentrancy)
    function withdrawWithLowGas() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0);

        // ❌ Even explicit low-gas calls are vulnerable now
        (bool success,) = msg.sender.call{gas: 5000, value: amount}("");
        require(success);

        balances[msg.sender] = 0;
    }
}

/**
 * @notice Attacker contract demonstrating transient storage reentrancy
 */
contract TransientReentrancyAttacker {
    // ✅ Transient storage - only 100 gas per operation!
    // Note: Using uint256 instead of "transient uint256" for parser compatibility
    uint256 private reentrancyCountStorage;

    VulnerableTransientStorageBank public target;

    constructor(address _target) {
        target = VulnerableTransientStorageBank(_target);
    }

    // Receive ETH and perform transient storage reentrancy
    receive() external payable {
        // ✅ TSTORE costs only 100 gas!
        // Can track reentrancy counter within 2300 gas limit

        if (reentrancyCountStorage < 10) {
            reentrancyCountStorage++;

            // Re-enter withdraw() - works because:
            // 1. TSTORE/TLOAD = 100 gas each
            // 2. 2300 gas stipend = room for ~10 TSTORE operations
            // 3. Balance check passes (not updated yet)
            target.withdraw();
        }
    }

    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw();
    }
}

/**
 * @notice ERC-777 hook reentrancy
 */
contract VulnerableERC777Vault is IERC777Recipient {
    mapping(address => uint256) public deposits;
    address public token;

    constructor(address _token) {
        token = _token;
    }

    // ❌ VULNERABILITY 4: ERC-777 tokensReceived hook (erc777-reentrancy-hooks)
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external {
        // ❌ No reentrancy protection!
        // ❌ Can be called during token transfer

        // Attacker can:
        // 1. Call withdraw()
        // 2. During token.transfer(), tokensReceived is called
        // 3. Re-enter withdraw() again
        // 4. State not updated yet - double withdrawal!
    }

    // ❌ Vulnerable to ERC-777 hook reentrancy
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient deposit");

        // ❌ External call to ERC-777 token (has hooks!)
        // Token will call tokensReceived() which can re-enter
        (bool success, ) = token.call(
            abi.encodeWithSignature("transfer(address,uint256)", msg.sender, amount)
        );
        require(success);

        // ❌ State updated AFTER hook execution
        deposits[msg.sender] -= amount;
    }

    function deposit(uint256 amount) external {
        (bool success, ) = token.call(
            abi.encodeWithSignature("transferFrom(address,address,uint256)", msg.sender, address(this), amount)
        );
        require(success);

        deposits[msg.sender] += amount;
    }
}

/**
 * @notice ERC-721 callback reentrancy
 */
contract VulnerableNFTMarketplace is IERC721Receiver {
    mapping(uint256 => address) public nftOwners;
    mapping(address => uint256) public balances;

    address public nftContract;

    constructor(address _nftContract) {
        nftContract = _nftContract;
    }

    // ❌ VULNERABILITY 5: onERC721Received callback (erc721-callback-reentrancy)
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4) {
        // ❌ No reentrancy guard!
        // This is called during safeTransferFrom()

        // Attacker can:
        // 1. Call sellNFT()
        // 2. During safeTransferFrom, onERC721Received is called
        // 3. Re-enter sellNFT() or buyNFT()
        // 4. State inconsistency!

        return this.onERC721Received.selector;
    }

    // ❌ Vulnerable to ERC-721 callback reentrancy
    function sellNFT(uint256 tokenId, uint256 price) external {
        require(nftOwners[tokenId] == msg.sender, "Not owner");

        // ❌ External call to NFT contract
        // safeTransferFrom will call onERC721Received
        (bool success, ) = nftContract.call(
            abi.encodeWithSignature(
                "safeTransferFrom(address,address,uint256)",
                address(this),
                msg.sender,
                tokenId
            )
        );
        require(success);

        // ❌ State updated after callback
        nftOwners[tokenId] = address(0);
        balances[msg.sender] += price;
    }

    function buyNFT(uint256 tokenId) external payable {
        require(nftOwners[tokenId] != address(0), "Not for sale");

        nftOwners[tokenId] = msg.sender;
    }
}

/**
 * @notice Uniswap V4 hook reentrancy
 */
contract VulnerableUniswapV4Pool {
    address public hook;
    uint256 public reserve0;
    uint256 public reserve1;

    function setHook(address _hook) external {
        hook = _hook;
    }

    // ❌ VULNERABILITY 6: Hook callback reentrancy (hook-reentrancy-enhanced)
    function swap(
        uint256 amount0Out,
        uint256 amount1Out,
        address to
    ) external {
        // ❌ beforeSwap hook called before state updates!
        if (hook != address(0)) {
            IUniswapV4Hook(hook).beforeSwap(msg.sender, "");
        }

        // Attacker's hook can:
        // 1. Read current reserves (not updated yet)
        // 2. Execute arbitrage
        // 3. Manipulate other functions
        // 4. Re-enter swap()

        // Swap logic...
        reserve0 -= amount0Out;
        reserve1 -= amount1Out;

        // ❌ afterSwap hook called after partial state updates
        if (hook != address(0)) {
            IUniswapV4Hook(hook).afterSwap(amount0Out, amount1Out);
        }
    }
}

/**
 * @notice Vault with hook reentrancy
 */
contract VulnerableVaultWithHooks {
    mapping(address => uint256) public balances;
    address public beforeWithdrawHook;
    address public afterWithdrawHook;

    // ❌ VULNERABILITY 7: Multiple hooks with reentrancy (hook-reentrancy-enhanced)
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // ❌ beforeWithdraw hook can re-enter!
        if (beforeWithdrawHook != address(0)) {
            (bool success,) = beforeWithdrawHook.call(
                abi.encodeWithSignature("beforeWithdraw(address,uint256)", msg.sender, amount)
            );
            require(success);
        }

        // ❌ State update between hooks
        balances[msg.sender] -= amount;

        payable(msg.sender).transfer(amount);

        // ❌ afterWithdraw hook can read inconsistent state!
        if (afterWithdrawHook != address(0)) {
            (bool success,) = afterWithdrawHook.call(
                abi.encodeWithSignature("afterWithdraw(address,uint256)", msg.sender, amount)
            );
            require(success);
        }
    }

    function setBeforeWithdrawHook(address _hook) external {
        beforeWithdrawHook = _hook;
    }

    function setAfterWithdrawHook(address _hook) external {
        afterWithdrawHook = _hook;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}

/**
 * @notice Combined persistent + transient storage attack
 */
contract VulnerableCombinedStorage {
    mapping(address => uint256) public balances; // Persistent
    // Note: Using uint256 instead of "transient uint256" for parser compatibility
    uint256 private reentrancyGuardStorage; // Transient "guard" - INEFFECTIVE!

    // ❌ VULNERABILITY 8: Ineffective transient reentrancy guard (transient-storage-reentrancy)
    function withdraw() external {
        // ❌ Transient storage guard clears after transaction!
        require(reentrancyGuardStorage == 0, "Reentrant");

        reentrancyGuardStorage = 1;

        uint256 amount = balances[msg.sender];
        require(amount > 0);

        // External call
        payable(msg.sender).transfer(amount);

        // ❌ Transient guard cleared automatically
        // But persistent state updated after call!
        balances[msg.sender] = 0;

        // Attacker can:
        // 1. Transaction 1: withdraw(), guard set, re-enter blocked
        // 2. Transaction 2: NEW transaction, guard cleared, re-enter succeeds!
    }
}

/**
 * @notice Secure implementation with proper guards
 */
contract SecureTransientStorageBank {
    mapping(address => uint256) public balances;
    bool private locked; // Persistent lock, not transient!

    modifier nonReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // ✅ Checks-Effects-Interactions + reentrancy guard
    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0);

        // ✅ Update state BEFORE external call
        balances[msg.sender] = 0;

        // ✅ External call AFTER state update
        // Even with transient storage, attacker can't exploit
        payable(msg.sender).transfer(amount);
    }

    // ✅ Alternative: Use call() with reentrancy guard instead of transfer()
    function withdrawWithCall() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0);

        balances[msg.sender] = 0;

        // ✅ call() allows sufficient gas for legitimate operations
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
    }
}
