// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Advanced EVM & DeFi Vulnerability Patterns
 * @notice Tests specialized advanced security detectors
 * @dev Tests: metamorphic-contract, extcodesize-bypass, uniswapv4-hook-issues,
 *             amm-liquidity-manipulation, weak-commit-reveal
 */

// =====================================================================
// 1. METAMORPHIC CONTRACT PATTERNS
// =====================================================================

/**
 * @dev Metamorphic contract factory using CREATE2 + SELFDESTRUCT
 */
contract VulnerableMetamorphicFactory {
    event ContractDeployed(address indexed deployed, bytes32 salt);

    // ❌ VULNERABILITY 1: Full metamorphic pattern
    function deployMetamorphic(bytes32 salt, bytes memory initCode) external returns (address deployed) {
        // Deploy with CREATE2
        assembly {
            deployed := create2(0, add(initCode, 0x20), mload(initCode), salt)
        }

        // ❌ CRITICAL: Contract can be redeployed with different code
        // Attack pattern:
        // 1. Deploy contract with CREATE2 (benign code)
        // 2. Constructor calls SELFDESTRUCT
        // 3. Redeploy at same address with malicious code
        // 4. Breaks trust assumptions

        emit ContractDeployed(deployed, salt);
    }

    // ❌ VULNERABILITY 2: Factory creates self-destructing contracts
    function deployTerminable(bytes32 salt) external returns (address deployed) {
        bytes memory bytecode = type(TerminableContract).creationCode;

        assembly {
            deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }

        // ❌ Combination of CREATE2 + SELFDESTRUCT enables metamorphic contracts
        emit ContractDeployed(deployed, salt);
    }
}

contract TerminableContract {
    address public owner;

    constructor() {
        owner = msg.sender;
        // ❌ SELFDESTRUCT in constructor creates metamorphic contract
        // After this, the same address can be reused with different code
    }

    // ❌ VULNERABILITY 3: External SELFDESTRUCT without proper protection
    function destroy() external {
        require(msg.sender == owner, "Not owner");
        // ❌ Missing: timelock, governance, transparency
        selfdestruct(payable(owner));
    }
}

// =====================================================================
// 2. EXTCODESIZE BYPASS PATTERNS
// =====================================================================

/**
 * @dev Contract using EXTCODESIZE for EOA validation (bypassable)
 */
contract VulnerableEOACheck {
    mapping(address => uint256) public balances;

    // ❌ VULNERABILITY 1: address.code.length for EOA check
    function depositEOAsOnly() external payable {
        // ❌ BYPASSABLE: During constructor, code.length == 0
        // Attacker can call from constructor to bypass
        require(msg.sender.code.length == 0, "Contracts not allowed");

        balances[msg.sender] += msg.value;
    }

    // ❌ VULNERABILITY 2: Assembly EXTCODESIZE check
    function transferEOAsOnly(address to, uint256 amount) external {
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(to)
        }

        // ❌ BYPASSABLE: Returns 0 during construction
        require(codeSize == 0, "Only EOAs can receive");

        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    // ❌ VULNERABILITY 3: Flawed contract detection
    function isContract(address account) public view returns (bool) {
        // ❌ VULNERABLE: Assumes nonzero code = contract
        // Bypass: Call from constructor where EXTCODESIZE(account) == 0
        return account.code.length > 0;
    }

    // ❌ VULNERABILITY 4: Using isContract for security
    function restrictedOperation() external {
        require(!isContract(msg.sender), "Contracts not allowed");

        // ❌ Attacker contract can call this from constructor
        // Protected operation proceeds
    }
}

/**
 * @dev Attacker contract bypassing EXTCODESIZE checks
 */
contract EXTCODESIZEBypassAttacker {
    VulnerableEOACheck public target;

    // Attack in constructor where EXTCODESIZE == 0
    constructor(address _target) payable {
        target = VulnerableEOACheck(_target);

        // ❌ This succeeds! During construction, address.code.length == 0
        target.depositEOAsOnly{value: msg.value}();

        // ❌ This also succeeds! EXTCODESIZE(this) == 0 in constructor
        target.restrictedOperation();
    }
}

// =====================================================================
// 3. UNISWAP V4 HOOK VULNERABILITIES
// =====================================================================

interface IPoolManager {
    function swap(PoolKey memory key) external returns (int256);
}

struct PoolKey {
    address token0;
    address token1;
    uint24 fee;
}

/**
 * @dev Vulnerable Uniswap V4 hook implementation
 */
contract VulnerableUniswapV4Hook {
    IPoolManager public poolManager;
    uint256 public hookFees;

    // ❌ VULNERABILITY 1: beforeSwap without reentrancy guard
    function beforeSwap(
        address sender,
        PoolKey calldata key,
        bool zeroForOne,
        int256 amountSpecified
    ) external returns (bytes4) {
        // ❌ No reentrancy protection
        // ❌ External call before state updates
        (bool success, ) = sender.call("");

        // ❌ State change after external call
        hookFees += 1 ether;

        // ❌ Reentrancy can manipulate hookFees
        return this.beforeSwap.selector;
    }

    // ❌ VULNERABILITY 2: afterSwap with unchecked return value
    function afterSwap(
        address sender,
        PoolKey calldata key,
        bool zeroForOne,
        int256 amountSpecified
    ) external returns (bytes4) {
        // ❌ No return value validation
        // ❌ Missing access control

        // ❌ Anyone can call hook functions directly
        hookFees += uint256(amountSpecified);

        return this.afterSwap.selector;
    }

    // ❌ VULNERABILITY 3: beforeAddLiquidity without fee validation
    function beforeAddLiquidity(
        address sender,
        PoolKey calldata key,
        uint256 amount0,
        uint256 amount1
    ) external returns (bytes4) {
        // ❌ Hook fee extraction without validation
        uint256 fee = (amount0 + amount1) / 100; // 1% fee

        // ❌ No check if fee is reasonable
        // ❌ No check if hook can actually receive fee
        hookFees += fee;

        return this.beforeAddLiquidity.selector;
    }

    // ❌ VULNERABILITY 4: afterRemoveLiquidity with callback
    function afterRemoveLiquidity(
        address sender,
        PoolKey calldata key,
        uint256 amount0,
        uint256 amount1
    ) external returns (bytes4) {
        // ❌ External call without reentrancy guard
        ICallback(sender).onLiquidityRemoved(amount0, amount1);

        // ❌ State changes after callback
        hookFees -= 100;

        return this.afterRemoveLiquidity.selector;
    }
}

interface ICallback {
    function onLiquidityRemoved(uint256 amount0, uint256 amount1) external;
}

// =====================================================================
// 4. AMM LIQUIDITY MANIPULATION
// =====================================================================

interface IAMM {
    function swap(uint256 amountIn, uint256 minAmountOut) external returns (uint256);
    function getReserves() external view returns (uint256, uint256);
}

/**
 * @dev Contract consuming AMM liquidity unsafely
 */
contract VulnerableAMMLiquidityConsumer {
    IAMM public amm;

    // ❌ VULNERABILITY 1: Large swap without slippage check
    function buyTokens() external payable {
        // ❌ No slippage protection
        // ❌ No price impact check
        // ❌ Vulnerable to sandwich attacks

        uint256 amountOut = amm.swap(msg.value, 0); // minAmountOut = 0!

        // ❌ Pool can be manipulated to drain this contract
    }

    // ❌ VULNERABILITY 2: Price calculation without manipulation check
    function calculatePrice() public view returns (uint256) {
        (uint256 reserve0, uint256 reserve1) = amm.getReserves();

        // ❌ Uses spot price without TWAP
        // ❌ Vulnerable to flash loan manipulation
        return (reserve1 * 1e18) / reserve0;
    }

    // ❌ VULNERABILITY 3: Liquidity provision without ratio check
    function addLiquidity(uint256 amount0, uint256 amount1) external {
        // ❌ No check that ratio matches pool
        // ❌ No minimum liquidity received check
        // ❌ Front-runnable for bad ratio

        // Add liquidity at arbitrary ratio
    }

    // ❌ VULNERABILITY 4: Flash swap without K invariant check
    function flashSwap(uint256 amount) external {
        // ❌ Borrows from AMM without verifying invariant
        // ❌ No check that K increased after callback
        // ❌ Can manipulate pool reserves

        amm.swap(amount, 0);

        // ❌ Repayment not verified against invariant
    }

    // ❌ VULNERABILITY 5: Price-based execution without delay
    function executeTrade() external {
        uint256 currentPrice = calculatePrice();

        // ❌ Uses manipulable spot price for decision
        // ❌ No time delay or commit-reveal
        if (currentPrice < 100 ether) {
            buyTokens();
        }
    }
}

// =====================================================================
// 5. WEAK COMMIT-REVEAL SCHEMES
// =====================================================================

/**
 * @dev Auction with weak commit-reveal implementation
 */
contract VulnerableCommitRevealAuction {
    struct Commitment {
        bytes32 commitment;
        uint256 timestamp;
        bool revealed;
    }

    mapping(address => Commitment) public commitments;
    uint256 public revealDeadline;

    // ❌ VULNERABILITY 1: Insufficient commit-reveal delay
    function commit(bytes32 commitment) external {
        commitments[msg.sender] = Commitment({
            commitment: commitment,
            timestamp: block.timestamp,
            revealed: false
        });

        // ❌ WEAK: Only 1 block delay (12 seconds)
        // MEV bots can monitor and front-run reveals
        revealDeadline = block.timestamp + 12;
    }

    // ❌ VULNERABILITY 2: Predictable reveal window
    function reveal(uint256 bid, bytes32 salt) external {
        Commitment storage c = commitments[msg.sender];

        // ❌ VULNERABLE: Fixed, predictable timing
        // Anyone can calculate exact reveal block
        require(block.timestamp >= revealDeadline, "Too early");

        // ❌ WEAK: No upper bound on reveal time
        // Late reveals can observe other bids first

        bytes32 hash = keccak256(abi.encodePacked(bid, salt));
        require(hash == c.commitment, "Invalid reveal");

        c.revealed = true;
    }

    // ❌ VULNERABILITY 3: No delay randomization
    function commitWithDelay(bytes32 commitment, uint256 delay) external {
        // ❌ User-controlled delay is predictable
        // Attacker can choose optimal timing
        commitments[msg.sender] = Commitment({
            commitment: commitment,
            timestamp: block.timestamp,
            revealed: false
        });

        revealDeadline = block.timestamp + delay;
    }

    // ❌ VULNERABILITY 4: Weak commitment scheme
    function weakCommit(uint256 bid) external {
        // ❌ CRITICAL: Commitment doesn't include salt
        // Bid can be brute-forced from commitment
        bytes32 commitment = keccak256(abi.encodePacked(bid));

        commitments[msg.sender].commitment = commitment;
        commitments[msg.sender].timestamp = block.timestamp;

        // ❌ Bid is recoverable: try all reasonable bid values
        // No salt = no security
    }
}

/**
 * @dev Lottery with weak randomness and commit-reveal
 */
contract VulnerableCommitRevealLottery {
    mapping(address => bytes32) public commitments;
    mapping(address => uint256) public commitTimes;

    // ❌ VULNERABILITY 1: Single block delay
    function commitNumber(bytes32 commitment) external {
        commitments[msg.sender] = commitment;
        commitTimes[msg.sender] = block.timestamp;

        // ❌ Can reveal in next block
        // Validator can censor/reorder reveals
    }

    // ❌ VULNERABILITY 2: Immediate reveal allowed
    function reveal(uint256 number, bytes32 salt) external {
        // ❌ WEAK: Only requires next timestamp
        require(block.timestamp > commitTimes[msg.sender], "Too early");

        // ❌ No minimum delay
        // ❌ MEV bots can front-run within same block

        bytes32 hash = keccak256(abi.encodePacked(number, salt));
        require(hash == commitments[msg.sender], "Invalid");

        // Determine winner using manipulable randomness
    }

    // ❌ VULNERABILITY 3: Block hash randomness with commit-reveal
    function determineWinner() external {
        // ❌ WEAK: blockhash is predictable for validators
        // ❌ Combined with weak commit-reveal = fully manipulable
        uint256 randomness = uint256(blockhash(block.number - 1));

        // Winner selection is MEV-extractable
    }
}

/**
 * TESTING NOTES:
 *
 * Expected Detectors:
 * 1. metamorphic-contract (5+ findings)
 *    - CREATE2 + SELFDESTRUCT combinations
 *    - Constructor SELFDESTRUCT
 *    - Factory deploying terminable contracts
 *
 * 2. extcodesize-bypass (4+ findings)
 *    - address.code.length for EOA validation
 *    - Assembly EXTCODESIZE checks
 *    - isContract() pattern
 *    - Security checks bypassable during construction
 *
 * 3. uniswapv4-hook-issues (4+ findings)
 *    - Hooks without reentrancy guards
 *    - Missing return value validation
 *    - Unsafe external calls in hooks
 *    - Hook fee extraction without validation
 *
 * 4. amm-liquidity-manipulation (5+ findings)
 *    - Swaps without slippage protection
 *    - Spot price usage without TWAP
 *    - Price-based decisions without delay
 *    - Flash swaps without invariant checks
 *    - Liquidity provision without ratio validation
 *
 * 5. weak-commit-reveal (7+ findings)
 *    - Insufficient commit-reveal delay (<5 minutes)
 *    - Predictable reveal windows
 *    - No delay randomization
 *    - Weak commitment without salt
 *    - Single block delays
 *    - Immediate reveals allowed
 *
 * Cross-Category Detectors Expected:
 * - dangerous-delegatecall
 * - classic-reentrancy
 * - external-calls-loop
 * - unchecked-external-call
 * - front-running-mitigation
 * - missing-slippage-protection
 * - oracle-manipulation
 * - insufficient-randomness
 * - timestamp-manipulation
 *
 * Real-World Relevance:
 * - Metamorphic contracts used in Tornado Cash attack
 * - EXTCODESIZE bypass in various DeFi protocols
 * - Uniswap V4 hooks are new attack surface
 * - AMM manipulation in countless DeFi exploits
 * - Weak commit-reveal in NFT mints, auctions
 *
 * Attack Patterns:
 * - Metamorphic: Deploy benign → SELFDESTRUCT → redeploy malicious
 * - EXTCODESIZE: Call from constructor when code.length == 0
 * - Hook reentrancy: Callback during hook execution
 * - AMM manipulation: Flash loan → manipulate spot price → profit
 * - Commit-reveal: Front-run reveals within predictable window
 */
