// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableCodeQuality
 * @notice Test contracts for code quality, input validation, and gas optimization issues
 * @dev Intentionally vulnerable for testing SolidityDefend quality detectors
 */

// ============================================================================
// INPUT VALIDATION ISSUES
// ============================================================================

/// @notice ❌ VULNERABLE: Missing input validation
contract VulnerableInputValidation {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalSupply;

    // ❌ VULNERABILITY 1: Missing zero address check
    function transfer(address to, uint256 amount) external {
        // ❌ No check: require(to != address(0), "Zero address");
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount; // ❌ Can transfer to zero address, burning funds!
    }

    // ❌ VULNERABILITY 2: Missing amount validation
    function mint(address to, uint256 amount) external {
        // ❌ No check: require(amount > 0, "Zero amount");
        // ❌ No check: require(amount <= MAX_MINT, "Exceeds max");
        balances[to] += amount;
        totalSupply += amount;
    }

    // ❌ VULNERABILITY 3: Missing array length validation
    function batchTransfer(address[] calldata recipients, uint256[] calldata amounts) external {
        // ❌ No check: require(recipients.length == amounts.length, "Length mismatch");
        // ❌ No check: require(recipients.length > 0, "Empty array");
        for (uint256 i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += amounts[i]; // ❌ May be out of bounds!
        }
    }

    // ❌ VULNERABILITY 4: Missing address validation
    function setOwner(address newOwner) external {
        // ❌ No check: require(newOwner != address(0), "Zero address");
        // ❌ No check: require(newOwner != owner, "Same owner");
        owner = newOwner;
    }

    // ❌ VULNERABILITY 5: Unchecked math operations
    function unsafeAdd(uint256 a, uint256 b) external pure returns (uint256) {
        // ❌ No overflow check in older Solidity
        return a + b; // Could overflow
    }

    // ❌ VULNERABILITY 6: Missing parameter consistency
    function inconsistentParams(address token, uint256 amount, address recipient) external {
        // ❌ Parameter order inconsistent with other functions
        // ❌ token parameter not validated
        // Transfer logic here
    }
}

/// @notice ❌ VULNERABLE: Enhanced input validation missing
contract VulnerableEnhancedValidation {
    struct Config {
        uint256 minAmount;
        uint256 maxAmount;
        uint256 fee;
        bool active;
    }

    Config public config;

    // ❌ VULNERABILITY 7: Missing range validation
    function setConfig(uint256 minAmount, uint256 maxAmount, uint256 fee) external {
        // ❌ No check: require(minAmount < maxAmount, "Invalid range");
        // ❌ No check: require(fee <= 10000, "Fee too high"); // 100% = 10000 basis points
        config.minAmount = minAmount;
        config.maxAmount = maxAmount;
        config.fee = fee; // ❌ Could be > 100%!
    }

    // ❌ VULNERABILITY 8: Missing bounds check
    function processAmount(uint256 amount) external view returns (uint256) {
        // ❌ No check: require(amount >= config.minAmount, "Below min");
        // ❌ No check: require(amount <= config.maxAmount, "Above max");
        return amount - config.fee;
    }
}

// ============================================================================
// GAS OPTIMIZATION ISSUES
// ============================================================================

/// @notice ❌ VULNERABLE: Excessive gas usage
contract VulnerableGasOptimization {
    uint256[] public largeArray;
    mapping(uint256 => uint256) public data;

    struct User {
        address addr;
        uint256 balance;
        uint256 lastUpdate;
        bool active;
    }

    mapping(address => User) public users;

    // ❌ VULNERABILITY 1: Unbounded loop - gas griefing
    function sumAllElements() external view returns (uint256) {
        uint256 sum = 0;
        // ❌ No limit on array size - can run out of gas!
        for (uint256 i = 0; i < largeArray.length; i++) {
            sum += largeArray[i];
        }
        return sum;
    }

    // ❌ VULNERABILITY 2: Inefficient storage usage
    function inefficientStorage() external {
        // ❌ Multiple SSTORE operations instead of memory
        data[0] = 1;
        data[1] = 2;
        data[2] = 3;
        data[3] = 4;
        data[4] = 5;
        // Should use memory array then single storage write
    }

    // ❌ VULNERABILITY 3: Reading storage in loop
    function inefficientLoop(uint256 n) external {
        // ❌ Reads storage variable in each iteration
        for (uint256 i = 0; i < n; i++) {
            uint256 temp = data[i]; // ❌ SLOAD each time
            largeArray.push(temp);
        }
    }

    // ❌ VULNERABILITY 4: String comparison instead of hash
    function compareStrings(string memory a, string memory b) external pure returns (bool) {
        // ❌ Expensive string operations
        return bytes(a).length == bytes(b).length; // Should use keccak256
    }

    // ❌ VULNERABILITY 5: Redundant storage access
    function redundantAccess(address user) external view returns (uint256, uint256, bool) {
        // ❌ Three separate storage reads
        uint256 balance = users[user].balance;
        uint256 lastUpdate = users[user].lastUpdate;
        bool active = users[user].active;
        // Should read struct once into memory
        return (balance, lastUpdate, active);
    }
}

/// @notice ❌ VULNERABLE: Gas griefing attacks
contract VulnerableGasGriefing {
    address[] public recipients;

    // ❌ VULNERABILITY 6: External call in unbounded loop
    function distributeRewards() external {
        // ❌ Attacker can add many recipients to cause DOS
        for (uint256 i = 0; i < recipients.length; i++) {
            (bool success, ) = recipients[i].call{value: 1 ether}("");
            require(success, "Transfer failed"); // ❌ Single failure DOS entire function!
        }
    }

    // ❌ VULNERABILITY 7: Unbounded array growth
    function addRecipient(address recipient) external {
        // ❌ No limit on array size
        recipients.push(recipient); // Grows forever
    }
}

// ============================================================================
// CODE QUALITY ISSUES
// ============================================================================

/// @notice ❌ VULNERABLE: Variable shadowing
contract VulnerableShadowing {
    address public owner;
    uint256 public balance;

    constructor(address owner) { // ❌ Shadows state variable!
        owner = owner; // ❌ This does nothing! State variable not set
    }

    // ❌ VULNERABILITY 2: Function parameter shadowing
    function setBalance(uint256 balance) external { // ❌ Shadows state variable!
        balance = balance; // ❌ Sets parameter to itself, not state!
    }

    // ❌ VULNERABILITY 3: Local variable shadowing
    function processData(uint256 amount) external view returns (uint256) {
        uint256 balance = amount * 2; // ❌ Shadows state variable
        return balance; // Confusing which balance is returned
    }
}

/// @notice ❌ VULNERABLE: Unused state variables
contract VulnerableUnused {
    uint256 public usedVariable;
    uint256 private unusedVariable; // ❌ Never used - wasted storage
    address private unusedAddress; // ❌ Never used
    bool private unusedFlag; // ❌ Never used

    function doSomething() external {
        usedVariable = 100;
        // unusedVariable never accessed
    }
}

/// @notice ❌ VULNERABLE: Default visibility
contract VulnerableVisibility {
    uint256 counter; // ❌ No visibility specifier - defaults to internal

    // ❌ No visibility specifier
    function increment() { // ❌ Defaults to public
        counter++;
    }

    // ❌ Should be external if only called externally
    function getValue() public view returns (uint256) { // ❌ Should be external
        return counter;
    }
}

/// @notice ❌ VULNERABLE: Inefficient storage patterns
contract VulnerableStoragePatterns {
    // ❌ VULNERABILITY 1: Bool + uint256 wastes storage slot
    bool public flag1; // Uses 1 byte in slot 0
    uint256 public value1; // Uses full slot 1 (wasted 31 bytes in slot 0!)
    bool public flag2; // Uses 1 byte in slot 2

    // ✅ BETTER: Pack multiple bools together
    // bool public flag1;
    // bool public flag2;
    // uint256 public value1;

    // ❌ VULNERABILITY 2: Struct with poor packing
    struct BadPacking {
        bool active; // 1 byte - slot 0
        uint256 amount; // 32 bytes - slot 1
        bool processed; // 1 byte - slot 2
        uint128 value; // 16 bytes - slot 3 (wastes 16 bytes!)
    }

    // ✅ BETTER: Pack bools and smaller types together
    // struct GoodPacking {
    //     bool active;     // 1 byte
    //     bool processed;  // 1 byte
    //     uint128 value;   // 16 bytes
    //     uint256 amount;  // 32 bytes (new slot)
    // }

    BadPacking public data;
}

/// @notice ❌ VULNERABLE: Redundant checks
contract VulnerableRedundantChecks {
    uint256 public value;

    function setValue(uint256 newValue) external {
        // ❌ Redundant check - Solidity 0.8+ has overflow protection
        require(newValue >= 0, "Must be non-negative"); // ❌ uint256 is always >= 0!

        // ❌ Redundant comparison
        require(newValue != newValue, "Invalid"); // ❌ Always false!

        value = newValue;
    }

    function redundantLogic(uint256 x) external pure returns (bool) {
        // ❌ Redundant boolean operations
        if (x > 10 && x > 10) { // ❌ Duplicate condition
            return true;
        }
        return false;
    }
}

/// @notice ❌ VULNERABLE: Unchecked external calls
contract VulnerableUncheckedCalls {
    // ❌ VULNERABILITY 1: Call return value not checked
    function uncheckedTransfer(address token, address to, uint256 amount) external {
        // ❌ Return value ignored!
        token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        // Should: (bool success, ) = ...
        // require(success, "Transfer failed");
    }

    // ❌ VULNERABILITY 2: Delegatecall return not checked
    function uncheckedDelegatecall(address target, bytes calldata data) external {
        // ❌ Return value ignored - critical!
        target.delegatecall(data);
    }

    // ❌ VULNERABILITY 3: Low-level call without checks
    function unsafeCall(address target) external payable {
        // ❌ No success check, no return data validation
        target.call{value: msg.value}("");
    }
}

/// @notice ❌ VULNERABLE: Circular dependencies
contract VulnerableCircularDependency {
    address public contractA;
    address public contractB;

    // ❌ VULNERABILITY: Circular external call pattern
    function callA() external {
        // ❌ Calls contract A which may call back to this contract
        (bool success, ) = contractA.call(abi.encodeWithSignature("callback()"));
        require(success, "Call failed");
    }

    function callback() external {
        // ❌ Can be called by contractA, creating circular dependency
        // May lead to reentrancy or infinite loops
    }
}

/// @notice ❌ VULNERABLE: Missing constants and immutables
contract VulnerableMissingConstants {
    // ❌ Should be constant
    uint256 public MAX_SUPPLY = 1000000; // ❌ Can be constant (saves gas)
    uint256 public FEE_DENOMINATOR = 10000; // ❌ Can be constant

    // ❌ Should be immutable
    address public admin; // ❌ Set once in constructor, should be immutable
    uint256 public deployTime; // ❌ Set once in constructor, should be immutable

    constructor(address _admin) {
        admin = _admin;
        deployTime = block.timestamp;
    }

    function calculateFee(uint256 amount, uint256 feeRate) external view returns (uint256) {
        // ❌ Multiple storage reads for constants
        return (amount * feeRate) / FEE_DENOMINATOR;
    }
}

/// @notice ❌ VULNERABLE: Array bounds issues
contract VulnerableArrayBounds {
    uint256[] public data;
    mapping(uint256 => uint256) public indexToValue;

    // ❌ VULNERABILITY: No bounds checking
    function getElement(uint256 index) external view returns (uint256) {
        // ❌ No check: require(index < data.length, "Out of bounds");
        return data[index]; // ❌ May revert with out of bounds!
    }

    // ❌ VULNERABILITY: Accessing array without length check
    function unsafeAccess() external view returns (uint256) {
        // ❌ Assumes array has elements
        return data[0]; // ❌ Reverts if array empty!
    }

    // ❌ VULNERABILITY: Loop without bounds
    function unsafeLoop(uint256 start, uint256 end) external {
        // ❌ No validation of start/end
        for (uint256 i = start; i < end; i++) {
            indexToValue[i] = i * 2;
        }
    }
}

// ============================================================================
// SECURE IMPLEMENTATIONS
// ============================================================================

/// @notice ✅ SECURE: Proper input validation
contract SecureInputValidation {
    mapping(address => uint256) public balances;
    uint256 public constant MAX_MINT = 1_000_000 ether;
    uint256 public constant MAX_BATCH_SIZE = 100;

    // ✅ Comprehensive validation
    function transfer(address to, uint256 amount) external {
        require(to != address(0), "Zero address");
        require(to != msg.sender, "Self transfer");
        require(amount > 0, "Zero amount");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    // ✅ Array validation
    function batchTransfer(
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external {
        require(recipients.length == amounts.length, "Length mismatch");
        require(recipients.length > 0, "Empty array");
        require(recipients.length <= MAX_BATCH_SIZE, "Batch too large");

        for (uint256 i = 0; i < recipients.length; i++) {
            require(recipients[i] != address(0), "Zero address");
            require(amounts[i] > 0, "Zero amount");
            // Transfer logic
        }
    }
}

/// @notice ✅ SECURE: Gas optimizations
contract SecureGasOptimization {
    uint256[] public data;

    struct User {
        address addr;
        uint256 balance;
        uint256 lastUpdate;
        bool active;
    }

    mapping(address => User) public users;
    uint256 public constant MAX_ITERATIONS = 100;

    // ✅ Bounded loop with limit
    function sumElements(uint256 maxIterations) external view returns (uint256) {
        require(maxIterations <= MAX_ITERATIONS, "Too many iterations");

        uint256 length = data.length < maxIterations ? data.length : maxIterations;
        uint256 sum = 0;

        for (uint256 i = 0; i < length; i++) {
            sum += data[i];
        }

        return sum;
    }

    // ✅ Read struct once into memory
    function getUserInfo(address user) external view returns (
        uint256 balance,
        uint256 lastUpdate,
        bool active
    ) {
        User memory u = users[user]; // ✅ Single storage read
        return (u.balance, u.lastUpdate, u.active);
    }

    // ✅ Use memory for intermediate calculations
    function efficientBatch(uint256[] calldata values) external {
        uint256 length = values.length;
        uint256[] memory results = new uint256[](length);

        for (uint256 i = 0; i < length; i++) {
            results[i] = values[i] * 2;
        }

        // Single storage write instead of many
        for (uint256 i = 0; i < length; i++) {
            data.push(results[i]);
        }
    }
}

/// @notice ✅ SECURE: Proper visibility and constants
contract SecureCodeQuality {
    uint256 private counter;
    uint256 public constant MAX_SUPPLY = 1_000_000 ether; // ✅ Constant
    address public immutable ADMIN; // ✅ Immutable

    constructor(address admin) {
        require(admin != address(0), "Zero address");
        ADMIN = admin;
    }

    // ✅ Explicit external visibility
    function increment() external {
        counter++;
    }

    // ✅ Explicit external for external-only functions
    function getValue() external view returns (uint256) {
        return counter;
    }
}

/// @notice ✅ SECURE: Optimized storage packing
contract SecureStoragePacking {
    // ✅ Efficient packing - all in one slot
    bool public flag1;     // 1 byte
    bool public flag2;     // 1 byte
    uint128 public value1; // 16 bytes
    uint96 public value2;  // 12 bytes
    // Total: 30 bytes in one slot!

    struct EfficientStruct {
        bool active;       // 1 byte - slot 0
        bool processed;    // 1 byte
        uint48 timestamp;  // 6 bytes
        uint128 amount;    // 16 bytes
        uint72 id;         // 9 bytes
        // Total: 33 bytes → 2 slots (efficient)
        uint256 largeValue; // 32 bytes - slot 2
    }
}
