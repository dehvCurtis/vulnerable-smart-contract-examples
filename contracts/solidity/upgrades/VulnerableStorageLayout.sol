// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableStorageLayout
 * @notice Test contract for storage layout upgrade vulnerabilities
 *
 * DETECTORS TO TEST:
 * - storage-layout-upgrade (Critical)
 * - storage-collision (Critical)
 *
 * VULNERABILITIES:
 * 1. Missing storage gap in base contract
 * 2. Reordered storage variables between versions
 * 3. Changed variable types between versions
 * 4. Added variables in middle of storage layout
 * 5. Small or missing storage gaps
 * 6. Inherited contract storage collision
 */

/**
 * @notice Base contract V1 without storage gap
 */
abstract contract BaseContractV1 {
    address public owner;
    uint256 public value;

    // ❌ VULNERABILITY 1: Missing storage gap! (storage-layout-upgrade)
    // When upgrading, can't add new variables without corrupting child storage!
    // Should have: uint256[50] private __gap;
}

/**
 * @notice Implementation V1 extending base
 */
contract ImplementationV1 is BaseContractV1 {
    // Slot 2: data
    bytes32 public data;

    // Slot 3: active
    bool public active;

    function initialize(address _owner) external {
        owner = _owner;
        active = true;
    }

    function setData(bytes32 _data) external {
        require(msg.sender == owner);
        data = _data;
    }
}

/**
 * @notice Base contract V2 with added variables
 */
abstract contract BaseContractV2 {
    address public owner;
    uint256 public value;

    // ❌ VULNERABILITY 2: Added new variables without gap! (storage-layout-upgrade)
    // This shifts all child contract storage down!
    // Corrupts ImplementationV2's storage layout!
    uint256 public newBaseVar1;
    address public newBaseVar2;

    // Still no gap!
}

/**
 * @notice Implementation V2 - child storage now corrupted
 */
contract ImplementationV2 is BaseContractV2 {
    // ❌ These are no longer in slots 2 and 3!
    // ❌ Slot 4: data (was slot 2)
    // ❌ Slot 5: active (was slot 3)
    // Old data in slots 2-3 is now interpreted as newBaseVar1/newBaseVar2!
    bytes32 public data;
    bool public active;

    // New functionality
    uint256 public newFeature;
}

/**
 * @notice Contract V1 with specific storage layout
 */
contract StorageOrderV1 {
    // Slot 0
    address public owner;

    // Slot 1
    uint256 public balance;

    // Slot 2
    bool public active;

    // Slot 3
    mapping(address => uint256) public deposits;

    function initialize() external {
        owner = msg.sender;
        active = true;
    }
}

/**
 * @notice Contract V2 with reordered storage
 */
contract StorageOrderV2 {
    // ❌ VULNERABILITY 3: Storage order changed! (storage-layout-upgrade)

    // ❌ Slot 0: balance (was owner!) - address interpreted as uint256!
    uint256 public balance;

    // ❌ Slot 1: owner (was balance!) - uint256 interpreted as address!
    address public owner;

    // ❌ Slot 2: deposits mapping (was active!) - bool interpreted as mapping!
    mapping(address => uint256) public deposits;

    // ❌ Slot 3: active (was deposits mapping!) - mapping interpreted as bool!
    bool public active;

    // Complete storage corruption!
}

/**
 * @notice Contract V1 with uint8
 */
contract TypeChangeV1 {
    address public owner;
    uint8 public count; // ❌ Slot 1: uint8

    function increment() external {
        count++;
    }
}

/**
 * @notice Contract V2 with changed type
 */
contract TypeChangeV2 {
    address public owner;

    // ❌ VULNERABILITY 4: Type changed from uint8 to uint256! (storage-layout-upgrade)
    uint256 public count; // ❌ Now uint256 - wrong interpretation!

    // If count was 5 in V1 (stored as uint8),
    // V2 reads it as uint256 - wrong value!

    function increment() external {
        count++;
    }
}

/**
 * @notice Contract V1 with array
 */
contract ArraySizeChangeV1 {
    address public owner;

    // ❌ Fixed-size array
    uint256[5] public fixedArray;

    function setValue(uint256 index, uint256 value) external {
        fixedArray[index] = value;
    }
}

/**
 * @notice Contract V2 with different array size
 */
contract ArraySizeChangeV2 {
    address public owner;

    // ❌ VULNERABILITY 5: Array size changed! (storage-layout-upgrade)
    // Changed from uint256[5] to uint256[10]
    // Collides with storage after original array!
    uint256[10] public fixedArray;

    function setValue(uint256 index, uint256 value) external {
        fixedArray[index] = value;
    }
}

/**
 * @notice Contract V1 with proper layout
 */
contract VariableInsertionV1 {
    // Slot 0
    address public owner;

    // Slot 1
    uint256 public totalSupply;

    // Slot 2
    mapping(address => uint256) public balances;
}

/**
 * @notice Contract V2 with variable inserted in middle
 */
contract VariableInsertionV2 {
    // Slot 0
    address public owner;

    // ❌ VULNERABILITY 6: New variable inserted in middle! (storage-layout-upgrade)
    // ❌ Slot 1: paused (NEW!) - shifts everything down!
    bool public paused;

    // ❌ Slot 2: totalSupply (was slot 1!) - corrupted!
    uint256 public totalSupply;

    // ❌ Slot 3: balances (was slot 2!) - corrupted!
    mapping(address => uint256) public balances;

    // New variables must be added at the END, not middle!
}

/**
 * @notice Base contract with tiny storage gap
 */
abstract contract TinyGapBase {
    address public owner;
    uint256 public value;

    // ❌ VULNERABILITY 7: Storage gap too small! (storage-layout-upgrade)
    // Only 2 slots reserved - not enough for future upgrades!
    // Should be at least 50 slots!
    uint256[2] private __gap;
}

/**
 * @notice Contract extending tiny gap base
 */
contract TinyGapImplementation is TinyGapBase {
    uint256 public data;

    function setData(uint256 _data) external {
        data = _data;
    }
}

/**
 * @notice Multiple inheritance without gaps
 */
abstract contract ParentA {
    uint256 public valueA;
    // ❌ No gap!
}

abstract contract ParentB {
    uint256 public valueB;
    // ❌ No gap!
}

/**
 * @notice Contract with diamond inheritance
 */
contract MultiInheritance is ParentA, ParentB {
    // ❌ VULNERABILITY 8: Multiple inheritance without gaps! (storage-layout-upgrade)
    // If ParentA or ParentB add variables in upgrade,
    // storage collision occurs!

    uint256 public valueC;
}

/**
 * @notice Contract with mapping and new variable
 */
contract MappingCollisionV1 {
    address public owner;

    // Slot 1: mapping
    mapping(address => uint256) public balances;

    // Slots 2+: data storage for mapping (dynamic)
}

/**
 * @notice Upgraded version adding variable
 */
contract MappingCollisionV2 {
    address public owner;

    mapping(address => uint256) public balances;

    // ❌ VULNERABILITY 9: New variable after mapping! (storage-layout-upgrade)
    // ❌ Slot 2: newVar
    // But mapping data might already use slot 2!
    // Collision with existing mapping data!
    uint256 public newVar;
}

/**
 * @notice Secure storage layout implementation
 */
abstract contract SecureBaseContract {
    address public owner;
    uint256 public value;

    // ✅ Adequate storage gap for future upgrades
    uint256[48] private __gap;
}

/**
 * @notice Secure implementation with proper layout
 */
contract SecureImplementation is SecureBaseContract {
    // Slots after base + gap
    bytes32 public data;
    bool public active;

    // ✅ Own storage gap
    uint256[48] private __gap_implementation;

    function initialize(address _owner) external {
        require(owner == address(0), "Already initialized");
        owner = _owner;
        active = true;
    }

    function setData(bytes32 _data) external {
        require(msg.sender == owner, "Not owner");
        data = _data;
    }
}

/**
 * @notice Secure V2 - adds variables at END
 */
contract SecureImplementationV2 is SecureBaseContract {
    // ✅ Original variables stay in same slots
    bytes32 public data;
    bool public active;

    // ✅ New variables added at END
    uint256 public newFeature1;
    address public newFeature2;

    // ✅ Adjusted gap (48 - 2 = 46)
    uint256[46] private __gap_implementation;

    function initialize(address _owner) external {
        require(owner == address(0), "Already initialized");
        owner = _owner;
        active = true;
    }

    function enableNewFeature(uint256 value, address addr) external {
        require(msg.sender == owner, "Not owner");
        newFeature1 = value;
        newFeature2 = addr;
    }
}
