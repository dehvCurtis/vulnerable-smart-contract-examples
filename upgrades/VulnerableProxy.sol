// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableProxy
 * @notice Test contract for proxy pattern vulnerabilities
 *
 * DETECTORS TO TEST:
 * - upgradeable-proxy-issues (Critical)
 * - storage-collision (Critical)
 * - uninitialized-storage (High)
 * - dangerous-delegatecall (Critical)
 *
 * VULNERABILITIES:
 * 1. Unprotected upgrade function (anyone can upgrade)
 * 2. Missing initialization protection
 * 3. Storage collision between proxy and implementation
 * 4. Delegatecall to arbitrary address
 * 5. No upgrade delay/timelock
 * 6. Missing upgrade events
 * 7. Constructor in upgradeable contract
 * 8. Uninitialized storage slots
 */

/**
 * @notice Vulnerable transparent proxy with unprotected upgrade
 */
contract VulnerableTransparentProxy {
    // ❌ VULNERABILITY 1: Storage collision! (storage-collision)
    // Implementation address in slot 0 - WILL collide with implementation storage!
    address public implementation;

    // Proxy admin
    address public admin;

    constructor(address _implementation) {
        // ❌ VULNERABILITY 2: Using constructor in upgradeable pattern!
        // Constructor runs only once during deployment, not during upgrades!
        implementation = _implementation;
        admin = msg.sender;
    }

    // ❌ VULNERABILITY 3: No access control on upgrade! (upgradeable-proxy-issues)
    function upgradeTo(address newImplementation) external {
        // ❌ Anyone can upgrade to malicious implementation!
        // ❌ No require(msg.sender == admin)
        // ❌ No timelock delay
        // ❌ No validation of new implementation

        implementation = newImplementation;
        // ❌ No event emitted!
    }

    // ❌ VULNERABILITY 4: Unprotected admin change (upgradeable-proxy-issues)
    function changeAdmin(address newAdmin) external {
        // ❌ No access control!
        admin = newAdmin;
    }

    // Fallback function delegates all calls to implementation
    fallback() external payable {
        // ❌ VULNERABILITY 5: Delegatecall to user-controlled address (dangerous-delegatecall)
        address _impl = implementation;

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), _impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

/**
 * @notice Vulnerable UUPS proxy without authorization
 */
contract VulnerableUUPSProxy {
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    constructor(address _implementation) {
        _setImplementation(_implementation);
    }

    // ❌ VULNERABILITY 6: Missing _authorizeUpgrade check (upgradeable-proxy-issues)
    function upgradeTo(address newImplementation) external {
        // ❌ No authorization check!
        // Should call: _authorizeUpgrade(newImplementation)

        _setImplementation(newImplementation);
    }

    function _setImplementation(address newImplementation) private {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
    }

    fallback() external payable {
        address _impl;
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            _impl := sload(slot)
        }

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), _impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

/**
 * @notice Vulnerable implementation with storage collision
 */
contract VulnerableImplementationV1 {
    // ❌ VULNERABILITY 7: Storage collision with proxy! (storage-collision)
    // Slot 0: owner (collides with proxy's implementation variable!)
    address public owner;

    // Slot 1: value
    uint256 public value;

    // ❌ VULNERABILITY 8: No initializer protection! (upgradeable-proxy-issues)
    function initialize(address _owner) external {
        // ❌ Can be called multiple times!
        // ❌ No: require(!initialized)
        // ❌ No: initializer modifier

        owner = _owner;
    }

    function setValue(uint256 _value) external {
        require(msg.sender == owner, "Not owner");
        value = _value;
    }

    function getValue() external view returns (uint256) {
        return value;
    }
}

/**
 * @notice Upgraded implementation with storage layout violation
 */
contract VulnerableImplementationV2 {
    // ❌ VULNERABILITY 9: Storage layout changed! (storage-collision)
    // ❌ Variable order changed - causes data corruption!

    // Slot 0: value (was owner in V1!) - CORRUPT!
    uint256 public value;

    // Slot 1: owner (was value in V1!) - CORRUPT!
    address public owner;

    // Slot 2: newFeature (new variable)
    bool public newFeature;

    function setValue(uint256 _value) external {
        value = _value;
    }

    function enableNewFeature() external {
        newFeature = true;
    }
}

/**
 * @notice Vulnerable implementation with constructor
 */
contract VulnerableImplementationWithConstructor {
    address public owner;
    uint256 public value;
    uint256 public immutable deployTime; // ✅ immutable is ok

    // ❌ VULNERABILITY 10: Constructor in upgradeable contract! (upgradeable-proxy-issues)
    // Constructor only runs during deployment, NOT during proxy upgrade!
    // State set here will NOT be available through proxy!
    constructor() {
        owner = msg.sender; // ❌ This won't work through proxy!
        deployTime = block.timestamp; // ✅ immutable variables are ok
    }

    function setValue(uint256 _value) external {
        require(msg.sender == owner); // ❌ owner is address(0) through proxy!
        value = _value;
    }
}

/**
 * @notice Vulnerable implementation with uninitialized storage
 */
contract VulnerableUninitializedStorage {
    struct UserData {
        address user;
        uint256 balance;
        bool active;
    }

    mapping(address => UserData) public userData;
    UserData[] public userList;

    // ❌ VULNERABILITY 11: Uninitialized storage pointer (uninitialized-storage)
    function addUser(address user, uint256 balance) external {
        UserData storage data; // ❌ Uninitialized! Points to slot 0!

        // ❌ This writes to storage slot 0!
        // Corrupts contract state!
        data.user = user;
        data.balance = balance;
        data.active = true;

        userList.push(data);
    }

    // ❌ VULNERABILITY 12: Another uninitialized storage (uninitialized-storage)
    function getUserData(address user) external view returns (UserData memory) {
        UserData storage data; // ❌ Uninitialized!

        // ❌ Reads garbage from slot 0
        return data;
    }
}

/**
 * @notice Proxy with arbitrary delegatecall
 */
contract VulnerableArbitraryDelegatecall {
    address public implementation;
    address public admin;

    constructor(address _implementation) {
        implementation = _implementation;
        admin = msg.sender;
    }

    // ❌ VULNERABILITY 13: Arbitrary delegatecall (dangerous-delegatecall)
    function execute(address target, bytes calldata data) external {
        // ❌ Even with admin check, delegatecall to arbitrary target is dangerous!
        require(msg.sender == admin, "Not admin");

        // ❌ Admin can delegatecall to malicious contract
        // ❌ Can modify storage arbitrarily
        (bool success,) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    // ❌ VULNERABILITY 14: Delegatecall without access control (dangerous-delegatecall)
    function executeAny(address target, bytes calldata data) external {
        // ❌ No access control at all!
        (bool success,) = target.delegatecall(data);
        require(success);
    }
}

/**
 * @notice Proxy without upgrade delay
 */
contract VulnerableNoTimelockProxy {
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    address public admin;

    constructor(address _implementation) {
        admin = msg.sender;
        _setImplementation(_implementation);
    }

    // ❌ VULNERABILITY 15: No timelock on upgrades (upgradeable-proxy-issues)
    function upgradeTo(address newImplementation) external {
        require(msg.sender == admin, "Not admin");

        // ❌ Immediate upgrade without delay!
        // ❌ No time for users to exit if malicious upgrade!
        // Should have:
        // - proposeUpgrade() with timelock
        // - executeUpgrade() after delay

        _setImplementation(newImplementation);
    }

    function _setImplementation(address newImplementation) private {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
    }

    fallback() external payable {
        address _impl;
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            _impl := sload(slot)
        }

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), _impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

/**
 * @notice Secure proxy implementation with proper patterns
 */
contract SecureTransparentProxy {
    // ✅ Use EIP-1967 storage slots to avoid collision
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
    bytes32 private constant ADMIN_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);

    event Upgraded(address indexed implementation);
    event AdminChanged(address indexed previousAdmin, address indexed newAdmin);

    constructor(address _implementation) {
        _setAdmin(msg.sender);
        _setImplementation(_implementation);
    }

    modifier onlyAdmin() {
        require(msg.sender == _getAdmin(), "Not admin");
        _;
    }

    // ✅ Protected upgrade with validation and event
    function upgradeTo(address newImplementation) external onlyAdmin {
        require(newImplementation != address(0), "Invalid implementation");
        require(_isContract(newImplementation), "Not a contract");

        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }

    // ✅ Protected admin change
    function changeAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "Invalid admin");

        address previousAdmin = _getAdmin();
        _setAdmin(newAdmin);

        emit AdminChanged(previousAdmin, newAdmin);
    }

    function _setImplementation(address newImplementation) private {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
    }

    function _getImplementation() private view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    function _setAdmin(address newAdmin) private {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            sstore(slot, newAdmin)
        }
    }

    function _getAdmin() private view returns (address adm) {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            adm := sload(slot)
        }
    }

    function _isContract(address account) private view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    fallback() external payable {
        address _impl = _getImplementation();
        require(_impl != address(0), "Implementation not set");

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), _impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}
