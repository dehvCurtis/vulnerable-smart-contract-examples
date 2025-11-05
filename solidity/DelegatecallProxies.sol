// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Upgradeable Proxy Delegatecall Patterns Test
 * @dev VULNERABLE - Tests for proxy pattern delegatecall vulnerabilities
 *
 * This contract tests delegatecall in various proxy patterns:
 * 1. UUPS (Universal Upgradeable Proxy Standard)
 * 2. Transparent Proxy
 * 3. Beacon Proxy
 * 4. Diamond Proxy (EIP-2535)
 * 5. Minimal Proxy (EIP-1167)
 */

// ============================================================================
// 1. UUPS PROXY PATTERN
// ============================================================================

contract VulnerableUUPS {
    address public implementation;
    address public owner;

    constructor(address _implementation) {
        implementation = _implementation;
        owner = msg.sender;
    }

    // VULNERABLE: upgradeTo without proper access control
    function upgradeTo(address newImplementation) public {
        // VULNERABILITY: Missing onlyOwner or similar protection
        // Anyone can upgrade the implementation!
        implementation = newImplementation;
    }

    // VULNERABLE: upgradeTo without implementation validation
    function upgradeToUnchecked(address newImplementation) public {
        require(msg.sender == owner, "Not owner");
        // VULNERABILITY: No validation that newImplementation is valid
        // Could be EOA, zero address, or malicious contract
        implementation = newImplementation;
    }

    // VULNERABLE: Fallback with delegatecall
    fallback() external payable {
        address impl = implementation;
        // VULNERABILITY: Delegatecall in fallback to potentially malicious implementation
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

// VULNERABLE: UUPS implementation without proper protection
contract VulnerableUUPSImplementation {
    address public implementation;
    address public owner;

    // VULNERABILITY: _authorizeUpgrade without access control
    function _authorizeUpgrade(address newImplementation) internal virtual {
        // Missing: require(msg.sender == owner);
        // Anyone can authorize upgrade!
    }

    function upgradeTo(address newImplementation) public {
        _authorizeUpgrade(newImplementation);
        implementation = newImplementation;
    }
}

// ============================================================================
// 2. TRANSPARENT PROXY PATTERN
// ============================================================================

contract VulnerableTransparentProxy {
    address public implementation;
    address public admin;

    constructor(address _implementation, address _admin) {
        implementation = _implementation;
        admin = _admin;
    }

    // VULNERABLE: Missing admin-only restriction
    function upgradeTo(address newImplementation) public {
        // VULNERABILITY: Should be admin-only but isn't protected
        implementation = newImplementation;
    }

    // VULNERABLE: Admin check but no implementation validation
    function adminUpgrade(address newImplementation) public {
        require(msg.sender == admin, "Not admin");
        // VULNERABILITY: No validation of newImplementation
        implementation = newImplementation;
    }

    // VULNERABLE: Delegatecall for non-admin callers
    fallback() external payable {
        // VULNERABILITY: Should prevent admin from calling implementation
        // but this logic is missing or flawed
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

// VULNERABLE: Transparent proxy with selector collision
contract TransparentProxySelectorCollision {
    address public implementation;
    address public admin;

    // VULNERABLE: Function selector might collide with implementation
    function changeAdmin(address newAdmin) public {
        require(msg.sender == admin);
        admin = newAdmin;
    }

    // If implementation has same selector, causes collision
    fallback() external payable {
        // VULNERABILITY: No selector collision protection
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

// ============================================================================
// 3. BEACON PROXY PATTERN
// ============================================================================

interface IBeacon {
    function implementation() external view returns (address);
}

contract VulnerableBeaconProxy {
    address public beacon;

    constructor(address _beacon) {
        beacon = _beacon;
    }

    // VULNERABLE: Beacon upgrade without validation
    function upgradeBeacon(address newBeacon) public {
        // VULNERABILITY: No access control, no validation
        beacon = newBeacon;
    }

    // VULNERABLE: No validation that beacon returns valid implementation
    function _implementation() internal view returns (address) {
        // VULNERABILITY: Assumes beacon.implementation() returns valid address
        return IBeacon(beacon).implementation();
    }

    // VULNERABLE: Delegatecall to potentially invalid implementation
    fallback() external payable {
        address impl = _implementation();
        // VULNERABILITY: No check that impl is valid contract
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

contract VulnerableBeacon {
    address public implementation;
    address public owner;

    constructor(address _implementation) {
        implementation = _implementation;
        owner = msg.sender;
    }

    // VULNERABLE: Beacon upgrade without proper protection
    function upgrade(address newImplementation) public {
        // VULNERABILITY: Weak access control
        require(msg.sender == owner, "Not owner");
        // VULNERABILITY: No validation of newImplementation
        implementation = newImplementation;
    }
}

// ============================================================================
// 4. DIAMOND PROXY PATTERN (EIP-2535)
// ============================================================================

contract VulnerableDiamondProxy {
    struct Facet {
        address facetAddress;
        bytes4[] functionSelectors;
    }

    mapping(bytes4 => address) public selectorToFacet;
    address public owner;

    // VULNERABLE: Add facet without validation
    function addFacet(address facetAddress, bytes4[] memory selectors) public {
        // VULNERABILITY: No access control
        for (uint256 i = 0; i < selectors.length; i++) {
            selectorToFacet[selectors[i]] = facetAddress;
        }
    }

    // VULNERABLE: Replace facet without storage collision check
    function replaceFacet(bytes4 selector, address newFacet) public {
        require(msg.sender == owner, "Not owner");
        // VULNERABILITY: No storage collision validation
        selectorToFacet[selector] = newFacet;
    }

    // VULNERABLE: Delegatecall to facet without validation
    fallback() external payable {
        address facet = selectorToFacet[msg.sig];
        // VULNERABILITY: No check if facet is valid or compatible
        require(facet != address(0), "Function does not exist");

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

// VULNERABLE: Diamond facet with direct storage access
contract VulnerableDiamondFacet {
    // VULNERABILITY: Direct storage declaration causes collision
    uint256 public facetCounter;
    address public facetOwner;

    function incrementCounter() public {
        facetCounter++;
    }

    // This will collide with diamond proxy storage!
}

// VULNERABLE: Diamond without storage isolation
contract DiamondWithoutStoragePattern {
    mapping(bytes4 => address) public selectorToFacet;

    // VULNERABILITY: Missing Diamond Storage pattern
    // Should use: bytes32 constant STORAGE_POSITION = keccak256("diamond.storage");

    uint256 public directStorage; // VULNERABLE: Will collide with facets

    fallback() external payable {
        address facet = selectorToFacet[msg.sig];
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

// ============================================================================
// 5. MINIMAL PROXY (EIP-1167)
// ============================================================================

contract VulnerableMinimalProxy {
    // VULNERABLE: Minimal proxy without initialization protection
    address public implementation;

    function clone(address _implementation) public returns (address proxy) {
        // VULNERABILITY: No validation of implementation
        bytes20 targetBytes = bytes20(_implementation);
        assembly {
            let clone := mload(0x40)
            mstore(clone, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(clone, 0x14), targetBytes)
            mstore(add(clone, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            proxy := create(0, clone, 0x37)
        }
    }

    // VULNERABLE: Clone factory without access control
    function createClone(address target) public returns (address) {
        // VULNERABILITY: Anyone can create clones pointing to any target
        return clone(target);
    }
}

// ============================================================================
// 6. PROXY WITH STORAGE COLLISION
// ============================================================================

contract ProxyWithStorageCollision {
    // Proxy storage layout
    address public implementation; // Slot 0
    address public admin;          // Slot 1

    constructor(address _implementation, address _admin) {
        implementation = _implementation;
        admin = _admin;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

// VULNERABLE: Implementation with mismatched storage
contract MismatchedStorageImplementation {
    // VULNERABILITY: Different storage layout than proxy
    uint256 public counter;      // Slot 0 - collides with proxy.implementation!
    address public owner;        // Slot 1 - collides with proxy.admin!

    function setCounter(uint256 _counter) public {
        // VULNERABILITY: This will overwrite proxy.implementation!
        counter = _counter;
    }

    function setOwner(address _owner) public {
        // VULNERABILITY: This will overwrite proxy.admin!
        owner = _owner;
    }
}

// ============================================================================
// 7. PROXY INITIALIZATION VULNERABILITIES
// ============================================================================

contract VulnerableProxyInitialization {
    address public implementation;
    address public owner;
    bool public initialized;

    constructor(address _implementation) {
        implementation = _implementation;
        // VULNERABILITY: Owner not set in constructor
    }

    // VULNERABLE: Unprotected initialization
    function initialize(address _owner) public {
        // VULNERABILITY: No require(!initialized) check
        owner = _owner;
        initialized = true;
    }

    // VULNERABLE: Re-initialization possible
    function reinitialize(address _owner) public {
        // VULNERABILITY: Can be called even if initialized
        owner = _owner;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

// ============================================================================
// MALICIOUS IMPLEMENTATIONS FOR TESTING
// ============================================================================

contract MaliciousProxyImplementation {
    // Storage layout matches proxy to corrupt it
    address public implementation;
    address public admin;

    function takeOwnership() public {
        // Overwrites proxy's admin
        admin = msg.sender;
    }

    function changeImplementation(address newImpl) public {
        // Overwrites proxy's implementation
        implementation = newImpl;
    }

    function selfDestruct() public {
        selfdestruct(payable(msg.sender));
    }
}
