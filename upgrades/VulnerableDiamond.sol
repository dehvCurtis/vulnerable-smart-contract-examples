// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableDiamond
 * @notice Test contract for EIP-2535 Diamond pattern vulnerabilities
 *
 * DETECTORS TO TEST:
 * - diamond-storage-collision (Critical)
 * - diamond-delegatecall-zero (Critical)
 * - diamond-init-reentrancy (High)
 *
 * VULNERABILITIES:
 * 1. Diamond storage collision between facets
 * 2. Delegatecall to zero address in diamond
 * 3. Reentrancy in diamond initialization
 * 4. Missing storage collision protection
 * 5. Facet selector collision
 * 6. Unprotected facet replacement
 */

/**
 * @notice Diamond cut structure
 */
struct FacetCut {
    address facetAddress;
    uint8 action; // 0=Add, 1=Replace, 2=Remove
    bytes4[] functionSelectors;
}

/**
 * @notice Vulnerable diamond with storage collision
 */
contract VulnerableDiamondStorage {
    // ❌ VULNERABILITY 1: Diamond storage NOT using namespaced pattern (diamond-storage-collision)
    // Facets will collide with each other's storage!

    struct DiamondStorage {
        mapping(bytes4 => address) selectorToFacet;
        address owner;
        // ❌ Regular storage layout - facets can collide!
    }

    DiamondStorage internal diamondStorage;

    // ❌ Facet A storage
    uint256 public facetAValue;

    // ❌ Facet B storage
    address public facetBAddress;

    // ❌ Storage collision likely between facets!

    function diamondCut(FacetCut[] calldata cuts) external {
        for (uint256 i = 0; i < cuts.length; i++) {
            FacetCut memory cut = cuts[i];

            for (uint256 j = 0; j < cut.functionSelectors.length; j++) {
                diamondStorage.selectorToFacet[cut.functionSelectors[j]] = cut.facetAddress;
            }
        }
    }

    fallback() external payable {
        address facet = diamondStorage.selectorToFacet[msg.sig];

        // ❌ VULNERABILITY 2: No check for zero address! (diamond-delegatecall-zero)
        // Delegatecall to address(0) causes unexpected behavior!

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

/**
 * @notice Facet A with regular storage
 */
contract VulnerableFacetA {
    // ❌ VULNERABILITY 3: Storage collision! (diamond-storage-collision)
    // Slot 0: value (collides with diamondStorage in diamond!)
    uint256 public value;

    // Slot 1: owner (collides!)
    address public owner;

    function setValue(uint256 _value) external {
        value = _value;
    }

    function getValue() external view returns (uint256) {
        return value;
    }
}

/**
 * @notice Facet B with storage collision
 */
contract VulnerableFacetB {
    // ❌ VULNERABILITY 4: Storage collision with Facet A! (diamond-storage-collision)
    // Slot 0: data (collides with Facet A's value!)
    bytes32 public data;

    // Slot 1: authorized (collides with Facet A's owner!)
    bool public authorized;

    function setData(bytes32 _data) external {
        data = _data;
    }

    function getData() external view returns (bytes32) {
        return data;
    }
}

/**
 * @notice Diamond with delegatecall to zero
 */
contract VulnerableDiamondZeroAddress {
    mapping(bytes4 => address) public selectorToFacet;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function addFunction(bytes4 selector, address facet) external {
        require(msg.sender == owner);
        selectorToFacet[selector] = facet;
    }

    function removeFunction(bytes4 selector) external {
        require(msg.sender == owner);
        // ❌ VULNERABILITY 5: Sets to zero but doesn't remove from mapping (diamond-delegatecall-zero)
        selectorToFacet[selector] = address(0);
        // Should: delete selectorToFacet[selector];
    }

    fallback() external payable {
        address facet = selectorToFacet[msg.sig];

        // ❌ VULNERABILITY 6: Delegatecall to potentially zero address (diamond-delegatecall-zero)
        // If function removed, facet = address(0)
        // Delegatecall to address(0) has undefined behavior!

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

/**
 * @notice Diamond with initialization reentrancy
 */
contract VulnerableDiamondInit {
    bool public initialized;
    mapping(bytes4 => address) public selectorToFacet;
    address public owner;

    // ❌ VULNERABILITY 7: Initialization reentrancy (diamond-init-reentrancy)
    function initialize(address _owner, address[] calldata facets, bytes[] calldata initData) external {
        require(!initialized, "Already initialized");

        // ❌ initialized set AFTER external calls!
        // Attacker can re-enter during facet initialization!

        owner = _owner;

        // Initialize each facet
        for (uint256 i = 0; i < facets.length; i++) {
            // ❌ External call BEFORE setting initialized flag!
            (bool success,) = facets[i].delegatecall(initData[i]);
            require(success, "Init failed");
        }

        // ❌ Too late - already re-entered!
        initialized = true;
    }

    fallback() external payable {
        address facet = selectorToFacet[msg.sig];
        require(facet != address(0), "Function not found");

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

/**
 * @notice Malicious facet for reentrancy attack
 */
contract MaliciousFacetReentrancy {
    function init() external {
        // ❌ Calls back to diamond during initialization!
        // Can call initialize() again since not yet set!
        VulnerableDiamondInit diamond = VulnerableDiamondInit(address(this));

        // Re-enter (if not already in recursion)
        if (!diamond.initialized()) {
            address[] memory facets = new address[](0);
            bytes[] memory initData = new bytes[](0);
            diamond.initialize(msg.sender, facets, initData);
        }
    }
}

/**
 * @notice Diamond with selector collision
 */
contract VulnerableDiamondSelectors {
    mapping(bytes4 => address) public selectorToFacet;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // ❌ VULNERABILITY 8: No selector collision check (diamond-storage-collision)
    function addFacet(bytes4[] calldata selectors, address facet) external {
        require(msg.sender == owner);

        for (uint256 i = 0; i < selectors.length; i++) {
            // ❌ Overwrites existing selector without warning!
            // ❌ No check: require(selectorToFacet[selectors[i]] == address(0))
            // Can accidentally replace critical functions!

            selectorToFacet[selectors[i]] = facet;
        }
    }

    fallback() external payable {
        address facet = selectorToFacet[msg.sig];
        require(facet != address(0));

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

/**
 * @notice Secure diamond implementation with namespaced storage
 */
contract SecureDiamond {
    // ✅ Namespaced storage pattern (EIP-2535)
    bytes32 constant DIAMOND_STORAGE_POSITION = keccak256("diamond.standard.diamond.storage");

    struct DiamondStorage {
        mapping(bytes4 => address) selectorToFacet;
        mapping(address => bool) supportedInterfaces;
        address contractOwner;
    }

    // ✅ Get storage from fixed slot
    function diamondStorage() internal pure returns (DiamondStorage storage ds) {
        bytes32 position = DIAMOND_STORAGE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    event DiamondCut(FacetCut[] cuts, address init, bytes initData);

    constructor() {
        diamondStorage().contractOwner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == diamondStorage().contractOwner, "Not owner");
        _;
    }

    // ✅ Secure diamond cut with validation
    function diamondCut(
        FacetCut[] calldata cuts,
        address init,
        bytes calldata initData
    ) external onlyOwner {
        for (uint256 i = 0; i < cuts.length; i++) {
            FacetCut memory cut = cuts[i];

            // ✅ Validate facet address
            require(cut.facetAddress != address(0) || cut.action == 2, "Invalid facet");

            for (uint256 j = 0; j < cut.functionSelectors.length; j++) {
                bytes4 selector = cut.functionSelectors[j];

                if (cut.action == 0) {
                    // Add
                    require(diamondStorage().selectorToFacet[selector] == address(0), "Selector exists");
                    diamondStorage().selectorToFacet[selector] = cut.facetAddress;
                } else if (cut.action == 1) {
                    // Replace
                    require(diamondStorage().selectorToFacet[selector] != address(0), "Selector not found");
                    diamondStorage().selectorToFacet[selector] = cut.facetAddress;
                } else if (cut.action == 2) {
                    // Remove
                    require(diamondStorage().selectorToFacet[selector] != address(0), "Selector not found");
                    delete diamondStorage().selectorToFacet[selector];
                }
            }
        }

        emit DiamondCut(cuts, init, initData);

        // ✅ Initialize after cuts if needed
        if (init != address(0)) {
            (bool success, bytes memory error) = init.delegatecall(initData);
            require(success, string(error));
        }
    }

    fallback() external payable {
        DiamondStorage storage ds = diamondStorage();
        address facet = ds.selectorToFacet[msg.sig];

        // ✅ Check for zero address
        require(facet != address(0), "Function not found");

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

/**
 * @notice Secure facet with namespaced storage
 */
contract SecureFacet {
    // ✅ Namespaced storage for this facet
    bytes32 constant FACET_STORAGE_POSITION = keccak256("facet.storage.position");

    struct FacetStorage {
        uint256 value;
        address owner;
        mapping(address => uint256) balances;
    }

    function facetStorage() internal pure returns (FacetStorage storage fs) {
        bytes32 position = FACET_STORAGE_POSITION;
        assembly {
            fs.slot := position
        }
    }

    function setValue(uint256 _value) external {
        facetStorage().value = _value;
    }

    function getValue() external view returns (uint256) {
        return facetStorage().value;
    }

    function setBalance(address user, uint256 amount) external {
        facetStorage().balances[user] = amount;
    }

    function getBalance(address user) external view returns (uint256) {
        return facetStorage().balances[user];
    }
}
