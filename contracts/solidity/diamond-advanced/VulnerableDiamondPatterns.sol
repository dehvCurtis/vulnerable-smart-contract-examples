// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Diamond Pattern Advanced Vulnerabilities
 * @notice Tests advanced EIP-2535 Diamond Standard detectors
 * @dev Tests: diamond-delegatecall-zero, diamond-loupe-violation
 */

// =====================================================================
// 1. DIAMOND DELEGATECALL TO ZERO ADDRESS
// =====================================================================

/**
 * @dev Diamond proxy with delegatecall to zero address vulnerability
 * EIP-2535 Diamond Standard allows multiple facets, but must validate addresses
 */
contract VulnerableDiamondDelegatecall {
    struct FacetCut {
        address facetAddress;
        uint8 action; // 0=add, 1=replace, 2=remove
        bytes4[] functionSelectors;
    }

    // Mapping from function selector to facet address
    mapping(bytes4 => address) public selectorToFacet;

    // ❌ VULNERABILITY 1: Delegatecall to zero address
    fallback() external payable {
        address facet = selectorToFacet[msg.sig];

        // ❌ No check if facet is zero address!
        // If selector not found, facet will be address(0)
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    // ❌ VULNERABILITY 2: Diamond cut without zero address check
    function diamondCut(FacetCut[] calldata cuts) external {
        for (uint256 i = 0; i < cuts.length; i++) {
            FacetCut memory cut = cuts[i];

            // ❌ Missing: require(cut.facetAddress != address(0), "Zero address");

            for (uint256 j = 0; j < cut.functionSelectors.length; j++) {
                bytes4 selector = cut.functionSelectors[j];

                if (cut.action == 0) { // Add
                    selectorToFacet[selector] = cut.facetAddress;
                } else if (cut.action == 1) { // Replace
                    selectorToFacet[selector] = cut.facetAddress;
                } else if (cut.action == 2) { // Remove
                    // ❌ Sets to zero address without validation!
                    selectorToFacet[selector] = address(0);
                }
            }
        }
    }

    // ❌ VULNERABILITY 3: Direct delegatecall without facet validation
    function executeOnFacet(address facet, bytes calldata data) external payable {
        // ❌ No validation that facet is non-zero
        // ❌ No validation that facet is a registered facet

        (bool success, bytes memory result) = facet.delegatecall(data);
        require(success, "Delegatecall failed");
    }
}

// =====================================================================
// 2. DIAMOND LOUPE VIOLATION
// =====================================================================

/**
 * @dev Diamond contract violating EIP-2535 Loupe standard
 * The Loupe is required for transparency and discoverability
 */

// IDiamondLoupe interface from EIP-2535
interface IDiamondLoupe {
    struct Facet {
        address facetAddress;
        bytes4[] functionSelectors;
    }

    function facets() external view returns (Facet[] memory facets_);
    function facetFunctionSelectors(address _facet) external view returns (bytes4[] memory facetFunctionSelectors_);
    function facetAddresses() external view returns (address[] memory facetAddresses_);
    function facetAddress(bytes4 _functionSelector) external view returns (address facetAddress_);
}

/**
 * @dev Diamond contract WITHOUT implementing IDiamondLoupe
 * ❌ VIOLATION: EIP-2535 requires IDiamondLoupe implementation
 */
contract VulnerableDiamondNoLoupe {
    struct FacetCut {
        address facetAddress;
        uint8 action;
        bytes4[] functionSelectors;
    }

    mapping(bytes4 => address) public selectorToFacet;
    address[] private facetAddressList;

    // ❌ VIOLATION 1: No IDiamondLoupe interface support
    // Missing: contract VulnerableDiamondNoLoupe is IDiamondLoupe

    // ❌ VIOLATION 2: No supportsInterface check
    // Missing ERC-165 implementation

    fallback() external payable {
        address facet = selectorToFacet[msg.sig];
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

    function diamondCut(FacetCut[] calldata cuts) external {
        for (uint256 i = 0; i < cuts.length; i++) {
            FacetCut memory cut = cuts[i];
            require(cut.facetAddress != address(0), "Zero address");

            for (uint256 j = 0; j < cut.functionSelectors.length; j++) {
                selectorToFacet[cut.functionSelectors[j]] = cut.facetAddress;
            }

            facetAddressList.push(cut.facetAddress);
        }
    }

    // ❌ VIOLATION 3: Missing required loupe functions
    // Required by EIP-2535:
    // - facets()
    // - facetFunctionSelectors(address)
    // - facetAddresses()
    // - facetAddress(bytes4)
}

/**
 * @dev Diamond with incomplete IDiamondLoupe implementation
 */
contract VulnerableDiamondIncompleteLoupe is IDiamondLoupe {
    mapping(bytes4 => address) public selectorToFacet;
    address[] private facetAddressList;

    // ❌ VIOLATION 1: Incomplete facets() implementation
    function facets() external view override returns (Facet[] memory) {
        // ❌ Returns empty array instead of actual facets
        return new Facet[](0);
    }

    // ❌ VIOLATION 2: Incorrect facetFunctionSelectors implementation
    function facetFunctionSelectors(address) external pure override returns (bytes4[] memory) {
        // ❌ Returns empty array for all facets
        return new bytes4[](0);
    }

    // ❌ VIOLATION 3: Incorrect facetAddresses implementation
    function facetAddresses() external view override returns (address[] memory) {
        // ❌ Returns array with duplicates
        return facetAddressList;
    }

    // ❌ VIOLATION 4: Missing validation in facetAddress
    function facetAddress(bytes4 _functionSelector) external view override returns (address) {
        // ❌ No validation, returns address(0) for unknown selectors
        return selectorToFacet[_functionSelector];
    }

    fallback() external payable {
        address facet = selectorToFacet[msg.sig];
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

/**
 * @dev Diamond with loupe that returns stale/incorrect data
 */
contract VulnerableDiamondStaleLoupe is IDiamondLoupe {
    struct FacetCut {
        address facetAddress;
        uint8 action;
        bytes4[] functionSelectors;
    }

    mapping(bytes4 => address) public selectorToFacet;
    mapping(address => bytes4[]) private facetToSelectors;
    address[] private facetAddressList;

    // ❌ VIOLATION: Loupe data not updated when facets change
    Facet[] private cachedFacets; // Never updated!

    function diamondCut(FacetCut[] calldata cuts) external {
        for (uint256 i = 0; i < cuts.length; i++) {
            FacetCut memory cut = cuts[i];

            for (uint256 j = 0; j < cut.functionSelectors.length; j++) {
                bytes4 selector = cut.functionSelectors[j];

                if (cut.action == 0 || cut.action == 1) {
                    selectorToFacet[selector] = cut.facetAddress;
                    facetToSelectors[cut.facetAddress].push(selector);
                } else if (cut.action == 2) {
                    delete selectorToFacet[selector];
                }
            }

            facetAddressList.push(cut.facetAddress);
        }

        // ❌ VIOLATION: cachedFacets never updated!
    }

    // ❌ VIOLATION: Returns stale cached data
    function facets() external view override returns (Facet[] memory) {
        return cachedFacets; // Stale data!
    }

    function facetFunctionSelectors(address _facet) external view override returns (bytes4[] memory) {
        return facetToSelectors[_facet];
    }

    function facetAddresses() external view override returns (address[] memory) {
        return facetAddressList;
    }

    function facetAddress(bytes4 _functionSelector) external view override returns (address) {
        return selectorToFacet[_functionSelector];
    }

    fallback() external payable {
        address facet = selectorToFacet[msg.sig];
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

// =====================================================================
// 3. COMBINED DIAMOND VULNERABILITIES
// =====================================================================

/**
 * @dev Diamond with multiple vulnerabilities
 */
contract VulnerableDiamondCombined {
    struct FacetCut {
        address facetAddress;
        uint8 action;
        bytes4[] functionSelectors;
    }

    mapping(bytes4 => address) public selectorToFacet;

    // ❌ No IDiamondLoupe implementation
    // ❌ No ERC-165 support

    // ❌ VULNERABILITY 1: Delegatecall to zero address
    fallback() external payable {
        address facet = selectorToFacet[msg.sig];
        // ❌ No zero address check

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    // ❌ VULNERABILITY 2: Diamond cut with zero address
    function diamondCut(FacetCut[] calldata cuts) external {
        for (uint256 i = 0; i < cuts.length; i++) {
            FacetCut memory cut = cuts[i];

            // ❌ No zero address validation

            for (uint256 j = 0; j < cut.functionSelectors.length; j++) {
                bytes4 selector = cut.functionSelectors[j];

                if (cut.action == 2) {
                    // ❌ Remove sets to zero address
                    selectorToFacet[selector] = address(0);
                } else {
                    selectorToFacet[selector] = cut.facetAddress;
                }
            }
        }
    }

    // ❌ VULNERABILITY 3: No access control on diamond cut
    // Anyone can modify the diamond!

    // ❌ VULNERABILITY 4: No initialization protection
    // Diamond can be re-initialized multiple times
}

/**
 * TESTING NOTES:
 *
 * Expected Detectors:
 * 1. diamond-delegatecall-zero (6+ findings)
 *    - Delegatecall to zero address in fallback
 *    - Diamond cut setting zero addresses
 *    - No validation before delegatecall
 *
 * 2. diamond-loupe-violation (8+ findings)
 *    - Missing IDiamondLoupe implementation
 *    - Incomplete loupe functions
 *    - Stale loupe data
 *    - Missing ERC-165 support
 *
 * Cross-Category Detectors Expected:
 * - diamond-storage-collision (from previous tests)
 * - diamond-selector-collision (from previous tests)
 * - diamond-init-reentrancy (from previous tests)
 * - dangerous-delegatecall
 * - missing-access-modifiers
 * - upgradeable-proxy-issues
 *
 * Real-World Relevance:
 * - EIP-2535 is used by major protocols (Aavegotchi, etc.)
 * - Delegatecall to zero can brick entire diamond
 * - Missing loupe makes diamonds non-transparent
 * - EIP-2535 compliance is critical for interoperability
 */
