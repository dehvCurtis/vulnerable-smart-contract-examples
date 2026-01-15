// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableCreate2
 * @notice Test contract for CREATE2 frontrunning vulnerabilities
 *
 * DETECTORS TO TEST:
 * - create2-frontrunning (High)
 *
 * VULNERABILITIES:
 * 1. CREATE2 salt derived from msg.sender only (predictable)
 * 2. CREATE2 salt uses simple counter (predictable address)
 * 3. Public CREATE2 deployment without access control
 * 4. CREATE2 salt not validated (address collision risk)
 * 5. CREATE2 initialization without frontrunning protection
 * 6. Assembly CREATE2 without success check
 * 7. CREATE2 factory without nonce tracking
 * 8. Predictable salt enables address squatting
 */

contract VulnerableCreate2Factory {
    uint256 public deploymentCount;

    event Deployed(address indexed deployed, bytes32 salt);

    // ❌ VULNERABILITY 1: Salt derived from msg.sender only (create2-frontrunning)
    // Address is predictable, can be front-run
    function deploySenderSalt(bytes memory bytecode) external returns (address deployed) {
        // ❌ Salt = msg.sender only
        // Attacker can:
        // 1. See your deployment transaction
        // 2. Calculate the address you'll get
        // 3. Front-run and deploy malicious contract to that address
        // 4. Your deployment fails or deploys to different address

        bytes32 salt = bytes32(uint256(uint160(msg.sender)));

        // ❌ No randomness, no unpredictability
        assembly {
            deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }

        emit Deployed(deployed, salt);
    }

    // ❌ VULNERABILITY 2: Salt uses simple counter (create2-frontrunning)
    // Counter is visible on-chain, address is predictable
    function deployCounterSalt(bytes memory bytecode) external returns (address deployed) {
        // ❌ Counter is predictable!
        bytes32 salt = bytes32(deploymentCount);
        deploymentCount++;

        // Attacker can:
        // 1. Read current counter value
        // 2. Predict next addresses
        // 3. Front-run deployments

        assembly {
            deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }

        emit Deployed(deployed, salt);
    }

    // ❌ VULNERABILITY 3: Public deployment without access control (create2-frontrunning)
    function deployPublic(bytes32 salt, bytes memory bytecode) external returns (address deployed) {
        // ❌ No access control!
        // ❌ No onlyOwner modifier
        // ❌ No whitelist check

        // Anyone can deploy to any address!
        // This enables:
        // 1. Address squatting
        // 2. Malicious contract deployment
        // 3. Address collision attacks

        assembly {
            deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }

        emit Deployed(deployed, salt);
    }

    // ❌ VULNERABILITY 4: Salt not validated (create2-frontrunning)
    function deployNoValidation(bytes32 salt, bytes memory bytecode) external returns (address deployed) {
        // ❌ Salt not checked against used salts!
        // ❌ No require(!usedSalts[salt])

        // Attacker can:
        // 1. Try to reuse salts
        // 2. Cause address collisions
        // 3. Deploy unexpected contracts

        assembly {
            deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }

        // ❌ Missing: usedSalts[salt] = true;

        emit Deployed(deployed, salt);
    }

    // ❌ VULNERABILITY 5: Immediate initialization (create2-frontrunning)
    function deployAndInitialize(
        bytes32 salt,
        bytes memory bytecode,
        bytes memory initData
    ) external returns (address deployed) {
        // Deploy contract
        assembly {
            deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }

        // ❌ Initialize immediately without protection!
        // Attacker can:
        // 1. See the deployment transaction
        // 2. Front-run with their own initialization
        // 3. Take control of the contract

        (bool success,) = deployed.call(initData);
        require(success, "Initialization failed");

        // ❌ Missing: codehash validation
        // ❌ Missing: initialization protection
    }

    // ❌ VULNERABILITY 6: Assembly CREATE2 without success check (create2-frontrunning)
    function deployAssemblyNoCheck(bytes32 salt, bytes memory bytecode) external returns (address deployed) {
        // ❌ No success check after CREATE2!
        assembly {
            deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
            // ❌ Missing: if iszero(deployed) { revert(...) }
        }

        // If deployment fails, deployed = address(0)
        // But contract doesn't check or revert!

        emit Deployed(deployed, salt);
        // Continues execution even if deployment failed!
    }

    // ❌ VULNERABILITY 7: Factory without nonce tracking (create2-frontrunning)
    function deployBatch(bytes[] memory bytecodes) external {
        // ❌ No nonce/counter in salt!
        // ❌ No deployment tracking

        for (uint256 i = 0; i < bytecodes.length; i++) {
            bytes32 salt = keccak256(abi.encodePacked(msg.sender, i));
            bytes memory bytecode = bytecodes[i];

            address deployed;
            assembly {
                deployed := create2(
                    0,
                    add(bytecode, 0x20),
                    mload(bytecode),
                    salt
                )
            }

            // ❌ Salt is predictable from transaction data
            // ❌ Addresses can be calculated in advance
        }
    }

    // ❌ VULNERABILITY 8: Exposed address calculation (informational)
    function computeAddress(
        bytes32 salt,
        bytes32 bytecodeHash
    ) external view returns (address) {
        // Public address calculation is standard for CREATE2
        // But combined with predictable salts, enables:
        // 1. Address squatting
        // 2. Front-running deployments
        // 3. Griefing attacks

        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            salt,
            bytecodeHash
        )))));
    }
}

/**
 * @notice Vulnerable minimal proxy factory
 */
contract VulnerableProxyFactory {
    address public implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    // ❌ VULNERABILITY 9: Clone with predictable salt
    function cloneDeterministic(address account) external returns (address proxy) {
        // ❌ Salt = account address (predictable!)
        bytes32 salt = bytes32(uint256(uint160(account)));

        // ❌ No access control
        // ❌ No salt validation

        bytes memory bytecode = _getMinimalProxyBytecode(implementation);

        assembly {
            proxy := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }

        // ❌ No initialization protection
    }

    function _getMinimalProxyBytecode(address _implementation) internal pure returns (bytes memory) {
        // EIP-1167 minimal proxy bytecode
        return abi.encodePacked(
            hex"3d602d80600a3d3981f3363d3d373d3d3d363d73",
            _implementation,
            hex"5af43d82803e903d91602b57fd5bf3"
        );
    }
}

/**
 * @notice Vulnerable upgradeable factory
 */
contract VulnerableUpgradeableFactory {
    // ❌ VULNERABILITY 10: Upgradeable deployment without protection
    function deployUpgradeable(
        address implementation,
        bytes memory data
    ) external returns (address proxy) {
        // ❌ Salt uses only msg.sender
        bytes32 salt = bytes32(uint256(uint160(msg.sender)));

        // Deploy proxy
        bytes memory bytecode = _getProxyBytecode(implementation);

        assembly {
            proxy := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }

        // ❌ Initialize without protection
        if (data.length > 0) {
            (bool success,) = proxy.call(data);
            require(success, "Initialization failed");
        }

        // Attacker can:
        // 1. Front-run deployment
        // 2. Deploy malicious proxy to same address
        // 3. Front-run initialization
    }

    function _getProxyBytecode(address implementation) internal pure returns (bytes memory) {
        // Simplified proxy bytecode
        return abi.encodePacked(type(ProxyContract).creationCode, abi.encode(implementation));
    }
}

contract ProxyContract {
    address public implementation;

    constructor(address _implementation) {
        implementation = _implementation;
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

/**
 * @notice Secure CREATE2 factory with protections
 */
contract SecureCreate2Factory {
    address public owner;
    mapping(bytes32 => bool) public usedSalts;
    mapping(address => uint256) public nonces;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // ✅ Secure deployment with all protections
    function deploy(bytes memory bytecode) external onlyOwner returns (address deployed) {
        // ✅ Access control with onlyOwner
        // ✅ Unpredictable salt combining multiple sources
        uint256 nonce = nonces[msg.sender];
        nonces[msg.sender]++;

        bytes32 salt = keccak256(abi.encodePacked(
            msg.sender,
            block.timestamp,
            nonce,
            blockhash(block.number - 1)
        ));

        // ✅ Validate salt not used
        require(!usedSalts[salt], "Salt already used");
        usedSalts[salt] = true;

        // ✅ Deploy with success check
        assembly {
            deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
            if iszero(deployed) {
                revert(0, 0)
            }
        }

        // ✅ Additional validation
        require(deployed != address(0), "Deployment failed");
    }

    // ✅ Secure initialization with codehash check
    function deployAndInitialize(
        bytes memory bytecode,
        bytes memory initData,
        bytes32 expectedCodeHash
    ) external onlyOwner returns (address deployed) {
        deployed = this.deploy(bytecode);

        // ✅ Verify deployed contract codehash
        require(deployed.codehash == expectedCodeHash, "Invalid codehash");

        // ✅ Now safe to initialize
        (bool success,) = deployed.call(initData);
        require(success, "Initialization failed");
    }
}
