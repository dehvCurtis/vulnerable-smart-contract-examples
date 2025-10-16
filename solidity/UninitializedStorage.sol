// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * @title Uninitialized Storage Pointer Vulnerability Example
 * @dev VULNERABLE - DO NOT USE IN PRODUCTION
 *
 * This vulnerability was more prevalent in older Solidity versions (< 0.5.0)
 * where storage pointers could be uninitialized, pointing to slot 0.
 *
 * In Solidity 0.5.0+, this produces a compiler warning/error, but the
 * vulnerability can still occur with improper struct usage.
 */
contract VulnerableStorage {
    address public owner;  // Slot 0
    uint256 public totalSupply;  // Slot 1
    mapping(address => uint256) public balances;  // Slot 2

    struct User {
        address addr;
        uint256 balance;
        bool active;
    }

    User[] public users;

    constructor() {
        owner = msg.sender;
        totalSupply = 1000000;
    }

    // VULNERABLE: Uninitialized struct in memory defaults to storage slot 0
    function addUser(address _addr, uint256 _balance) public {
        // In older Solidity, this would point to slot 0 (owner)
        User memory newUser;
        newUser.addr = _addr;
        newUser.balance = _balance;
        newUser.active = true;

        users.push(newUser);
    }

    // VULNERABLE: Array manipulation without proper bounds checking
    function updateUser(uint256 _index, address _addr) public {
        // VULNERABILITY: No bounds checking
        User storage user = users[_index];
        user.addr = _addr;
    }
}

/**
 * @title Uninitialized Storage in Loop
 * @dev Shows vulnerability with storage pointers in loops
 */
contract VulnerableArray {
    address public owner;
    uint256 public value;

    struct Item {
        address owner;
        uint256 amount;
    }

    Item[] public items;

    constructor() {
        owner = msg.sender;
        value = 100;
    }

    // VULNERABLE: Storage pointer in loop
    function processItems() public {
        // VULNERABILITY: If items array is empty, this could cause issues
        for (uint256 i = 0; i < items.length; i++) {
            Item storage item = items[i];
            // In certain conditions, this could access wrong storage slots
            item.amount += 10;
        }
    }

    function addItem(address _owner, uint256 _amount) public {
        items.push(Item(_owner, _amount));
    }
}

/**
 * @title Default Visibility Vulnerability
 * @dev Shows how default visibility can cause security issues
 */
contract VulnerableVisibility {
    address owner;  // Default internal visibility in Solidity 0.5.0+, public before
    uint256 secret;  // Default internal

    constructor() {
        owner = msg.sender;
        secret = 12345;
    }

    // VULNERABLE: State variable with implicit visibility
    // In older versions, this would be public by default

    // VULNERABLE: Function without explicit visibility (pre 0.5.0 defaults to public)
    function changeOwner(address _newOwner) public {
        // In Solidity < 0.5.0, forgetting 'public' keyword made this public anyway
        owner = _newOwner;
    }

    // VULNERABLE: This should probably be internal or private
    function resetSecret() public {
        secret = 0;
    }
}

/**
 * @title Uninitialized Storage Pointer Exploit Example
 * @dev Historic vulnerability showing storage collision
 */
contract StorageCollision {
    address public owner;  // Slot 0
    uint256 public balance;  // Slot 1

    struct Transaction {
        address recipient;
        uint256 amount;
    }

    Transaction[] public transactions;

    constructor() {
        owner = msg.sender;
        balance = 1000;
    }

    // VULNERABLE: In Solidity < 0.5.0, uninitialized storage pointers
    // could overwrite critical state variables
    function createTransaction(address _recipient, uint256 _amount) public {
        // Old vulnerability: This could point to slot 0 and overwrite owner
        Transaction memory txn;
        txn.recipient = _recipient;
        txn.amount = _amount;
        transactions.push(txn);
    }
}

/**
 * @title Delete Mapping Vulnerability
 * @dev Shows that deleting a struct with mappings doesn't clear the mapping
 */
contract VulnerableMapping {
    struct User {
        uint256 id;
        mapping(address => uint256) approvals;
    }

    mapping(address => User) public users;

    function createUser(uint256 _id) public {
        users[msg.sender].id = _id;
    }

    function approve(address _spender, uint256 _amount) public {
        users[msg.sender].approvals[_spender] = _amount;
    }

    // VULNERABLE: Delete doesn't clear nested mappings
    function deleteUser() public {
        // VULNERABILITY: The approvals mapping is NOT deleted
        // _spender can still access their approval even after user is "deleted"
        delete users[msg.sender];
    }

    function getApproval(address _user, address _spender) public view returns (uint256) {
        return users[_user].approvals[_spender];
    }
}

/**
 * @title Storage Array Deletion
 * @dev Shows issues with deleting array elements
 */
contract VulnerableArrayDeletion {
    address public owner;
    uint256[] public values;

    constructor() {
        owner = msg.sender;
    }

    function addValue(uint256 _value) public {
        values.push(_value);
    }

    // VULNERABLE: Delete on array element leaves a gap
    function deleteValue(uint256 _index) public {
        require(_index < values.length, "Index out of bounds");
        // VULNERABILITY: This sets values[_index] to 0 but doesn't remove it
        // Array length stays the same, creating a "hole"
        delete values[_index];
    }

    // VULNERABLE: Accessing deleted elements
    function getValue(uint256 _index) public view returns (uint256) {
        // Will return 0 for deleted elements, but index is still valid
        return values[_index];
    }
}
