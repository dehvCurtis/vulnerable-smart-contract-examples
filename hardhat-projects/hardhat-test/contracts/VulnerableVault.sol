// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title VulnerableVault
 * @notice Intentionally vulnerable contract for testing Hardhat project scanning
 */
contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalSupply;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    // Missing zero address check - HIGH
    function deposit(address to) public payable {
        balances[to] += msg.value;
        totalSupply += msg.value;
        emit Deposit(to, msg.value);
    }

    // Reentrancy vulnerability - CRITICAL
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call before state update - reentrancy!
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
        totalSupply -= amount;
        emit Withdrawal(msg.sender, amount);
    }

    // Missing access control - HIGH
    function mint(address to, uint256 amount) public {
        balances[to] += amount;
        totalSupply += amount;
    }

    // Unchecked return value - MEDIUM
    function withdrawToAddress(address payable recipient, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        totalSupply -= amount;

        // Unchecked low-level call
        recipient.call{value: amount}("");
    }

    // Missing access control on ownership transfer - CRITICAL
    function changeOwner(address newOwner) public {
        owner = newOwner;
    }

    // Centralization risk - owner can drain all funds
    function emergencyWithdraw() public {
        require(msg.sender == owner, "Not owner");
        (bool success, ) = owner.call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
    }
}
