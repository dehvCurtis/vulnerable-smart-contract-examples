// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Access Control Vulnerability Example
 * @dev VULNERABLE - DO NOT USE IN PRODUCTION
 *
 * This contract has multiple access control vulnerabilities.
 */
contract VulnerableWallet {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: Missing access control modifier
    function changeOwner(address _newOwner) public {
        // Anyone can call this and become the owner!
        owner = _newOwner;
    }

    // VULNERABLE: tx.origin authentication
    function withdrawAll(address _recipient) public {
        // VULNERABILITY: Uses tx.origin instead of msg.sender
        require(tx.origin == owner, "Not owner");
        payable(_recipient).transfer(address(this).balance);
    }

    // VULNERABLE: Unprotected initialization
    bool public initialized;

    function initialize(address _owner) public {
        // VULNERABILITY: Can be called by anyone if not initialized
        // Missing require(!initialized) check
        owner = _owner;
        initialized = true;
    }

    // VULNERABLE: Delegate call to user-supplied address
    function execute(address _target, bytes memory _data) public returns (bytes memory) {
        // VULNERABILITY: Anyone can execute arbitrary code in the context of this contract
        (bool success, bytes memory result) = _target.delegatecall(_data);
        require(success, "Execution failed");
        return result;
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}

/**
 * @title Phishing Attack using tx.origin
 * @dev Shows how tx.origin vulnerability can be exploited
 */
contract PhishingAttacker {
    VulnerableWallet public vulnerableWallet;
    address public attackerAddress;

    constructor(address _vulnerableWalletAddress) {
        vulnerableWallet = VulnerableWallet(_vulnerableWalletAddress);
        attackerAddress = msg.sender;
    }

    // Victim calls this thinking it's legitimate
    function claimReward() public {
        // When victim calls this, tx.origin is still the victim
        // but this contract calls withdrawAll
        vulnerableWallet.withdrawAll(attackerAddress);
    }
}

/**
 * @title Missing Access Control on Critical Function
 * @dev Shows unprotected state-changing functions
 */
contract VulnerableAuction {
    address public highestBidder;
    uint256 public highestBid;
    address public beneficiary;

    constructor() {
        beneficiary = msg.sender;
    }

    function bid() public payable {
        require(msg.value > highestBid, "Bid too low");
        highestBidder = msg.sender;
        highestBid = msg.value;
    }

    // VULNERABLE: No access control
    function endAuction() public {
        // Anyone can end the auction!
        payable(beneficiary).transfer(address(this).balance);
    }

    // VULNERABLE: No access control on critical state change
    function setBeneficiary(address _beneficiary) public {
        // Anyone can change the beneficiary!
        beneficiary = _beneficiary;
    }
}
