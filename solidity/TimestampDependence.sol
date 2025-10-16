// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Timestamp Dependence Vulnerability Example
 * @dev VULNERABLE - DO NOT USE IN PRODUCTION
 *
 * This contract uses block.timestamp for critical logic, which can be manipulated
 * by miners within a ~15 second window.
 */
contract VulnerableLottery {
    address public owner;
    uint256 public lotteryEndTime;
    address[] public players;
    uint256 public ticketPrice = 0.1 ether;

    constructor(uint256 _duration) {
        owner = msg.sender;
        lotteryEndTime = block.timestamp + _duration;
    }

    function buyTicket() public payable {
        require(msg.value == ticketPrice, "Incorrect ticket price");
        require(block.timestamp < lotteryEndTime, "Lottery ended");
        players.push(msg.sender);
    }

    // VULNERABLE: Uses block.timestamp for random number generation
    function drawWinner() public {
        require(block.timestamp >= lotteryEndTime, "Lottery not ended yet");
        require(players.length > 0, "No players");

        // VULNERABILITY: Miners can manipulate block.timestamp
        uint256 randomIndex = uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty))) % players.length;
        address winner = players[randomIndex];

        payable(winner).transfer(address(this).balance);
        delete players;
        lotteryEndTime = block.timestamp + 1 days;
    }
}

/**
 * @title Time-Based Access Control Vulnerability
 * @dev Shows timestamp manipulation for access control
 */
contract VulnerableTimelock {
    mapping(address => uint256) public lockTime;
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        // Lock for 1 week
        lockTime[msg.sender] = block.timestamp + 1 weeks;
    }

    // VULNERABLE: Relies on block.timestamp for security
    function withdraw() public {
        require(balances[msg.sender] > 0, "No balance");
        // VULNERABILITY: Miner can manipulate timestamp by ~15 seconds
        require(block.timestamp >= lockTime[msg.sender], "Funds locked");

        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    // VULNERABLE: Time-based access control
    function emergencyWithdraw() public {
        // VULNERABILITY: Attacker miner can manipulate timing
        require(block.timestamp % 2 == 0, "Can only withdraw on even seconds");
        payable(msg.sender).transfer(balances[msg.sender]);
        balances[msg.sender] = 0;
    }
}

/**
 * @title Randomness from Block Variables
 * @dev Shows vulnerability in using block variables for randomness
 */
contract VulnerableRandomness {
    uint256 public lastWinningNumber;

    // VULNERABLE: Predictable random number generation
    function generateRandomNumber() public returns (uint256) {
        // VULNERABILITY: All block variables are known/predictable
        uint256 random = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.difficulty,
            block.number,
            msg.sender
        ))) % 100;

        lastWinningNumber = random;
        return random;
    }

    function playGame() public payable returns (bool) {
        require(msg.value == 0.01 ether, "Must bet 0.01 ether");

        uint256 winningNumber = generateRandomNumber();

        // If number is > 50, player wins
        if (winningNumber > 50) {
            payable(msg.sender).transfer(0.02 ether);
            return true;
        }
        return false;
    }

    receive() external payable {}
}
