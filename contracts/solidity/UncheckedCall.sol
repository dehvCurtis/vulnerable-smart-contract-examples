// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Unchecked External Call Vulnerability Example
 * @dev VULNERABLE - DO NOT USE IN PRODUCTION
 *
 * This contract fails to check return values of external calls.
 */
contract VulnerablePayment {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: Unchecked low-level call
    function withdrawUnchecked(address payable _recipient, uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        balances[msg.sender] -= _amount;

        // VULNERABILITY: Return value not checked
        _recipient.call{value: _amount}("");
        // If the call fails, the user loses their balance!
    }

    // VULNERABLE: Unchecked send
    function withdrawWithSend(address payable _recipient, uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        balances[msg.sender] -= _amount;

        // VULNERABILITY: send() returns false on failure but we don't check it
        _recipient.send(_amount);
    }

    // VULNERABLE: Multiple unchecked calls
    function batchPayout(address payable[] memory _recipients, uint256[] memory _amounts) public {
        require(_recipients.length == _amounts.length, "Length mismatch");

        for (uint256 i = 0; i < _recipients.length; i++) {
            // VULNERABILITY: If one call fails, the loop continues
            _recipients[i].call{value: _amounts[i]}("");
        }
    }
}

/**
 * @title Unchecked External Contract Call
 * @dev Shows vulnerability with external contract interactions
 */
interface IExternalContract {
    function executeAction(address user) external returns (bool);
}

contract VulnerableIntegration {
    IExternalContract public externalContract;
    mapping(address => uint256) public rewards;

    constructor(address _externalContract) {
        externalContract = IExternalContract(_externalContract);
    }

    // VULNERABLE: Assumes external call succeeds
    function claimReward() public {
        uint256 reward = rewards[msg.sender];
        require(reward > 0, "No reward");

        // VULNERABILITY: Doesn't check return value
        externalContract.executeAction(msg.sender);

        // Reward is cleared even if external call failed
        rewards[msg.sender] = 0;
        payable(msg.sender).transfer(reward);
    }

    function setReward(address _user, uint256 _amount) public {
        rewards[_user] = _amount;
    }

    receive() external payable {}
}

/**
 * @title Malicious Receiver
 * @dev Contract that always rejects payments to exploit unchecked calls
 */
contract MaliciousReceiver {
    // Always rejects payments
    receive() external payable {
        revert("Payment rejected");
    }

    // This function can drain the VulnerablePayment contract
    function attack(address _vulnerableContract, uint256 _amount) public {
        VulnerablePayment vulnerable = VulnerablePayment(_vulnerableContract);

        // Deposit funds
        vulnerable.deposit{value: _amount}();

        // Withdraw using unchecked call - balance will be deducted
        // but payment will fail, and we can do it again
        vulnerable.withdrawUnchecked(payable(address(this)), _amount);
    }
}
