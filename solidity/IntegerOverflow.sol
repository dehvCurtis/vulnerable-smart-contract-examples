// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * @title Integer Overflow/Underflow Vulnerability Example
 * @dev VULNERABLE - DO NOT USE IN PRODUCTION
 *
 * This contract uses Solidity 0.7.6 which doesn't have automatic overflow checks.
 * In Solidity 0.8.0+, overflow checks are automatic, but this shows the vulnerability
 * in older versions or when using unchecked blocks.
 */
contract VulnerableToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    constructor(uint256 _initialSupply) {
        balances[msg.sender] = _initialSupply;
        totalSupply = _initialSupply;
    }

    // VULNERABLE: No overflow check on addition
    function transfer(address _to, uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");

        // VULNERABILITY: Can overflow if balances[_to] + _amount > type(uint256).max
        balances[msg.sender] -= _amount;
        balances[_to] += _amount;
    }

    // VULNERABLE: Underflow attack possible
    function batchTransfer(address[] memory _receivers, uint256 _value) public {
        uint256 count = _receivers.length;
        // VULNERABILITY: count * _value can overflow
        uint256 amount = count * _value;
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        for (uint256 i = 0; i < count; i++) {
            balances[_receivers[i]] += _value;
        }
    }

    // VULNERABLE: Can underflow
    function withdrawReward(uint256 _reward) public {
        // VULNERABILITY: If _reward > balances[msg.sender], this underflows
        balances[msg.sender] -= _reward;
    }
}

/**
 * @title Integer Overflow in Solidity 0.8.0+
 * @dev Shows overflow vulnerability when using unchecked blocks
 */
contract UncheckedOverflow {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: Using unchecked block bypasses overflow protection
    function unsafeMultiply(uint256 amount, uint256 multiplier) public view returns (uint256) {
        unchecked {
            // VULNERABILITY: Can overflow without reverting
            return amount * multiplier;
        }
    }

    function vulnerableWithdraw(uint256 amount) public {
        unchecked {
            // VULNERABILITY: Can underflow
            balances[msg.sender] -= amount;
        }
        payable(msg.sender).transfer(amount);
    }
}
