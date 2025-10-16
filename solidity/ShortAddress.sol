// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Short Address Attack Vulnerability Example
 * @dev VULNERABLE - DO NOT USE IN PRODUCTION
 *
 * This vulnerability occurs when an ERC20 token contract doesn't validate
 * the length of the address parameter, allowing attackers to manipulate
 * the amount by sending a shorter address.
 *
 * Note: This is primarily a client-side vulnerability but contracts should
 * implement proper validation.
 */
contract VulnerableToken {
    mapping(address => uint256) public balances;
    string public name = "Vulnerable Token";
    string public symbol = "VULN";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(uint256 _initialSupply) {
        totalSupply = _initialSupply;
        balances[msg.sender] = _initialSupply;
    }

    // VULNERABLE: No length validation on address parameters
    function transfer(address _to, uint256 _value) public returns (bool) {
        // VULNERABILITY: If _to address is short (missing trailing zeros),
        // the EVM will pad it, and _value might get shifted
        require(balances[msg.sender] >= _value, "Insufficient balance");

        balances[msg.sender] -= _value;
        balances[_to] += _value;

        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    // VULNERABLE: Batch transfer without proper validation
    function batchTransfer(address[] memory _receivers, uint256 _value) public returns (bool) {
        // VULNERABILITY: No validation on address array length
        uint256 count = _receivers.length;
        uint256 amount = _value * count;

        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;

        for (uint256 i = 0; i < count; i++) {
            balances[_receivers[i]] += _value;
            emit Transfer(msg.sender, _receivers[i], _value);
        }

        return true;
    }
}

/**
 * @title Missing Input Validation
 * @dev Shows various input validation vulnerabilities
 */
contract VulnerableExchange {
    mapping(address => mapping(address => uint256)) public tokens;

    // VULNERABLE: No zero address check
    function deposit(address _token, uint256 _amount) public {
        // VULNERABILITY: Doesn't check for zero address
        require(_amount > 0, "Amount must be positive");
        tokens[_token][msg.sender] += _amount;
    }

    // VULNERABLE: No validation on addresses
    function withdraw(address _token, uint256 _amount) public {
        // VULNERABILITY: No address validation
        require(tokens[_token][msg.sender] >= _amount, "Insufficient balance");
        tokens[_token][msg.sender] -= _amount;
    }

    // VULNERABLE: Missing array length check
    function batchDeposit(
        address[] memory _tokens,
        uint256[] memory _amounts
    ) public {
        // VULNERABILITY: Assumes arrays have same length
        for (uint256 i = 0; i < _tokens.length; i++) {
            tokens[_tokens[i]][msg.sender] += _amounts[i];
        }
    }

    // VULNERABLE: No validation on transfer parameters
    function transferBetweenUsers(
        address _token,
        address _from,
        address _to,
        uint256 _amount
    ) public {
        // VULNERABILITY: No checks on addresses (zero address, same address, etc.)
        require(tokens[_token][_from] >= _amount, "Insufficient balance");
        tokens[_token][_from] -= _amount;
        tokens[_token][_to] += _amount;
    }
}

/**
 * @title Missing Data Length Validation
 * @dev Shows vulnerability in handling dynamic data
 */
contract VulnerableMultisig {
    address[] public owners;
    mapping(bytes32 => bool) public executed;

    constructor(address[] memory _owners) {
        // VULNERABLE: No validation on array length or addresses
        owners = _owners;
    }

    // VULNERABLE: No validation on data length
    function execute(
        address _target,
        bytes memory _data,
        bytes[] memory _signatures
    ) public {
        bytes32 txHash = keccak256(abi.encodePacked(_target, _data));
        require(!executed[txHash], "Already executed");

        // VULNERABILITY: No validation on signatures array length
        // VULNERABILITY: No validation that signatures is not empty
        require(_signatures.length >= owners.length / 2 + 1, "Not enough signatures");

        // Simplified signature verification (also vulnerable)
        executed[txHash] = true;

        (bool success, ) = _target.call(_data);
        require(success, "Execution failed");
    }
}

/**
 * @title Parameter Validation Bypass
 * @dev Shows how missing parameter validation can be exploited
 */
contract VulnerableAirdrop {
    mapping(address => uint256) public claimed;
    address public token;

    constructor(address _token) {
        token = _token;
    }

    // VULNERABLE: No validation on parameters
    function claimTokens(address _recipient, uint256 _amount) public {
        // VULNERABILITY: No check that _recipient is not zero address
        // VULNERABILITY: No check that _amount is reasonable
        // VULNERABILITY: No check that caller hasn't claimed before

        require(claimed[_recipient] == 0, "Already claimed");
        claimed[_recipient] = _amount;

        // Simplified token transfer
        (bool success, ) = token.call(
            abi.encodeWithSignature("transfer(address,uint256)", _recipient, _amount)
        );
        require(success, "Transfer failed");
    }
}
