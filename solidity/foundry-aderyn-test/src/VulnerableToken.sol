// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableToken
 * @notice Intentionally vulnerable ERC20-like token for testing Aderyn scanner
 *
 * Contains the following vulnerabilities that Aderyn should detect:
 * 1. Reentrancy vulnerability in withdraw()
 * 2. Missing access control on mint()
 * 3. Unchecked external call in withdrawToAddress()
 * 4. State changes after external calls
 * 5. Missing zero address checks
 * 6. No events for critical state changes
 */
contract VulnerableToken {
    string public name = "Vulnerable Token";
    string public symbol = "VULN";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    address public owner;

    constructor() {
        owner = msg.sender;
        totalSupply = 1000000 * 10**decimals;
        balanceOf[msg.sender] = totalSupply;
    }

    /**
     * VULNERABILITY 1: Missing access control
     * Anyone can mint tokens, not just the owner
     */
    function mint(address to, uint256 amount) public {
        // MISSING: require(msg.sender == owner, "Not owner");

        // VULNERABILITY 2: No zero address check
        totalSupply += amount;
        balanceOf[to] += amount;

        // VULNERABILITY 3: No event emitted
    }

    /**
     * VULNERABILITY 4: Reentrancy vulnerability
     * State is updated after external call, allowing reentrancy attacks
     */
    function withdraw(uint256 amount) public {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");

        // VULNERABILITY: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update AFTER external call - REENTRANCY RISK
        balanceOf[msg.sender] -= amount;
    }

    /**
     * VULNERABILITY 5: Unchecked external call
     * Does not check return value of call()
     */
    function withdrawToAddress(address payable recipient, uint256 amount) public {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");

        balanceOf[msg.sender] -= amount;

        // VULNERABILITY: Unchecked low-level call
        recipient.call{value: amount}("");
        // Missing: require(success, "Transfer failed");
    }

    /**
     * VULNERABILITY 6: Approval without event
     * Critical state change without event emission
     */
    function approve(address spender, uint256 amount) public returns (bool) {
        // VULNERABILITY: No zero address check
        allowance[msg.sender][spender] = amount;
        // VULNERABILITY: No event emitted
        return true;
    }

    /**
     * VULNERABILITY 7: transferFrom with state changes after external call
     */
    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");

        // External interaction (potential callback via transfer hook)
        balanceOf[from] -= amount;
        balanceOf[to] += amount;

        // State update after balance changes - potential reentrancy
        allowance[from][msg.sender] -= amount;

        return true;
    }

    /**
     * VULNERABILITY 8: Missing access control on critical function
     */
    function changeOwner(address newOwner) public {
        // MISSING: require(msg.sender == owner, "Not owner");
        // VULNERABILITY: No zero address check
        owner = newOwner;
        // VULNERABILITY: No event emitted
    }

    /**
     * VULNERABILITY 9: Integer overflow/underflow (pre-0.8.0 style)
     * While Solidity 0.8+ has built-in overflow protection,
     * Aderyn may flag patterns that could be risky
     */
    function unsafeIncrement(address account, uint256 amount) public {
        // While safe in 0.8+, this pattern may be flagged
        balanceOf[account] = balanceOf[account] + amount;
    }

    /**
     * VULNERABILITY 10: Centralization risk
     * Single owner with god mode privileges
     */
    function burnAll(address account) public {
        require(msg.sender == owner, "Not owner");
        // Centralization risk: owner can burn anyone's tokens
        balanceOf[account] = 0;
    }

    // Receive function to accept Ether
    receive() external payable {}
}
