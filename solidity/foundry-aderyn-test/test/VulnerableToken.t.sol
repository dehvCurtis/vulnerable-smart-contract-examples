// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/VulnerableToken.sol";

contract VulnerableTokenTest is Test {
    VulnerableToken public token;
    address public owner;
    address public attacker;

    function setUp() public {
        owner = address(this);
        attacker = address(0xBEEF);

        token = new VulnerableToken();
    }

    function testInitialSupply() public {
        assertEq(token.totalSupply(), 1000000 * 10**18);
        assertEq(token.balanceOf(owner), 1000000 * 10**18);
    }

    function testUnauthorizedMint() public {
        // This test demonstrates the missing access control vulnerability
        vm.prank(attacker);
        token.mint(attacker, 1000 * 10**18);

        // Attacker can mint tokens without authorization
        assertEq(token.balanceOf(attacker), 1000 * 10**18);
    }

    function testUnauthorizedOwnerChange() public {
        // This test demonstrates missing access control on changeOwner
        vm.prank(attacker);
        token.changeOwner(attacker);

        // Attacker can change owner without authorization
        assertEq(token.owner(), attacker);
    }
}
