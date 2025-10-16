# @version ^0.3.0

"""
@title Access Control Vulnerability Examples
@notice VULNERABLE - DO NOT USE IN PRODUCTION
@dev This contract demonstrates multiple access control vulnerabilities in Vyper
"""

owner: public(address)
balances: public(HashMap[address, uint256])
initialized: public(bool)

@external
def __init__():
    self.owner = msg.sender
    self.initialized = False


@external
def change_owner(new_owner: address):
    """
    @notice Change contract owner
    @dev VULNERABLE: Missing access control decorator
         Anyone can call this and become the owner!
    """
    # VULNERABILITY: No check that msg.sender == self.owner
    self.owner = new_owner


@external
def withdraw_all(recipient: address):
    """
    @notice Withdraw all contract funds
    @dev VULNERABLE: Weak access control using tx.origin
    """
    # VULNERABILITY: Using tx.origin instead of msg.sender
    # This enables phishing attacks
    assert tx.origin == self.owner, "Not owner"
    send(recipient, self.balance)


@external
def initialize(new_owner: address):
    """
    @notice Initialize the contract
    @dev VULNERABLE: Can be called multiple times by anyone
    """
    # VULNERABILITY: Missing check - should require not initialized
    # VULNERABILITY: No access control - anyone can call
    self.owner = new_owner
    self.initialized = True


@external
@payable
def deposit():
    """
    @notice Deposit funds
    """
    self.balances[msg.sender] += msg.value


@external
def emergency_withdraw():
    """
    @notice Emergency withdrawal function
    @dev VULNERABLE: No access control at all
    """
    # VULNERABILITY: Anyone can drain the contract
    send(msg.sender, self.balance)


@external
def set_balance(user: address, amount: uint256):
    """
    @notice Set user balance
    @dev VULNERABLE: Missing access control on critical function
    """
    # VULNERABILITY: Anyone can set arbitrary balances
    self.balances[user] = amount


# Secure version would use a decorator:
"""
@internal
def _only_owner():
    assert msg.sender == self.owner, "Not owner"

@external
def secure_change_owner(new_owner: address):
    self._only_owner()
    self.owner = new_owner
"""
