# @version ^0.3.0

"""
@title Raw Call Vulnerability Examples
@notice VULNERABLE - DO NOT USE IN PRODUCTION
@dev Demonstrates dangers of raw_call in Vyper
"""

owner: public(address)
balances: public(HashMap[address, uint256])

@external
def __init__():
    self.owner = msg.sender


@external
@payable
def deposit():
    """
    @notice Deposit ETH
    """
    self.balances[msg.sender] += msg.value


@external
def withdraw_unchecked(recipient: address, amount: uint256):
    """
    @notice Withdraw with unchecked raw_call
    @dev VULNERABLE: Doesn't check return value of raw_call
    """
    assert self.balances[msg.sender] >= amount, "Insufficient balance"
    self.balances[msg.sender] -= amount

    # VULNERABILITY: raw_call return value not checked
    # If the call fails, user loses their balance
    raw_call(recipient, b"", value=amount)


@external
def withdraw_ignored_return(recipient: address, amount: uint256):
    """
    @notice Withdraw with ignored return value
    @dev VULNERABLE: Checks success but doesn't handle failure properly
    """
    assert self.balances[msg.sender] >= amount, "Insufficient balance"

    # VULNERABILITY: Balance updated before call
    self.balances[msg.sender] -= amount

    # Even though we check success, balance is already gone
    success: bool = raw_call(recipient, b"", value=amount)
    # No revert if success is False!


@external
def execute_arbitrary(target: address, data: Bytes[1024]):
    """
    @notice Execute arbitrary call
    @dev VULNERABLE: User controls target and data
    """
    # VULNERABILITY: Allows calling any contract with any data
    # Could be used to call this contract's own functions
    response: Bytes[32] = raw_call(target, data, max_outsize=32)


@external
def batch_transfer(recipients: DynArray[address, 10], amounts: DynArray[uint256, 10]):
    """
    @notice Batch transfer to multiple recipients
    @dev VULNERABLE: One failure doesn't stop the loop
    """
    assert len(recipients) == len(amounts), "Length mismatch"

    for i in range(10):
        if i >= len(recipients):
            break

        # VULNERABILITY: If one call fails, loop continues
        # Some transfers succeed, some fail - inconsistent state
        raw_call(recipients[i], b"", value=amounts[i])


@external
def call_with_gas(target: address, data: Bytes[1024], gas_amount: uint256):
    """
    @notice Call with custom gas amount
    @dev VULNERABLE: User controls gas amount, could cause out-of-gas
    """
    # VULNERABILITY: User-controlled gas could be set too low
    # causing the call to fail
    success: bool = raw_call(
        target,
        data,
        max_outsize=32,
        gas=gas_amount
    )


@external
@payable
def proxy_call(target: address, data: Bytes[2048]):
    """
    @notice Proxy any call with value
    @dev VULNERABLE: No validation on target or data
    """
    # VULNERABILITY: Can proxy calls to malicious contracts
    # VULNERABILITY: msg.value is forwarded without checks
    response: Bytes[32] = raw_call(
        target,
        data,
        max_outsize=32,
        value=msg.value
    )
