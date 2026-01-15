# @version ^0.3.0

"""
@title Integer Issues in Vyper
@notice VULNERABLE - DO NOT USE IN PRODUCTION
@dev While Vyper has built-in overflow protection, there are still edge cases
     and logical errors that can occur with integer arithmetic
"""

balances: public(HashMap[address, uint256])
total_supply: public(uint256)

@external
def __init__():
    self.total_supply = 1000000


@external
def unsafe_multiply(a: uint256, b: uint256) -> uint256:
    """
    @notice Multiply two numbers
    @dev VULNERABLE: While Vyper prevents overflow, the result might not be what's expected
         Large multiplications can hit the max uint256 and revert unexpectedly
    """
    # VULNERABILITY: No check if result makes sense in context
    # If a * b > max_value(uint256), this reverts without clear error
    return a * b


@external
def division_rounding(amount: uint256, divisor: uint256) -> uint256:
    """
    @notice Divide with potential rounding issues
    @dev VULNERABLE: Integer division truncates, losing precision
    """
    # VULNERABILITY: Rounding down can lead to loss of funds
    # Example: 100 wei / 3 = 33 wei, losing 1 wei
    assert divisor > 0, "Division by zero"
    return amount / divisor


@external
def distribute_equally(recipients: DynArray[address, 100]):
    """
    @notice Distribute contract balance equally
    @dev VULNERABLE: Rounding errors cause funds to be locked
    """
    num_recipients: uint256 = len(recipients)
    assert num_recipients > 0, "No recipients"

    # VULNERABILITY: Rounding down means remaining funds get stuck
    # If balance = 100 and recipients = 3, each gets 33, 1 wei stuck forever
    amount_each: uint256 = self.balance / num_recipients

    for recipient in recipients:
        send(recipient, amount_each)


@external
def percentage_calculation(amount: uint256, percentage: uint256) -> uint256:
    """
    @notice Calculate percentage of amount
    @dev VULNERABLE: Order of operations can cause precision loss
    """
    # VULNERABILITY: Dividing before multiplying loses precision
    # Example: (99 / 100) * 1000 = 0 * 1000 = 0
    # Should be: (99 * 1000) / 100 = 990
    assert percentage <= 100, "Invalid percentage"
    return (amount / 100) * percentage


@external
def unsafe_subtraction(value: uint256) -> uint256:
    """
    @notice Subtract from total supply
    @dev VULNERABLE: Logic error - subtracts without checking state
    """
    # VULNERABILITY: While Vyper prevents underflow (reverts),
    # the revert might not be what users expect in the business logic
    # Better to have explicit checks and clear error messages
    self.total_supply -= value
    return self.total_supply


@external
def fee_calculation(amount: uint256, fee_percentage: uint256) -> uint256:
    """
    @notice Calculate amount after fee
    @dev VULNERABLE: Multiple precision loss points
    """
    # VULNERABILITY: Precision loss in fee calculation
    fee: uint256 = (amount * fee_percentage) / 10000  # Fee in basis points
    result: uint256 = amount - fee

    # VULNERABILITY: If amount is small, fee might round to 0
    # If amount = 50 and fee_percentage = 100 (1%), fee = 0
    return result


@external
def weighted_average(value1: uint256, weight1: uint256, value2: uint256, weight2: uint256) -> uint256:
    """
    @notice Calculate weighted average
    @dev VULNERABLE: Order of operations causes precision loss
    """
    # VULNERABILITY: Integer division loses precision
    # (v1*w1 + v2*w2) / (w1 + w2) truncates result
    total_weight: uint256 = weight1 + weight2
    assert total_weight > 0, "Weights must be positive"

    return (value1 * weight1 + value2 * weight2) / total_weight


@external
def compound_interest(principal: uint256, rate: uint256, periods: uint256) -> uint256:
    """
    @notice Calculate compound interest
    @dev VULNERABLE: Severe precision loss with integer arithmetic
    """
    # VULNERABILITY: Compound interest requires decimals
    # Using integers will give completely wrong results
    result: uint256 = principal

    for i in range(100):
        if i >= periods:
            break
        # This will give wrong results due to integer arithmetic
        result = result + (result * rate / 100)

    return result


@external
@payable
def deposit():
    self.balances[msg.sender] += msg.value
