# @version ^0.3.0

"""
@title Input Validation Vulnerability Examples
@notice VULNERABLE - DO NOT USE IN PRODUCTION
@dev Missing input validation can lead to severe security issues
"""

balances: public(HashMap[address, uint256])
allowances: public(HashMap[address, HashMap[address, uint256]])

@external
@payable
def deposit(token: address, amount: uint256):
    """
    @notice Deposit tokens
    @dev VULNERABLE: No validation on token address
    """
    # VULNERABILITY: No check for zero address
    # VULNERABILITY: No check if token is actually a contract
    # VULNERABILITY: amount parameter not used properly
    self.balances[token] += msg.value


@external
def withdraw(token: address, amount: uint256):
    """
    @notice Withdraw tokens
    @dev VULNERABLE: No address validation
    """
    # VULNERABILITY: No zero address check
    # VULNERABILITY: No check if user has sufficient balance
    assert self.balances[token] >= amount, "Insufficient balance"
    self.balances[token] -= amount


@external
def transfer(to: address, amount: uint256):
    """
    @notice Transfer tokens
    @dev VULNERABLE: Missing critical validations
    """
    # VULNERABILITY: No check that 'to' is not zero address
    # VULNERABILITY: No check that 'to' is not this contract's address
    # VULNERABILITY: No check that sender has sufficient balance
    self.balances[msg.sender] -= amount
    self.balances[to] += amount


@external
def batch_transfer(recipients: DynArray[address, 100], amounts: DynArray[uint256, 100]):
    """
    @notice Batch transfer to multiple addresses
    @dev VULNERABLE: No array length validation
    """
    # VULNERABILITY: Assumes arrays have same length but doesn't check
    # VULNERABILITY: No validation on addresses or amounts
    for i in range(100):
        if i >= len(recipients):
            break

        # Will fail if amounts array is shorter than recipients
        self.balances[msg.sender] -= amounts[i]
        self.balances[recipients[i]] += amounts[i]


@external
def set_allowance(spender: address, amount: uint256):
    """
    @notice Set spending allowance
    @dev VULNERABLE: No spender validation
    """
    # VULNERABILITY: No check that spender is not zero address
    # VULNERABILITY: No check that spender is not msg.sender
    self.allowances[msg.sender][spender] = amount


# Missing bounds checking
max_supply: public(uint256)
price: public(uint256)

@external
def set_price(new_price: uint256):
    """
    @notice Set token price
    @dev VULNERABLE: No bounds checking
    """
    # VULNERABILITY: No minimum or maximum price validation
    # Price could be set to 0 or an extremely high value
    self.price = new_price


@external
def set_max_supply(new_max: uint256):
    """
    @notice Set maximum supply
    @dev VULNERABLE: No validation against current supply
    """
    # VULNERABILITY: Could set max_supply to less than current supply
    # VULNERABILITY: Could set to 0
    self.max_supply = new_max


# Missing percentage validation
fee_percentage: public(uint256)

@external
def set_fee(fee: uint256):
    """
    @notice Set fee percentage
    @dev VULNERABLE: No upper bound check
    """
    # VULNERABILITY: Fee could be set to > 100%
    # VULNERABILITY: Could be set to max_value(uint256)
    self.fee_percentage = fee


@external
def calculate_fee(amount: uint256) -> uint256:
    """
    @notice Calculate fee
    @dev Uses unvalidated fee percentage
    """
    # Could overflow or return amount greater than input
    return amount * self.fee_percentage / 100


# Missing data length validation
data_storage: public(HashMap[uint256, Bytes[10000]])

@external
def store_data(id: uint256, data: Bytes[10000]):
    """
    @notice Store arbitrary data
    @dev VULNERABLE: No length validation
    """
    # VULNERABILITY: No check on data length
    # VULNERABILITY: No access control on who can store
    self.data_storage[id] = data


# Array index validation
items: public(DynArray[uint256, 1000])

@external
def get_item(index: uint256) -> uint256:
    """
    @notice Get item at index
    @dev VULNERABLE: No bounds checking
    """
    # VULNERABILITY: No check that index < len(items)
    # Vyper will revert but with unclear error
    return self.items[index]


@external
def update_item(index: uint256, value: uint256):
    """
    @notice Update item at index
    @dev VULNERABLE: No bounds checking
    """
    # VULNERABILITY: No validation of index
    self.items[index] = value


# Missing duplicate checking
whitelist: public(DynArray[address, 500])

@external
def add_to_whitelist(user: address):
    """
    @notice Add user to whitelist
    @dev VULNERABLE: No duplicate checking
    """
    # VULNERABILITY: Can add same address multiple times
    # VULNERABILITY: No zero address check
    self.whitelist.append(user)


# Missing state validation
state: public(uint256)  # 0 = inactive, 1 = active, 2 = paused

@external
def set_state(new_state: uint256):
    """
    @notice Set contract state
    @dev VULNERABLE: No validation on state values
    """
    # VULNERABILITY: Could set to invalid state (3, 4, etc.)
    self.state = new_state


@external
def perform_action():
    """
    @notice Perform action when active
    @dev Relies on unvalidated state
    """
    assert self.state == 1, "Not active"
    # Action here


# Missing signature validation
nonces: public(HashMap[address, uint256])

@external
def execute_meta_tx(user: address, data: Bytes[1024], signature: Bytes[65]):
    """
    @notice Execute meta transaction
    @dev VULNERABLE: Multiple validation issues
    """
    # VULNERABILITY: No validation that signature is from user
    # VULNERABILITY: No nonce checking for replay protection
    # VULNERABILITY: No validation of data length
    # VULNERABILITY: Signature not actually verified

    # Pretend to execute
    self.nonces[user] += 1


# Parameter overflow/wraparound
@external
def unsafe_timestamp_check(timestamp: uint256):
    """
    @notice Check if timestamp is in valid range
    @dev VULNERABLE: No validation can lead to wraparound
    """
    # VULNERABILITY: If timestamp is close to max_value(uint256)
    # adding to it could wrap around
    future_time: uint256 = timestamp + 86400  # Add 1 day

    # If timestamp was near max, future_time wraps to small number
    assert future_time > block.timestamp, "Time in past"
