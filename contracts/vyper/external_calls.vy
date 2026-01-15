# @version ^0.3.0

"""
@title External Call Vulnerabilities
@notice VULNERABLE - DO NOT USE IN PRODUCTION
@dev Demonstrates vulnerabilities related to external contract calls
"""

interface ERC20:
    def transfer(to: address, amount: uint256) -> bool: nonpayable
    def transferFrom(owner: address, to: address, amount: uint256) -> bool: nonpayable
    def balanceOf(account: address) -> uint256: view

interface IOracle:
    def getPrice(token: address) -> uint256: view

balances: public(HashMap[address, uint256])
oracle: public(address)

@external
def __init__():
    pass


@external
def set_oracle(oracle_address: address):
    """
    @notice Set price oracle
    @dev VULNERABLE: No validation of oracle address
    """
    # VULNERABILITY: No check if oracle_address is valid
    # VULNERABILITY: No access control
    self.oracle = oracle_address


@external
def deposit_token(token: address, amount: uint256):
    """
    @notice Deposit ERC20 tokens
    @dev VULNERABLE: Doesn't check return value properly
    """
    # VULNERABILITY: Assumes transferFrom always returns true
    # Some tokens don't return bool, some return false instead of reverting
    ERC20(token).transferFrom(msg.sender, self, amount)
    self.balances[msg.sender] += amount


@external
def withdraw_token(token: address, amount: uint256):
    """
    @notice Withdraw tokens
    @dev VULNERABLE: Doesn't verify transfer success
    """
    assert self.balances[msg.sender] >= amount, "Insufficient balance"
    self.balances[msg.sender] -= amount

    # VULNERABILITY: Doesn't check if transfer succeeded
    # If transfer fails, user loses balance without receiving tokens
    ERC20(token).transfer(msg.sender, amount)


@external
def get_token_price(token: address) -> uint256:
    """
    @notice Get token price from oracle
    @dev VULNERABLE: Trusts external oracle without validation
    """
    # VULNERABILITY: No check if oracle address is set
    # VULNERABILITY: No validation of returned price
    # VULNERABILITY: Oracle could be malicious or compromised
    price: uint256 = IOracle(self.oracle).getPrice(token)
    return price


@external
def calculate_value(token: address, amount: uint256) -> uint256:
    """
    @notice Calculate token value
    @dev VULNERABLE: Depends on untrusted external call
    """
    price: uint256 = self.get_token_price(token)

    # VULNERABILITY: Price could be manipulated or zero
    # VULNERABILITY: No bounds checking on result
    return amount * price


@external
@payable
def swap_with_external(token_out: address, min_amount_out: uint256):
    """
    @notice Swap ETH for tokens using external contract
    @dev VULNERABLE: Multiple external call issues
    """
    # VULNERABILITY: Calls unknown external contract
    # VULNERABILITY: No validation of token_out address
    # VULNERABILITY: Doesn't verify received amount

    response: Bytes[32] = raw_call(
        token_out,
        concat(
            method_id("swapETHForTokens(address,uint256)"),
            convert(msg.sender, bytes32),
            convert(min_amount_out, bytes32)
        ),
        max_outsize=32,
        value=msg.value
    )


# Callback vulnerability
authorized_caller: public(address)

@external
def set_authorized_caller(caller: address):
    """
    @notice Set authorized caller
    """
    self.authorized_caller = caller


@external
def execute_callback(target: address, data: Bytes[1024]):
    """
    @notice Execute callback on target
    @dev VULNERABLE: Callback could re-enter this contract
    """
    # VULNERABILITY: No reentrancy protection
    # VULNERABILITY: Target could be this contract itself
    # VULNERABILITY: Data is not validated

    response: Bytes[32] = raw_call(target, data, max_outsize=32)


# Untrusted interface implementation
@external
def interact_with_token(token: address, recipient: address, amount: uint256):
    """
    @notice Interact with external token
    @dev VULNERABLE: Assumes token follows ERC20 standard
    """
    # VULNERABILITY: Token might not implement ERC20 correctly
    # VULNERABILITY: Token could be malicious and re-enter
    # VULNERABILITY: No checks on returned value

    success: bool = ERC20(token).transfer(recipient, amount)
    # Even if we check success, malicious token could return true but not transfer


# Delegatecall alternative (raw_call with dangerous parameters)
@external
def proxy_call(implementation: address, data: Bytes[2048]) -> Bytes[1024]:
    """
    @notice Proxy call to implementation
    @dev VULNERABLE: User controls implementation address
    """
    # VULNERABILITY: User-controlled implementation address
    # VULNERABILITY: Could call malicious contract
    # VULNERABILITY: No validation on return data

    response: Bytes[1024] = raw_call(
        implementation,
        data,
        max_outsize=1024
    )
    return response


# Flash loan callback vulnerability
flash_loan_callback: public(address)

@external
@payable
def flash_loan(amount: uint256, callback_target: address, callback_data: Bytes[512]):
    """
    @notice Provide flash loan
    @dev VULNERABLE: Callback can manipulate state
    """
    # Send loan
    send(msg.sender, amount)

    # VULNERABILITY: External call allows borrower to manipulate state
    # before repayment check
    response: Bytes[32] = raw_call(callback_target, callback_data, max_outsize=32)

    # VULNERABILITY: Balance check after external call
    # State could have been manipulated
    assert self.balance >= amount, "Loan not repaid"


# Multiple external calls
@external
def multi_call(targets: DynArray[address, 10], datas: DynArray[Bytes[256], 10]):
    """
    @notice Call multiple contracts
    @dev VULNERABLE: Multiple external calls without protection
    """
    assert len(targets) == len(datas), "Length mismatch"

    # VULNERABILITY: Each call could re-enter
    # VULNERABILITY: No gas limit per call
    # VULNERABILITY: One call could affect the next
    for i in range(10):
        if i >= len(targets):
            break

        raw_call(targets[i], datas[i], max_outsize=32)


# Oracle manipulation
price_cache: public(HashMap[address, uint256])
last_update: public(HashMap[address, uint256])

@external
def update_price_cache(token: address):
    """
    @notice Update cached price
    @dev VULNERABLE: Relies on external oracle
    """
    # VULNERABILITY: Oracle price could be manipulated
    # VULNERABILITY: No time-weighted average
    # VULNERABILITY: No validation of price reasonableness

    price: uint256 = IOracle(self.oracle).getPrice(token)
    self.price_cache[token] = price
    self.last_update[token] = block.timestamp


@external
def get_cached_price(token: address) -> uint256:
    """
    @notice Get cached price
    @dev VULNERABLE: Stale price risk
    """
    # VULNERABILITY: No check if price is stale
    # VULNERABILITY: Could return 0 if never updated
    return self.price_cache[token]
