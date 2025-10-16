# @version ^0.3.0

"""
@title Uninitialized Storage and State Issues
@notice VULNERABLE - DO NOT USE IN PRODUCTION
@dev Demonstrates issues with uninitialized state and storage management
"""

owner: public(address)
initialized: public(bool)
total_supply: public(uint256)
balances: public(HashMap[address, uint256])

@external
def __init__():
    """
    @notice Constructor
    @dev VULNERABLE: Incomplete initialization
    """
    # VULNERABILITY: owner not set in constructor
    # VULNERABILITY: total_supply not initialized
    self.initialized = False


@external
def initialize(initial_owner: address):
    """
    @notice Initialize contract
    @dev VULNERABLE: Can be called multiple times or by anyone
    """
    # VULNERABILITY: No check on initialized flag
    # VULNERABILITY: No access control
    # VULNERABILITY: No validation of initial_owner

    self.owner = initial_owner
    self.total_supply = 1000000
    self.initialized = True


@external
def initialize_v2(new_owner: address):
    """
    @notice Second initialization function
    @dev VULNERABLE: Conflicting initialization
    """
    # VULNERABILITY: Different initialization function
    # Both could be called, causing conflicts
    self.owner = new_owner


# Struct with uninitialized fields
struct User:
    addr: address
    balance: uint256
    active: bool
    registered_at: uint256

users: public(HashMap[address, User])
user_list: public(DynArray[User, 1000])

@external
def register_user():
    """
    @notice Register new user
    @dev VULNERABLE: Fields not fully initialized
    """
    new_user: User = User({
        addr: msg.sender,
        balance: 0,
        active: True,
        registered_at: 0  # VULNERABILITY: Should be block.timestamp
    })

    self.users[msg.sender] = new_user


@external
def add_user_to_list(user_addr: address):
    """
    @notice Add user to list
    @dev VULNERABLE: Partial initialization
    """
    # VULNERABILITY: Not all fields initialized
    new_user: User = User({
        addr: user_addr,
        balance: 0,
        active: False,
        registered_at: 0
    })

    self.user_list.append(new_user)


# Array operations
items: public(DynArray[uint256, 1000])

@external
def add_item(value: uint256):
    """
    @notice Add item to array
    """
    self.items.append(value)


@external
def remove_item(index: uint256):
    """
    @notice Remove item from array
    @dev VULNERABLE: Creates gaps in array logic
    """
    # VULNERABILITY: This pops last item, not the item at index
    # Creates logical inconsistency
    assert index < len(self.items), "Index out of bounds"
    self.items.pop()


@external
def get_item(index: uint256) -> uint256:
    """
    @notice Get item at index
    @dev Can return wrong item after deletions
    """
    return self.items[index]


# Default values confusion
struct Config:
    min_amount: uint256
    max_amount: uint256
    fee_percentage: uint256
    enabled: bool

config: public(Config)

@external
def set_config():
    """
    @notice Set configuration
    @dev VULNERABLE: Not all fields set
    """
    # VULNERABILITY: Only sets some fields, others remain at default 0/False
    self.config.min_amount = 100
    self.config.enabled = True
    # max_amount and fee_percentage remain 0


@external
def check_amount(amount: uint256) -> bool:
    """
    @notice Check if amount is valid
    @dev VULNERABLE: Uses uninitialized max_amount
    """
    # VULNERABILITY: max_amount might be 0, making all amounts invalid
    if amount < self.config.min_amount:
        return False
    if amount > self.config.max_amount:  # This will always fail if max_amount = 0
        return False
    return True


# State transition issues
enum State:
    UNINITIALIZED
    PENDING
    ACTIVE
    PAUSED
    TERMINATED

current_state: public(State)

@external
def activate():
    """
    @notice Activate contract
    @dev VULNERABLE: No state validation
    """
    # VULNERABILITY: Can activate from any state
    # Should check current_state == State.PENDING
    self.current_state = State.ACTIVE


@external
def pause():
    """
    @notice Pause contract
    @dev VULNERABLE: Can pause when uninitialized
    """
    # VULNERABILITY: No check if contract is active
    self.current_state = State.PAUSED


# Missing reset on state changes
last_action_time: public(uint256)
action_count: public(uint256)

@external
def perform_action():
    """
    @notice Perform action
    """
    self.last_action_time = block.timestamp
    self.action_count += 1


@external
def reset():
    """
    @notice Reset state
    @dev VULNERABLE: Incomplete reset
    """
    # VULNERABILITY: Only resets action_count, not last_action_time
    self.action_count = 0


# Mapping with implicit zero values
deposits: public(HashMap[address, uint256])
has_deposited: public(HashMap[address, bool])

@external
@payable
def deposit():
    """
    @notice Deposit funds
    """
    self.deposits[msg.sender] += msg.value
    self.has_deposited[msg.sender] = True


@external
def withdraw():
    """
    @notice Withdraw funds
    @dev VULNERABLE: Doesn't handle state properly
    """
    amount: uint256 = self.deposits[msg.sender]
    assert amount > 0, "No deposit"

    self.deposits[msg.sender] = 0
    # VULNERABILITY: Doesn't reset has_deposited flag
    # This could cause issues in other functions that check the flag

    send(msg.sender, amount)


@external
def check_depositor(user: address) -> bool:
    """
    @notice Check if user has deposited
    @dev VULNERABLE: Returns wrong result after withdrawal
    """
    # Returns True even after user withdraws everything
    return self.has_deposited[user]


# Circular dependencies
contract_a: public(address)
contract_b: public(address)

@external
def set_contracts(a: address, b: address):
    """
    @notice Set contract addresses
    @dev VULNERABLE: No validation order
    """
    # VULNERABILITY: No check if these are valid contract addresses
    # VULNERABILITY: Could create circular dependency
    self.contract_a = a
    self.contract_b = b


@external
def call_contract_a():
    """
    @notice Call contract A
    @dev VULNERABLE: Uninitialized contract address
    """
    # VULNERABILITY: contract_a might be zero address
    raw_call(self.contract_a, b"", max_outsize=32)


# Multiple initialization patterns
setup_done: public(bool)
config_done: public(bool)

@external
def setup():
    """
    @notice Setup step 1
    """
    self.setup_done = True


@external
def configure():
    """
    @notice Configuration step 2
    @dev VULNERABLE: Can run before setup
    """
    # VULNERABILITY: No check if setup was done first
    self.config_done = True


@external
def start():
    """
    @notice Start operations
    @dev VULNERABLE: Incomplete state check
    """
    # VULNERABILITY: Only checks one flag
    assert self.setup_done, "Not setup"
    # Should also check config_done
