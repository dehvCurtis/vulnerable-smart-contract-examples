# @version ^0.3.0

"""
@title Front-Running Vulnerability Examples
@notice VULNERABLE - DO NOT USE IN PRODUCTION
@dev Transaction ordering dependencies and front-running vulnerabilities
"""

# Puzzle with front-running
solution_hash: public(bytes32)
reward: public(uint256)
solved: public(bool)

@external
@payable
def __init__(solution: bytes32):
    self.solution_hash = solution
    self.reward = as_wei_value(10, "ether")
    self.solved = False


@external
def submit_solution(solution: String[100]):
    """
    @notice Submit puzzle solution
    @dev VULNERABLE: Solution visible in mempool before confirmation
    """
    assert not self.solved, "Already solved"

    # VULNERABILITY: Anyone can see the solution in the mempool
    # and front-run it with higher gas price
    assert keccak256(solution) == self.solution_hash, "Incorrect solution"

    self.solved = True
    send(msg.sender, self.reward)


# DEX with front-running
token_a_reserve: public(uint256)
token_b_reserve: public(uint256)
token_a_balance: public(HashMap[address, uint256])
token_b_balance: public(HashMap[address, uint256])

@external
def initialize():
    """
    @notice Initialize reserves
    """
    self.token_a_reserve = as_wei_value(1000, "ether")
    self.token_b_reserve = as_wei_value(1000, "ether")


@external
@view
def get_swap_amount(token_a_amount: uint256) -> uint256:
    """
    @notice Calculate swap amount (constant product AMM)
    """
    k: uint256 = self.token_a_reserve * self.token_b_reserve
    new_token_a_reserve: uint256 = self.token_a_reserve + token_a_amount
    new_token_b_reserve: uint256 = k / new_token_a_reserve
    return self.token_b_reserve - new_token_b_reserve


@external
def swap_a_for_b(token_a_amount: uint256, min_token_b_amount: uint256):
    """
    @notice Swap token A for token B
    @dev VULNERABLE: Front-runner can manipulate price
    """
    token_b_amount: uint256 = self.get_swap_amount(token_a_amount)

    # VULNERABILITY: Front-runner can see this transaction and swap before it,
    # causing price to move and potentially failing the slippage check
    # or giving worse rate to victim
    assert token_b_amount >= min_token_b_amount, "Slippage too high"

    self.token_a_balance[msg.sender] -= token_a_amount
    self.token_b_balance[msg.sender] += token_b_amount

    self.token_a_reserve += token_a_amount
    self.token_b_reserve -= token_b_amount


# ICO with front-running
price: public(uint256)
tokens_available: public(uint256)
token_balances: public(HashMap[address, uint256])
owner: public(address)

@external
def setup_ico():
    """
    @notice Setup ICO
    """
    self.owner = msg.sender
    self.price = as_wei_value(1, "ether")
    self.tokens_available = 1000


@external
def update_price(new_price: uint256):
    """
    @notice Update token price
    @dev VULNERABLE: Price update can be front-run
    """
    assert msg.sender == self.owner, "Not owner"

    # VULNERABILITY: Users buying tokens can be front-run by owner
    # increasing price between transaction submission and confirmation
    self.price = new_price


@external
@payable
def buy_tokens(amount: uint256):
    """
    @notice Buy tokens
    @dev VULNERABLE: Price might change before confirmation
    """
    assert self.tokens_available >= amount, "Not enough tokens"

    # VULNERABILITY: Price might change between when user submits
    # transaction and when it's mined
    assert msg.value >= self.price * amount, "Insufficient payment"

    self.tokens_available -= amount
    self.token_balances[msg.sender] += amount


# Approval front-running (ERC20-style)
balances: public(HashMap[address, uint256])
allowances: public(HashMap[address, HashMap[address, uint256]])

@external
def approve(spender: address, amount: uint256):
    """
    @notice Approve spender
    @dev VULNERABLE: Changing allowance can be front-run
    """
    # VULNERABILITY: If user tries to change allowance from N to M,
    # spender can front-run by:
    # 1. transferFrom N tokens (old allowance)
    # 2. Let approve transaction execute
    # 3. transferFrom M tokens (new allowance)
    # Result: spender transferred N+M tokens instead of M
    self.allowances[msg.sender][spender] = amount


@external
def transfer_from(owner: address, to: address, amount: uint256):
    """
    @notice Transfer from approved address
    """
    assert self.balances[owner] >= amount, "Insufficient balance"
    assert self.allowances[owner][msg.sender] >= amount, "Insufficient allowance"

    self.balances[owner] -= amount
    self.balances[to] += amount
    self.allowances[owner][msg.sender] -= amount


# Commit-reveal to prevent front-running (better approach)
commits: public(HashMap[address, bytes32])
reveals: public(HashMap[address, String[100]])

@external
def commit(commitment: bytes32):
    """
    @notice Commit to a solution (without revealing it)
    @dev Better approach: Use commit-reveal to prevent front-running
    """
    self.commits[msg.sender] = commitment


@external
def reveal(solution: String[100], salt: String[32]):
    """
    @notice Reveal the committed solution
    @dev Verifies that the reveal matches the previous commitment
    """
    # Verify commitment matches reveal
    commitment: bytes32 = keccak256(concat(solution, salt))
    assert self.commits[msg.sender] == commitment, "Invalid reveal"

    self.reveals[msg.sender] = solution
    # Now check solution...


# Transaction ordering
order_count: public(uint256)
orders: public(HashMap[uint256, address])

@external
def place_order():
    """
    @notice Place order
    @dev VULNERABLE: Order of transactions matters
    """
    # VULNERABILITY: Higher gas price = earlier in block
    # Attackers can pay more gas to get their order first
    order_id: uint256 = self.order_count
    self.orders[order_id] = msg.sender
    self.order_count += 1
