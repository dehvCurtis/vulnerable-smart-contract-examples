# @version ^0.3.0

"""
@title Timestamp Dependence Vulnerability Examples
@notice VULNERABLE - DO NOT USE IN PRODUCTION
@dev Using block.timestamp for critical logic is dangerous as miners can manipulate it
"""

owner: public(address)
lottery_end_time: public(uint256)
players: public(DynArray[address, 1000])
ticket_price: public(uint256)

@external
def __init__(duration: uint256):
    self.owner = msg.sender
    self.lottery_end_time = block.timestamp + duration
    self.ticket_price = as_wei_value(1, "ether") / 10  # 0.1 ETH


@external
@payable
def buy_ticket():
    """
    @notice Buy lottery ticket
    @dev Uses block.timestamp for time check
    """
    assert msg.value == self.ticket_price, "Incorrect ticket price"
    assert block.timestamp < self.lottery_end_time, "Lottery ended"
    self.players.append(msg.sender)


@external
def draw_winner():
    """
    @notice Draw lottery winner
    @dev VULNERABLE: Uses block.timestamp for randomness
    """
    assert block.timestamp >= self.lottery_end_time, "Lottery not ended"
    assert len(self.players) > 0, "No players"

    # VULNERABILITY: Miners can manipulate block.timestamp by ~15 seconds
    # This makes the random number partially predictable
    random_index: uint256 = convert(
        keccak256(
            concat(
                convert(block.timestamp, bytes32),
                convert(block.difficulty, bytes32)
            )
        ),
        uint256
    ) % len(self.players)

    winner: address = self.players[random_index]
    send(winner, self.balance)

    # Reset for next round
    self.players = []
    self.lottery_end_time = block.timestamp + 86400  # 1 day


# Timelock example
lock_time: public(HashMap[address, uint256])
locked_balances: public(HashMap[address, uint256])

@external
@payable
def deposit_with_lock():
    """
    @notice Deposit funds with 1 week lock
    @dev VULNERABLE: Uses block.timestamp for lock mechanism
    """
    self.locked_balances[msg.sender] += msg.value
    # Lock for 1 week
    self.lock_time[msg.sender] = block.timestamp + 604800


@external
def withdraw_locked():
    """
    @notice Withdraw locked funds
    @dev VULNERABLE: Relies on block.timestamp for security
    """
    assert self.locked_balances[msg.sender] > 0, "No balance"

    # VULNERABILITY: Miner can manipulate timestamp to bypass lock
    assert block.timestamp >= self.lock_time[msg.sender], "Funds locked"

    amount: uint256 = self.locked_balances[msg.sender]
    self.locked_balances[msg.sender] = 0
    send(msg.sender, amount)


@external
def time_based_access() -> bool:
    """
    @notice Access control based on time
    @dev VULNERABLE: Time-based logic can be manipulated
    """
    # VULNERABILITY: Attacker miner can manipulate timestamp
    # to gain access during "even seconds"
    if block.timestamp % 2 == 0:
        return True
    return False


# Random number generation
last_random: public(uint256)

@external
def generate_random() -> uint256:
    """
    @notice Generate random number
    @dev VULNERABLE: Completely predictable randomness
    """
    # VULNERABILITY: All these values are known/predictable
    random: uint256 = convert(
        keccak256(
            concat(
                convert(block.timestamp, bytes32),
                convert(block.difficulty, bytes32),
                convert(block.number, bytes32),
                convert(msg.sender, bytes32)
            )
        ),
        uint256
    ) % 100

    self.last_random = random
    return random


@external
@payable
def play_game() -> bool:
    """
    @notice Play game with predictable randomness
    @dev VULNERABLE: Outcome is predictable
    """
    assert msg.value == as_wei_value(1, "ether") / 100, "Must bet 0.01 ether"

    winning_number: uint256 = self.generate_random()

    # VULNERABILITY: Attacker can predict the outcome before calling
    if winning_number > 50:
        send(msg.sender, as_wei_value(2, "ether") / 100)
        return True

    return False


# Auction with timestamp issues
highest_bidder: public(address)
highest_bid: public(uint256)
auction_end: public(uint256)

@external
def start_auction(duration: uint256):
    """
    @notice Start an auction
    """
    self.auction_end = block.timestamp + duration


@external
@payable
def bid():
    """
    @notice Place bid
    @dev VULNERABLE: Timestamp check can be manipulated
    """
    # VULNERABILITY: Miner can extend the auction by manipulating timestamp
    assert block.timestamp < self.auction_end, "Auction ended"
    assert msg.value > self.highest_bid, "Bid too low"

    # Refund previous bidder
    if self.highest_bidder != empty(address):
        send(self.highest_bidder, self.highest_bid)

    self.highest_bidder = msg.sender
    self.highest_bid = msg.value
