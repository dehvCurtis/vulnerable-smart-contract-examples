# @version ^0.3.0

"""
@title Denial of Service Vulnerability Examples
@notice VULNERABLE - DO NOT USE IN PRODUCTION
@dev Demonstrates various DoS attack vectors in Vyper
"""

# DoS by refusing payment
current_leader: public(address)
current_bid: public(uint256)

@external
@payable
def bid():
    """
    @notice Place bid in auction
    @dev VULNERABLE: Refund can fail and block new bids
    """
    assert msg.value > self.current_bid, "Bid too low"

    # VULNERABILITY: If current_leader is a contract that rejects payments,
    # this send will fail and revert, blocking all future bids
    if self.current_leader != empty(address):
        send(self.current_leader, self.current_bid)

    self.current_leader = msg.sender
    self.current_bid = msg.value


# DoS by gas limit
shareholders: public(DynArray[address, 1000])
shares: public(HashMap[address, uint256])

@external
def add_shareholder(shareholder: address, share_amount: uint256):
    """
    @notice Add shareholder
    """
    self.shareholders.append(shareholder)
    self.shares[shareholder] = share_amount


@external
@payable
def distribute_rewards():
    """
    @notice Distribute rewards to all shareholders
    @dev VULNERABLE: Unbounded loop can exceed gas limit
    """
    total_shares: uint256 = 0

    # VULNERABILITY: As shareholders array grows, this loop can exceed gas limit
    for shareholder in self.shareholders:
        total_shares += self.shares[shareholder]

    # VULNERABILITY: Another unbounded loop
    for shareholder in self.shareholders:
        reward: uint256 = msg.value * self.shares[shareholder] / total_shares
        send(shareholder, reward)


# DoS with block gas limit
users: public(DynArray[address, 10000])
registered: public(HashMap[address, bool])

@external
def register():
    """
    @notice Register as user
    """
    assert not self.registered[msg.sender], "Already registered"
    self.users.append(msg.sender)
    self.registered[msg.sender] = True


@external
def reset():
    """
    @notice Reset all registrations
    @dev VULNERABLE: Can exceed block gas limit with large arrays
    """
    # VULNERABILITY: Iterating over large array can exceed block gas limit
    for user in self.users:
        self.registered[user] = False

    # VULNERABILITY: Clearing large array is very expensive
    self.users = []


@external
def count_registered() -> uint256:
    """
    @notice Count registered users
    @dev VULNERABLE: Unbounded iteration
    """
    count: uint256 = 0

    # VULNERABILITY: Reading entire array can exceed gas limit
    for user in self.users:
        if self.registered[user]:
            count += 1

    return count


# DoS by external contract
recipients: public(DynArray[address, 100])

@external
def add_recipient(recipient: address):
    """
    @notice Add payment recipient
    """
    self.recipients.append(recipient)


@external
@payable
def split_payment():
    """
    @notice Split payment among recipients
    @dev VULNERABLE: One malicious recipient can block all payments
    """
    assert len(self.recipients) > 0, "No recipients"
    share: uint256 = msg.value / len(self.recipients)

    # VULNERABILITY: If any recipient reverts, all payments fail
    for recipient in self.recipients:
        send(recipient, share)


# DoS with storage operations
mapping_data: public(HashMap[uint256, uint256])
counter: public(uint256)

@external
def add_data(value: uint256):
    """
    @notice Add data to storage
    """
    self.mapping_data[self.counter] = value
    self.counter += 1


@external
def clear_all_data():
    """
    @notice Clear all data
    @dev VULNERABLE: Clearing large amounts of data can exceed gas limit
    """
    # VULNERABILITY: Can't iterate over mapping, but even if we could,
    # it would be too expensive with many entries
    # This function becomes unusable as data grows
    for i in range(10000):
        if i >= self.counter:
            break
        self.mapping_data[i] = 0


# Nested loop DoS
matrix: public(HashMap[uint256, HashMap[uint256, uint256]])

@external
def set_matrix_value(x: uint256, y: uint256, value: uint256):
    """
    @notice Set matrix value
    """
    self.matrix[x][y] = value


@external
def sum_matrix(size: uint256) -> uint256:
    """
    @notice Sum all values in matrix
    @dev VULNERABLE: Nested loops with large size exceed gas limit
    """
    total: uint256 = 0

    # VULNERABILITY: Nested loops with user-controlled size
    # size = 100 means 10,000 iterations
    for i in range(1000):
        if i >= size:
            break
        for j in range(1000):
            if j >= size:
                break
            total += self.matrix[i][j]

    return total


# External call in loop
token_holders: public(DynArray[address, 500])

@external
def add_holder(holder: address):
    """
    @notice Add token holder
    """
    self.token_holders.append(holder)


@external
def airdrop(amount: uint256):
    """
    @notice Airdrop tokens to all holders
    @dev VULNERABLE: External calls in loop can fail or run out of gas
    """
    # VULNERABILITY: One failing external call can revert entire transaction
    # VULNERABILITY: Many external calls can exceed gas limit
    for holder in self.token_holders:
        raw_call(
            holder,
            concat(
                method_id("transfer(address,uint256)"),
                convert(holder, bytes32),
                convert(amount, bytes32)
            )
        )
