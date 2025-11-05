// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableFlashLoanGovernance
 * @notice Test contract for flash loan governance attack vulnerabilities
 *
 * DETECTORS TO TEST:
 * - flash-loan-governance-attack (Critical)
 * - flashloan-governance-attack (High)
 *
 * VULNERABILITIES:
 * 1. Voting power based on current balance (flash loan attack)
 * 2. Proposal creation without snapshot
 * 3. Voting without time delay
 * 4. Delegation attacks via flash loans
 * 5. Quorum manipulation via flash loans
 * 6. Single-block governance execution
 * 7. No minimum voting period
 * 8. Flash loan to bypass proposal threshold
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IFlashLoanProvider {
    function flashLoan(address receiver, uint256 amount, bytes calldata data) external;
}

/**
 * @notice Vulnerable governance system
 */
contract VulnerableGovernance {
    IERC20 public governanceToken;

    struct Proposal {
        uint256 id;
        address proposer;
        string description;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 startBlock;
        uint256 endBlock;
        bool executed;
        mapping(address => bool) hasVoted;
    }

    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;

    uint256 public constant PROPOSAL_THRESHOLD = 1000e18; // 1000 tokens
    uint256 public constant QUORUM = 10000e18; // 10000 tokens
    uint256 public constant VOTING_PERIOD = 100; // blocks

    event ProposalCreated(uint256 indexed proposalId, address proposer);
    event VoteCast(address indexed voter, uint256 indexed proposalId, bool support, uint256 weight);
    event ProposalExecuted(uint256 indexed proposalId);

    constructor(address _governanceToken) {
        governanceToken = IERC20(_governanceToken);
    }

    // ❌ VULNERABILITY 1: Proposal creation based on current balance (flash-loan-governance-attack)
    // No snapshot mechanism - attacker can flash loan to meet threshold
    function propose(string calldata description) external returns (uint256) {
        // ❌ Checks CURRENT balance!
        // Attacker can:
        // 1. Flash loan governance tokens
        // 2. Call propose() to meet threshold
        // 3. Return tokens in same transaction
        // 4. Now attacker has active proposal without holding tokens

        require(
            governanceToken.balanceOf(msg.sender) >= PROPOSAL_THRESHOLD,
            "Below proposal threshold"
        );

        // ❌ No snapshot of balances at proposal creation!
        // ❌ No time-lock on proposal execution

        proposalCount++;
        Proposal storage proposal = proposals[proposalCount];
        proposal.id = proposalCount;
        proposal.proposer = msg.sender;
        proposal.description = description;
        proposal.startBlock = block.number;
        proposal.endBlock = block.number + VOTING_PERIOD;

        emit ProposalCreated(proposalCount, msg.sender);

        return proposalCount;
    }

    // ❌ VULNERABILITY 2: Voting power based on current balance (flash-loan-governance-attack)
    function vote(uint256 proposalId, bool support) external {
        Proposal storage proposal = proposals[proposalId];

        require(block.number >= proposal.startBlock, "Voting not started");
        require(block.number <= proposal.endBlock, "Voting ended");
        require(!proposal.hasVoted[msg.sender], "Already voted");

        // ❌ Voting power = CURRENT balance!
        // Attacker can:
        // 1. Flash loan massive amount of governance tokens
        // 2. Vote with inflated power
        // 3. Return tokens immediately
        // 4. Voting power persists even after returning tokens!

        uint256 weight = governanceToken.balanceOf(msg.sender);

        if (support) {
            proposal.forVotes += weight;
        } else {
            proposal.againstVotes += weight;
        }

        proposal.hasVoted[msg.sender] = true;

        emit VoteCast(msg.sender, proposalId, support, weight);
    }

    // ❌ VULNERABILITY 3: No minimum voting period (flashloan-governance-attack)
    function execute(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        require(block.number > proposal.endBlock, "Voting ongoing");
        require(!proposal.executed, "Already executed");

        // ❌ Minimal voting period (100 blocks ~= 20 minutes)
        // ❌ No time delay after voting ends
        // ❌ Can execute immediately after voting period

        // Combined with flash loan voting:
        // 1. Create proposal with flash loan
        // 2. Wait minimal period
        // 3. Flash loan to vote YES
        // 4. Execute immediately
        // 5. Entire attack in ~20 minutes!

        require(proposal.forVotes > proposal.againstVotes, "Proposal failed");
        require(proposal.forVotes >= QUORUM, "Quorum not reached");

        proposal.executed = true;

        emit ProposalExecuted(proposalId);

        // Execute proposal actions...
    }

    // ❌ VULNERABILITY 4: Quorum check at execution time (flash-loan-governance-attack)
    function hasReachedQuorum(uint256 proposalId) public view returns (bool) {
        Proposal storage proposal = proposals[proposalId];

        // ❌ Quorum check uses historical votes
        // BUT votes were cast using flash loan balances!

        return proposal.forVotes >= QUORUM;
    }
}

/**
 * @notice Vulnerable delegation system
 */
contract VulnerableDelegation {
    IERC20 public governanceToken;

    mapping(address => address) public delegates;
    mapping(address => uint256) public delegatedVotes;

    // ❌ VULNERABILITY 5: Delegation without snapshot (flash-loan-governance-attack)
    function delegate(address delegatee) external {
        address currentDelegate = delegates[msg.sender];

        // Remove votes from previous delegate
        if (currentDelegate != address(0)) {
            delegatedVotes[currentDelegate] -= governanceToken.balanceOf(msg.sender);
        }

        // ❌ Delegation power = CURRENT balance!
        // Attacker can:
        // 1. Flash loan governance tokens
        // 2. Delegate massive voting power to their address
        // 3. Return tokens
        // 4. Delegated power remains until next delegation update!

        delegates[msg.sender] = delegatee;
        delegatedVotes[delegatee] += governanceToken.balanceOf(msg.sender);
    }

    // ❌ VULNERABILITY 6: Voting power includes delegated votes (flash-loan-governance-attack)
    function getVotingPower(address account) public view returns (uint256) {
        // ❌ Returns balance + delegated votes
        // Both can be manipulated via flash loan!

        return governanceToken.balanceOf(account) + delegatedVotes[account];
    }
}

/**
 * @notice Vulnerable timelock governance
 */
contract VulnerableTimelockGovernance {
    IERC20 public governanceToken;

    struct Proposal {
        uint256 id;
        address target;
        bytes data;
        uint256 eta; // Execution time
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;

    uint256 public constant DELAY = 2 days;
    uint256 public constant PROPOSAL_THRESHOLD = 10000e18;

    // ❌ VULNERABILITY 7: Proposal queue without voting (flash-loan-governance-attack)
    function queueProposal(address target, bytes calldata data) external returns (uint256) {
        // ❌ Only checks balance threshold, no voting!
        // Attacker can:
        // 1. Flash loan to meet threshold
        // 2. Queue malicious proposal
        // 3. Wait DELAY period
        // 4. Execute (might need another flash loan for execution)

        require(
            governanceToken.balanceOf(msg.sender) >= PROPOSAL_THRESHOLD,
            "Below threshold"
        );

        proposalCount++;
        proposals[proposalCount] = Proposal({
            id: proposalCount,
            target: target,
            data: data,
            eta: block.timestamp + DELAY,
            executed: false
        });

        return proposalCount;
    }

    // ❌ VULNERABILITY 8: Execution without re-checking balance (flashloan-governance-attack)
    function executeProposal(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        require(block.timestamp >= proposal.eta, "Timelock not expired");
        require(!proposal.executed, "Already executed");

        // ❌ No check if proposer still holds tokens!
        // Proposer could have flash-loaned initially, now has 0 tokens

        proposal.executed = true;

        (bool success,) = proposal.target.call(proposal.data);
        require(success, "Execution failed");
    }
}

/**
 * @notice Vulnerable voting escrow (veToken)
 */
contract VulnerableVotingEscrow {
    IERC20 public governanceToken;

    struct Lock {
        uint256 amount;
        uint256 unlockTime;
    }

    mapping(address => Lock) public locks;

    // ❌ VULNERABILITY 9: Lock creation with flash loan (flash-loan-governance-attack)
    function createLock(uint256 amount, uint256 unlockTime) external {
        require(unlockTime > block.timestamp, "Invalid unlock time");

        // ❌ Creates lock with current balance
        // Attacker can:
        // 1. Flash loan tokens
        // 2. Create massive lock (voting power boost)
        // 3. Vote immediately
        // 4. Return flash loan
        // 5. Lock exists but tokens were returned!

        governanceToken.transferFrom(msg.sender, address(this), amount);

        locks[msg.sender] = Lock({
            amount: amount,
            unlockTime: unlockTime
        });

        // ❌ No verification that tokens will remain locked!
    }

    function getVotingPower(address account) external view returns (uint256) {
        Lock memory lock = locks[account];

        if (lock.unlockTime <= block.timestamp) {
            return 0;
        }

        // ❌ Voting power based on lock amount
        // But lock might have been created with flash loan!
        return lock.amount;
    }
}

/**
 * @notice Secure governance with snapshots
 */
contract SecureGovernance {
    IERC20 public governanceToken;

    struct Proposal {
        uint256 id;
        address proposer;
        uint256 snapshotBlock; // ✅ Snapshot of balances
        uint256 forVotes;
        uint256 againstVotes;
        uint256 startBlock;
        uint256 endBlock;
        bool executed;
        mapping(address => bool) hasVoted;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => uint256)) public balanceSnapshots;
    uint256 public proposalCount;

    uint256 public constant PROPOSAL_THRESHOLD = 1000e18;
    uint256 public constant VOTING_DELAY = 1 days;
    uint256 public constant VOTING_PERIOD = 3 days;
    uint256 public constant EXECUTION_DELAY = 2 days;

    // ✅ Proposal with balance snapshot
    function propose(string calldata description) external returns (uint256) {
        require(
            governanceToken.balanceOf(msg.sender) >= PROPOSAL_THRESHOLD,
            "Below threshold"
        );

        proposalCount++;
        uint256 snapshotBlock = block.number;

        Proposal storage proposal = proposals[proposalCount];
        proposal.id = proposalCount;
        proposal.proposer = msg.sender;
        proposal.snapshotBlock = snapshotBlock;
        proposal.startBlock = block.number + (VOTING_DELAY / 12); // Convert time to blocks
        proposal.endBlock = proposal.startBlock + (VOTING_PERIOD / 12);

        return proposalCount;
    }

    // ✅ Voting with snapshot balance
    function vote(uint256 proposalId, bool support) external {
        Proposal storage proposal = proposals[proposalId];

        require(!proposal.hasVoted[msg.sender], "Already voted");

        // ✅ Uses balance at snapshot block!
        // Flash loan after snapshot has no effect
        uint256 weight = getBalanceAtSnapshot(msg.sender, proposal.snapshotBlock);

        if (support) {
            proposal.forVotes += weight;
        } else {
            proposal.againstVotes += weight;
        }

        proposal.hasVoted[msg.sender] = true;
    }

    function getBalanceAtSnapshot(address account, uint256 blockNumber) internal view returns (uint256) {
        // Implementation would use historical balance tracking
        // For this example, simplified
        return balanceSnapshots[blockNumber][account];
    }
}
