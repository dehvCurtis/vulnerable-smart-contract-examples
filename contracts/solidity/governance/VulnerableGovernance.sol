// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableGovernance
 * @notice Test contract for DAO governance vulnerabilities
 *
 * DETECTORS TO TEST:
 * - flash-loan-governance-attack (Critical)
 * - flashloan-governance-attack (High)
 * - test-governance (High)
 *
 * VULNERABILITIES:
 * 1. Flash loan governance attacks (borrow tokens, vote, return)
 * 2. Snapshot bypass (no snapshot, current balance voting)
 * 3. Proposal manipulation (malicious proposal execution)
 * 4. Quorum manipulation
 * 5. Timelock bypass
 * 6. Delegation attacks
 * 7. Vote buying/bribing
 * 8. Majority attack (51% attack)
 * 9. Proposal front-running
 * 10. Vote double-counting
 */

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/**
 * @notice Vulnerable DAO with flash loan voting
 */
contract VulnerableDAOFlashLoan {
    IERC20 public governanceToken;

    struct Proposal {
        address proposer;
        string description;
        address target;
        bytes data;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 startTime;
        uint256 endTime;
        bool executed;
        mapping(address => bool) hasVoted;
    }

    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;

    uint256 public constant VOTING_PERIOD = 3 days;
    uint256 public constant QUORUM = 1000000 * 10**18; // 1M tokens

    constructor(address _token) {
        governanceToken = IERC20(_token);
    }

    function createProposal(
        string calldata description,
        address target,
        bytes calldata data
    ) external returns (uint256) {
        uint256 proposalId = proposalCount++;

        Proposal storage proposal = proposals[proposalId];
        proposal.proposer = msg.sender;
        proposal.description = description;
        proposal.target = target;
        proposal.data = data;
        proposal.startTime = block.timestamp;
        proposal.endTime = block.timestamp + VOTING_PERIOD;

        return proposalId;
    }

    // ❌ VULNERABILITY 1: Flash loan governance attack (flash-loan-governance-attack)
    function vote(uint256 proposalId, bool support) external {
        Proposal storage proposal = proposals[proposalId];

        require(block.timestamp < proposal.endTime, "Voting ended");
        require(!proposal.hasVoted[msg.sender], "Already voted");

        // ❌ Uses current token balance for voting power!
        // ❌ No snapshot of balances at proposal creation!
        // ❌ Flash loan attack possible!

        uint256 votingPower = governanceToken.balanceOf(msg.sender);

        // Flash loan attack:
        // 1. Attacker flash loans 10M governance tokens
        // 2. Calls vote() with 10M voting power
        // 3. Returns flash loan
        // 4. Vote persists with 10M power!
        // 5. Attacker controls DAO without owning tokens!

        if (support) {
            proposal.forVotes += votingPower;
        } else {
            proposal.againstVotes += votingPower;
        }

        proposal.hasVoted[msg.sender] = true;
    }

    function executeProposal(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        require(block.timestamp >= proposal.endTime, "Voting ongoing");
        require(!proposal.executed, "Already executed");
        require(proposal.forVotes > proposal.againstVotes, "Not passed");
        require(proposal.forVotes >= QUORUM, "Quorum not reached");

        proposal.executed = true;

        (bool success,) = proposal.target.call(proposal.data);
        require(success, "Execution failed");
    }
}

/**
 * @notice DAO with delegation vulnerabilities
 */
contract VulnerableDAODelegation {
    IERC20 public token;

    struct Proposal {
        uint256 forVotes;
        uint256 againstVotes;
        uint256 endTime;
        bool executed;
        mapping(address => bool) hasVoted;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(address => address) public delegates;
    mapping(address => uint256) public votingPower;

    uint256 public proposalCount;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // ❌ VULNERABILITY 2: Delegation without validation (test-governance)
    function delegate(address delegatee) external {
        // ❌ No validation that delegatee is trustworthy!
        // ❌ Can delegate to malicious contract!
        // ❌ Delegatee can vote differently than delegator intended!

        address previousDelegate = delegates[msg.sender];

        // Remove voting power from previous delegate
        if (previousDelegate != address(0)) {
            votingPower[previousDelegate] -= token.balanceOf(msg.sender);
        }

        // Add voting power to new delegate
        delegates[msg.sender] = delegatee;
        votingPower[delegatee] += token.balanceOf(msg.sender);

        // Issues:
        // 1. Delegatee can vote against delegator's interests
        // 2. No way to verify delegatee's voting history
        // 3. Delegatee can accept bribes to vote certain way
        // 4. Malicious contract as delegatee can front-run votes
    }

    // ❌ VULNERABILITY 3: Vote with delegated power (test-governance)
    function voteWithDelegation(uint256 proposalId, bool support) external {
        Proposal storage proposal = proposals[proposalId];

        require(!proposal.hasVoted[msg.sender], "Already voted");

        // ❌ Uses current delegated voting power!
        // ❌ Can be manipulated by adding/removing delegations!

        uint256 power = votingPower[msg.sender] + token.balanceOf(msg.sender);

        // Attack:
        // 1. Create proposal
        // 2. Convince users to delegate to attacker
        // 3. Vote with massive delegated power
        // 4. Users later realize they were manipulated
        // 5. Too late, proposal already passed

        if (support) {
            proposal.forVotes += power;
        } else {
            proposal.againstVotes += power;
        }

        proposal.hasVoted[msg.sender] = true;
    }

    function createProposal() external returns (uint256) {
        uint256 proposalId = proposalCount++;
        proposals[proposalId].endTime = block.timestamp + 3 days;
        return proposalId;
    }
}

/**
 * @notice DAO with quorum manipulation
 */
contract VulnerableDAOQuorum {
    struct Proposal {
        uint256 forVotes;
        uint256 againstVotes;
        uint256 totalSupplySnapshot;
        uint256 endTime;
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;

    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // ❌ VULNERABILITY 4: Quorum based on token balance (test-governance)
    function createProposal() external returns (uint256) {
        uint256 proposalId = proposalCount++;

        // ❌ Quorum calculated as % of current total supply!
        // ❌ Attacker can burn tokens to lower quorum threshold!

        Proposal storage proposal = proposals[proposalId];
        proposal.totalSupplySnapshot = getTotalSupply();
        proposal.endTime = block.timestamp + 3 days;

        // Attack:
        // 1. Attacker creates proposal
        // 2. Attacker burns large amount of tokens
        // 3. Quorum threshold drops (e.g., from 1M to 100k)
        // 4. Attacker easily reaches lowered quorum
        // 5. Malicious proposal passes

        return proposalId;
    }

    function getTotalSupply() public view returns (uint256) {
        // Assume this returns actual circulating supply
        return 10000000 * 10**18;
    }

    // ❌ VULNERABILITY 5: Quorum check manipulable
    function executeProposal(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        require(block.timestamp >= proposal.endTime, "Voting ongoing");
        require(!proposal.executed, "Already executed");

        // ❌ Quorum is 10% of snapshot supply
        uint256 quorum = proposal.totalSupplySnapshot / 10;

        // ❌ But if attacker burned tokens, quorum is lower than expected!
        require(proposal.forVotes >= quorum, "Quorum not met");
        require(proposal.forVotes > proposal.againstVotes, "Not passed");

        proposal.executed = true;
    }
}

/**
 * @notice DAO with timelock bypass
 */
contract VulnerableDAOTimelock {
    struct Proposal {
        address target;
        bytes data;
        uint256 eta; // Execution time
        bool executed;
        bool queued;
    }

    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;

    uint256 public constant DELAY = 2 days;
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    // ❌ VULNERABILITY 6: Admin can bypass timelock (test-governance)
    function queueProposal(address target, bytes calldata data) external {
        require(msg.sender == admin, "Not admin");

        uint256 proposalId = proposalCount++;

        proposals[proposalId] = Proposal({
            target: target,
            data: data,
            eta: block.timestamp + DELAY,
            executed: false,
            queued: true
        });
    }

    // ❌ VULNERABILITY 7: Admin can execute immediately
    function executeProposalImmediate(uint256 proposalId) external {
        require(msg.sender == admin, "Not admin");

        // ❌ Admin bypass - can execute without timelock!
        // ❌ Defeats purpose of timelock (giving users time to exit)!

        Proposal storage proposal = proposals[proposalId];
        require(!proposal.executed, "Already executed");

        proposal.executed = true;

        (bool success,) = proposal.target.call(proposal.data);
        require(success);
    }

    function executeProposal(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        require(proposal.queued, "Not queued");
        require(!proposal.executed, "Already executed");
        require(block.timestamp >= proposal.eta, "Timelock not expired");

        proposal.executed = true;

        (bool success,) = proposal.target.call(proposal.data);
        require(success);
    }
}

/**
 * @notice DAO with vote double-counting
 */
contract VulnerableDAODoubleVote {
    struct Proposal {
        uint256 forVotes;
        uint256 againstVotes;
        uint256 endTime;
        mapping(address => bool) hasVoted;
    }

    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;

    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // ❌ VULNERABILITY 8: Vote double-counting via transfer (flash-loan-governance-attack)
    function vote(uint256 proposalId, bool support) external {
        Proposal storage proposal = proposals[proposalId];

        require(block.timestamp < proposal.endTime, "Ended");
        require(!proposal.hasVoted[msg.sender], "Already voted");

        uint256 votes = token.balanceOf(msg.sender);

        if (support) {
            proposal.forVotes += votes;
        } else {
            proposal.againstVotes += votes;
        }

        proposal.hasVoted[msg.sender] = true;

        // ❌ Attack: Vote with account A, transfer tokens to account B, vote again!
        // 1. Alice votes with 100 tokens
        // 2. Alice transfers 100 tokens to Bob
        // 3. Bob votes with same 100 tokens
        // 4. 200 votes counted from 100 tokens!
    }

    function createProposal() external returns (uint256) {
        uint256 proposalId = proposalCount++;
        proposals[proposalId].endTime = block.timestamp + 3 days;
        return proposalId;
    }
}

/**
 * @notice DAO with proposal spam
 */
contract VulnerableDAOSpam {
    struct Proposal {
        address proposer;
        string description;
        uint256 endTime;
    }

    Proposal[] public proposals;

    // ❌ VULNERABILITY 9: No proposal creation cost (test-governance)
    function createProposal(string calldata description) external {
        // ❌ Anyone can create unlimited proposals!
        // ❌ No token requirement, no fee!
        // ❌ Can spam governance with fake proposals!

        proposals.push(Proposal({
            proposer: msg.sender,
            description: description,
            endTime: block.timestamp + 3 days
        }));

        // Attack:
        // 1. Attacker creates 10,000 spam proposals
        // 2. Real proposals get buried
        // 3. Voters can't find legitimate proposals
        // 4. Governance becomes unusable
        // 5. DAO paralyzed
    }

    // ❌ VULNERABILITY 10: No proposal cancellation
    function voteOnProposal(uint256 proposalId) external {
        // Even if proposal is malicious or spam, can't be cancelled!
    }
}

/**
 * @notice DAO with majority attack
 */
contract VulnerableDAOMajority {
    struct Proposal {
        address target;
        bytes data;
        uint256 forVotes;
        uint256 againstVotes;
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;

    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // ❌ VULNERABILITY 11: Simple majority, no supermajority (test-governance)
    function executeProposal(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        require(!proposal.executed, "Already executed");

        // ❌ Only requires forVotes > againstVotes (simple majority)!
        // ❌ No supermajority requirement for critical changes!
        // ❌ 51% can pass any proposal!

        require(proposal.forVotes > proposal.againstVotes, "Not passed");

        // 51% attack:
        // 1. Attacker acquires 51% of tokens
        // 2. Creates malicious proposal (drain treasury)
        // 3. Votes with 51% (passes)
        // 4. Executes proposal
        // 5. 49% minority helpless

        proposal.executed = true;

        (bool success,) = proposal.target.call(proposal.data);
        require(success);
    }
}

/**
 * @notice DAO with vote buying
 */
contract VulnerableDAOVoteBuying {
    struct Proposal {
        uint256 forVotes;
        uint256 againstVotes;
        mapping(address => bool) hasVoted;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(address => uint256) public votingPower;

    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // ❌ VULNERABILITY 12: Vote buying marketplace (test-governance)
    function sellVote(uint256 proposalId, bool support, address buyer) external payable {
        // ❌ Users can sell their voting power!
        // ❌ No mechanism to prevent vote buying!

        Proposal storage proposal = proposals[proposalId];
        require(!proposal.hasVoted[msg.sender], "Already voted");

        uint256 votes = token.balanceOf(msg.sender);

        // Buyer pays for the vote
        payable(msg.sender).transfer(msg.value);

        // Vote according to buyer's preference
        if (support) {
            proposal.forVotes += votes;
        } else {
            proposal.againstVotes += votes;
        }

        proposal.hasVoted[msg.sender] = true;

        // Vote buying attack:
        // 1. Attacker offers $10 per vote
        // 2. Users sell votes for profit
        // 3. Attacker accumulates voting power
        // 4. Passes malicious proposal
        // 5. Makes more profit than cost of buying votes
    }
}

/**
 * @notice Secure DAO with snapshot-based voting
 */
contract SecureDAOSnapshot {
    struct Proposal {
        uint256 forVotes;
        uint256 againstVotes;
        uint256 snapshotBlock;
        uint256 endTime;
        bool executed;
        mapping(address => bool) hasVoted;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => uint256)) public balanceSnapshots;

    uint256 public proposalCount;
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // ✅ Secure: Snapshot voting power at proposal creation
    function createProposal() external returns (uint256) {
        uint256 proposalId = proposalCount++;

        Proposal storage proposal = proposals[proposalId];
        proposal.snapshotBlock = block.number;
        proposal.endTime = block.timestamp + 3 days;

        return proposalId;
    }

    // ✅ Secure: Vote with snapshot balance
    function vote(uint256 proposalId, bool support) external {
        Proposal storage proposal = proposals[proposalId];

        require(!proposal.hasVoted[msg.sender], "Already voted");
        require(block.timestamp < proposal.endTime, "Ended");

        // ✅ Use balance at snapshot block!
        uint256 votes = balanceSnapshots[proposal.snapshotBlock][msg.sender];

        // ✅ If no snapshot, get current balance (and record it)
        if (votes == 0) {
            votes = token.balanceOf(msg.sender);
            balanceSnapshots[proposal.snapshotBlock][msg.sender] = votes;
        }

        if (support) {
            proposal.forVotes += votes;
        } else {
            proposal.againstVotes += votes;
        }

        proposal.hasVoted[msg.sender] = true;

        // ✅ Flash loan attack prevented!
        // ✅ Vote double-counting prevented!
    }

    // ✅ Secure: Supermajority + quorum for critical proposals
    function executeProposal(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        require(!proposal.executed, "Already executed");
        require(block.timestamp >= proposal.endTime, "Voting ongoing");

        // ✅ Supermajority: 66% approval
        require(proposal.forVotes * 3 >= (proposal.forVotes + proposal.againstVotes) * 2, "Supermajority not met");

        // ✅ Quorum: At least 10% of supply voted
        uint256 totalVotes = proposal.forVotes + proposal.againstVotes;
        require(totalVotes >= getTotalSupply() / 10, "Quorum not met");

        proposal.executed = true;
    }

    function getTotalSupply() public view returns (uint256) {
        return 10000000 * 10**18;
    }
}
