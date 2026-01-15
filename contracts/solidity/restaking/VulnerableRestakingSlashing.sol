// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableRestakingSlashing
 * @notice Test contract for restaking slashing vulnerabilities
 *
 * DETECTORS TO TEST:
 * - restaking-slashing-bypass (Critical)
 * - restaking-double-slashing (High)
 * - restaking-operator-validation (High)
 * - restaking-stake-manipulation (Critical)
 *
 * VULNERABILITIES:
 * 1. Slashing without proper validation
 * 2. Double slashing same stake
 * 3. Cascade slashing risks
 * 4. Operator registration without checks
 * 5. Stake amount manipulation
 * 6. Missing slashing conditions validation
 */

interface IEigenPodManager {
    function verifyWithdrawalCredentials(
        uint64 oracleTimestamp,
        bytes32 beaconStateRoot,
        uint40 validatorIndex,
        bytes calldata withdrawalCredentialProof,
        bytes32[] calldata validatorFields
    ) external;
}

/**
 * @notice Vulnerable restaking pool with slashing issues
 */
contract VulnerableRestakingPool {
    struct Operator {
        address operatorAddress;
        uint256 stakedAmount;
        uint256 delegatedAmount;
        bool isActive;
        bool slashed;
    }

    struct Delegator {
        address delegatorAddress;
        uint256 amount;
        address operator;
        uint256 shares;
    }

    mapping(address => Operator) public operators;
    mapping(address => Delegator) public delegators;
    mapping(address => uint256) public slashedAmounts;

    address[] public operatorList;
    uint256 public totalStaked;

    // ❌ VULNERABILITY 1: Missing access control on slashing (restaking-slashing-bypass)
    function slashOperator(address operator, uint256 amount) external {
        // ❌ No validation that caller is authorized slasher!
        // ❌ No check if operator actually misbehaved!
        // Anyone can slash any operator:
        // 1. Attacker calls slashOperator with competitor's address
        // 2. Operator loses stake unfairly
        // 3. Delegators lose funds
        // 4. Attacker can drain entire protocol

        Operator storage op = operators[operator];
        require(op.isActive, "Operator not active");

        // ❌ No slashing condition validation!
        op.stakedAmount -= amount;
        slashedAmounts[operator] += amount;

        // Funds sent to attacker (msg.sender)
        payable(msg.sender).transfer(amount);
    }

    // ❌ VULNERABILITY 2: Double slashing possible (restaking-double-slashing)
    function slashForMisbehavior(address operator, bytes32 evidenceHash) external {
        Operator storage op = operators[operator];

        // ❌ No check if this evidence was already used!
        // ❌ Same misbehavior can be slashed multiple times!
        // Attacker can:
        // 1. Find one slashable event
        // 2. Call slashForMisbehavior multiple times with same evidence
        // 3. Slash operator 100% even though only 1 violation occurred
        // 4. Drain all operator stake and delegator funds

        uint256 slashAmount = op.stakedAmount / 10; // 10% slash

        op.stakedAmount -= slashAmount;
        op.slashed = true;

        slashedAmounts[operator] += slashAmount;
    }

    // ❌ VULNERABILITY 3: Cascade slashing without limits (restaking-slashing-bypass)
    function slashOperatorAndDelegators(address operator, uint256 slashPercentage) external {
        Operator storage op = operators[operator];

        // ❌ Slashes operator AND all delegators without limit!
        // ❌ No maximum slashing percentage check!
        // ❌ Can slash 100% of all funds!

        require(slashPercentage <= 100, "Invalid percentage");

        uint256 operatorSlash = (op.stakedAmount * slashPercentage) / 100;
        op.stakedAmount -= operatorSlash;

        // ❌ Cascades to all delegators without individual checks!
        uint256 delegatorSlash = (op.delegatedAmount * slashPercentage) / 100;
        op.delegatedAmount -= delegatorSlash;

        // If slashPercentage = 100, everyone loses everything!
    }

    // ❌ VULNERABILITY 4: No operator validation (restaking-operator-validation)
    function registerOperator() external payable {
        // ❌ No validation of operator credentials!
        // ❌ No minimum stake requirement!
        // ❌ No reputation check!
        // ❌ No commission rate limits!

        // Malicious operator can:
        // 1. Register with 1 wei stake
        // 2. Attract delegators with fake promises
        // 3. Steal delegator funds
        // 4. Run malicious AVS tasks

        operators[msg.sender] = Operator({
            operatorAddress: msg.sender,
            stakedAmount: msg.value, // ❌ Could be 0!
            delegatedAmount: 0,
            isActive: true,
            slashed: false
        });

        operatorList.push(msg.sender);
    }

    // ❌ VULNERABILITY 5: Stake manipulation (restaking-stake-manipulation)
    function increaseOperatorStake(address operator) external payable {
        Operator storage op = operators[operator];

        // ❌ Anyone can increase any operator's stake!
        // ❌ No validation that sender is the operator!
        // This can be exploited:
        // 1. Operator A has low stake (should be slashed soon)
        // 2. Attacker increases stake to avoid slashing threshold
        // 3. Operator A escapes slashing
        // OR:
        // 1. Attacker inflates operator stake artificially
        // 2. Operator gets more delegations due to high stake
        // 3. Operator rugpulls delegators

        op.stakedAmount += msg.value;
    }

    function delegate(address operator) external payable {
        require(operators[operator].isActive, "Operator not active");

        delegators[msg.sender] = Delegator({
            delegatorAddress: msg.sender,
            amount: msg.value,
            operator: operator,
            shares: msg.value // Simplified share calculation
        });

        operators[operator].delegatedAmount += msg.value;
    }
}

/**
 * @notice Vulnerable AVS (Actively Validated Service) contract
 */
contract VulnerableAVS {
    struct Task {
        bytes32 taskHash;
        address operator;
        uint256 stake;
        bool validated;
        uint256 quorumRequired;
    }

    struct OperatorSet {
        address[] operators;
        mapping(address => uint256) stakes;
        uint256 totalStake;
    }

    mapping(bytes32 => Task) public tasks;
    OperatorSet public quorum;

    // ❌ VULNERABILITY 6: Task validation bypass (restaking-operator-validation)
    function submitTask(bytes32 taskHash, bytes calldata signature) external {
        // ❌ No validation that operator has minimum stake!
        // ❌ No signature verification!
        // ❌ No check for operator reputation/slashing history!

        tasks[taskHash] = Task({
            taskHash: taskHash,
            operator: msg.sender,
            stake: 0, // ❌ Task submitted with 0 stake!
            validated: false,
            quorumRequired: 1
        });
    }

    // ❌ VULNERABILITY 7: Quorum manipulation (restaking-stake-manipulation)
    function validateTask(bytes32 taskHash) external {
        Task storage task = tasks[taskHash];

        // ❌ No validation that caller is part of quorum!
        // ❌ No stake weight checking!
        // ❌ Anyone can validate any task!

        // Attacker can:
        // 1. Submit malicious task
        // 2. Immediately call validateTask
        // 3. Task is validated without proper quorum
        // 4. Malicious operation executed

        task.validated = true;
    }

    // ❌ VULNERABILITY 8: Stake manipulation in quorum (restaking-stake-manipulation)
    function addOperatorToQuorum(address operator, uint256 stake) external {
        // ❌ Anyone can add operators to quorum!
        // ❌ No validation of actual stake!
        // ❌ Attacker can report fake stake amounts!

        quorum.operators.push(operator);
        quorum.stakes[operator] = stake; // ❌ Unverified stake amount!
        quorum.totalStake += stake;

        // Attacker can:
        // 1. Add themselves with 1 billion fake stake
        // 2. Control quorum decisions alone
        // 3. Validate malicious tasks
        // 4. Steal protocol funds
    }

    function getQuorumStake() external view returns (uint256) {
        return quorum.totalStake;
    }
}

/**
 * @notice Vulnerable EigenLayer-style delegation manager
 */
contract VulnerableDelegationManager {
    struct DelegationTerms {
        address delegator;
        address operator;
        uint256 amount;
        uint256 shares;
        uint256 startTime;
        bool active;
    }

    mapping(address => DelegationTerms) public delegations;
    mapping(address => uint256) public operatorStakes;
    mapping(address => bool) public frozenOperators;

    // ❌ VULNERABILITY 9: Force undelegation without validation (restaking-slashing-bypass)
    function forceUndelegate(address delegator) external {
        // ❌ No check that caller is authorized!
        // ❌ No validation of undelegation conditions!

        DelegationTerms storage terms = delegations[delegator];

        // ❌ Anyone can force undelegate any user!
        // Attacker can:
        // 1. Force undelegate all users from honest operators
        // 2. Redirect delegations to attacker-controlled operator
        // 3. Steal rewards
        // 4. Cause mass undelegation DOS

        terms.active = false;
        operatorStakes[terms.operator] -= terms.amount;
    }

    // ❌ VULNERABILITY 10: Slashing without delegation check (restaking-double-slashing)
    function slashDelegation(address delegator, uint256 amount) external {
        DelegationTerms storage terms = delegations[delegator];

        // ❌ No check if delegation is already slashed!
        // ❌ No validation that operator actually misbehaved!
        // ❌ Can slash same delegation multiple times!

        require(terms.active, "Not active");

        terms.amount -= amount;

        // ❌ If called multiple times with same amount,
        // can slash more than delegator's balance!
    }

    // ❌ VULNERABILITY 11: Freeze without proper conditions (restaking-operator-validation)
    function freezeOperator(address operator) external {
        // ❌ Anyone can freeze any operator!
        // ❌ No unfreezing mechanism!
        // ❌ Permanent DOS possible!

        frozenOperators[operator] = true;

        // All delegators to this operator now frozen!
        // Funds locked forever!
    }

    function delegate(address operator) external payable {
        require(!frozenOperators[operator], "Operator frozen");

        delegations[msg.sender] = DelegationTerms({
            delegator: msg.sender,
            operator: operator,
            amount: msg.value,
            shares: msg.value,
            startTime: block.timestamp,
            active: true
        });

        operatorStakes[operator] += msg.value;
    }
}

/**
 * @notice Secure restaking implementation with proper validations
 */
contract SecureRestakingPool {
    struct Operator {
        address operatorAddress;
        uint256 stakedAmount;
        uint256 delegatedAmount;
        bool isActive;
        bool slashed;
        uint256 minStakeRequired;
    }

    mapping(address => Operator) public operators;
    mapping(bytes32 => bool) public processedSlashingEvents;

    address public slashingAuthority;
    uint256 public constant MAX_SLASH_PERCENTAGE = 10; // 10% max per event
    uint256 public constant MIN_OPERATOR_STAKE = 32 ether;

    modifier onlySlashingAuthority() {
        require(msg.sender == slashingAuthority, "Not authorized");
        _;
    }

    constructor(address _slashingAuthority) {
        slashingAuthority = _slashingAuthority;
    }

    // ✅ Secure slashing with authorization and limits
    function slashOperator(
        address operator,
        uint256 amount,
        bytes32 evidenceHash,
        bytes calldata proof
    ) external onlySlashingAuthority {
        // ✅ Only authorized slasher can call
        require(!processedSlashingEvents[evidenceHash], "Already slashed");

        Operator storage op = operators[operator];
        require(op.isActive, "Operator not active");

        // ✅ Validate slashing proof
        require(_validateSlashingProof(operator, evidenceHash, proof), "Invalid proof");

        // ✅ Enforce maximum slash limit
        uint256 maxSlash = (op.stakedAmount * MAX_SLASH_PERCENTAGE) / 100;
        require(amount <= maxSlash, "Exceeds max slash");

        // ✅ Mark evidence as processed (prevent double slashing)
        processedSlashingEvents[evidenceHash] = true;

        op.stakedAmount -= amount;
        op.slashed = true;
    }

    // ✅ Secure operator registration with validation
    function registerOperator(bytes calldata credentials) external payable {
        // ✅ Minimum stake requirement
        require(msg.value >= MIN_OPERATOR_STAKE, "Insufficient stake");

        // ✅ Validate operator credentials
        require(_validateOperatorCredentials(credentials), "Invalid credentials");

        operators[msg.sender] = Operator({
            operatorAddress: msg.sender,
            stakedAmount: msg.value,
            delegatedAmount: 0,
            isActive: true,
            slashed: false,
            minStakeRequired: MIN_OPERATOR_STAKE
        });
    }

    // ✅ Only operator can increase their own stake
    function increaseStake() external payable {
        Operator storage op = operators[msg.sender];
        require(op.isActive, "Not an operator");

        op.stakedAmount += msg.value;
    }

    function _validateSlashingProof(
        address operator,
        bytes32 evidenceHash,
        bytes calldata proof
    ) internal view returns (bool) {
        // Validate fraud proof, signature, etc.
        return true; // Placeholder
    }

    function _validateOperatorCredentials(bytes calldata credentials) internal pure returns (bool) {
        // Validate operator credentials, reputation, etc.
        return credentials.length > 0; // Placeholder
    }
}
