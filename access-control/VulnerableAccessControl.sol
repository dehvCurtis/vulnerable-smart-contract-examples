// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableAccessControl
 * @notice Test contract for access control vulnerabilities
 *
 * DETECTORS TO TEST:
 * - missing-access-modifiers (Critical)
 * - unprotected-initializer (High)
 * - tx-origin-authentication (Critical)
 * - dangerous-delegatecall (Critical)
 * - centralization-risk (High)
 * - time-locked-admin-bypass (Critical)
 * - role-hierarchy-bypass (Critical)
 * - privilege-escalation-paths (High)
 * - multi-role-confusion (High)
 * - enhanced-access-control (Critical)
 *
 * VULNERABILITIES:
 * 1. Critical functions without access control modifiers
 * 2. Unprotected initializer allowing takeover
 * 3. tx.origin used for authentication (phishing vulnerable)
 * 4. Delegatecall to user-controlled address
 * 5. Single owner without multisig (centralization)
 * 6. Timelock bypass via direct admin change
 * 7. Role hierarchy can be bypassed
 * 8. Privilege escalation through role management
 * 9. Multiple roles cause confusion and errors
 * 10. Missing role checks on critical operations
 */

/**
 * @notice Vulnerable contract with missing access control
 */
contract VulnerableMissingAccessControl {
    address public owner;
    uint256 public criticalValue;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    // ❌ VULNERABILITY 1: Missing access control modifier (missing-access-modifiers)
    // Critical function without onlyOwner or other access control!
    function setCriticalValue(uint256 newValue) external {
        // ❌ No require(msg.sender == owner)!
        // ❌ No onlyOwner modifier!
        // Anyone can call this and change critical state!

        criticalValue = newValue;
    }

    // ❌ VULNERABILITY 2: Transfer ownership without access control (missing-access-modifiers)
    function transferOwnership(address newOwner) external {
        // ❌ Anyone can become owner!
        owner = newOwner;
    }

    // ❌ VULNERABILITY 3: Withdraw funds without protection (missing-access-modifiers)
    function withdrawAll() external {
        // ❌ Anyone can drain the contract!
        payable(msg.sender).transfer(address(this).balance);
    }

    // ❌ VULNERABILITY 4: Mint tokens without control (missing-access-modifiers)
    function mint(address to, uint256 amount) external {
        // ❌ Anyone can mint unlimited tokens!
        balances[to] += amount;
    }

    receive() external payable {}
}

/**
 * @notice Vulnerable initializer pattern
 */
contract VulnerableInitializer {
    address public owner;
    bool public initialized;
    uint256 public value;

    // ❌ VULNERABILITY 5: Unprotected initializer (unprotected-initializer)
    // Can be called by anyone to take over the contract!
    function initialize(address _owner, uint256 _value) external {
        // ❌ No access control!
        // ❌ No require(!initialized) check!
        // First caller becomes owner!

        owner = _owner;
        value = _value;
        initialized = true;
    }

    // ❌ VULNERABILITY 6: Setup function without protection (unprotected-initializer)
    function setup(address admin) external {
        // ❌ Anyone can call setup!
        owner = admin;
    }

    // ❌ VULNERABILITY 7: Configure without one-time guard (unprotected-initializer)
    function configure(uint256 newValue) external {
        // ❌ Can be called multiple times by anyone!
        value = newValue;
    }

    function criticalAction() external {
        require(msg.sender == owner, "Not owner");
        // Critical logic...
    }
}

/**
 * @notice tx.origin authentication vulnerability
 */
contract VulnerableTxOrigin {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    // ❌ VULNERABILITY 8: tx.origin for authentication (tx-origin-authentication)
    // Vulnerable to phishing attacks!
    function withdraw(uint256 amount) external {
        // ❌ Uses tx.origin instead of msg.sender!
        // Attacker can create malicious contract that calls this
        // tx.origin will still be the victim!
        require(tx.origin == owner, "Not owner");

        payable(msg.sender).transfer(amount);
    }

    // ❌ VULNERABILITY 9: tx.origin in authorization check (tx-origin-authentication)
    function authorize(address user) external {
        // ❌ Checks tx.origin - vulnerable to phishing!
        if (tx.origin == owner) {
            balances[user] = 1000 ether;
        }
    }

    // ❌ VULNERABILITY 10: tx.origin comparison (tx-origin-authentication)
    function isAuthorized() external view returns (bool) {
        // ❌ Returns true if tx.origin matches, regardless of msg.sender
        return tx.origin == owner;
    }

    receive() external payable {}
}

/**
 * @notice Dangerous delegatecall vulnerability
 */
contract VulnerableDelegatecall {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // ❌ VULNERABILITY 11: Delegatecall to user-provided address (dangerous-delegatecall)
    function execute(address target, bytes calldata data) external onlyOwner {
        // ❌ Delegatecall to arbitrary address!
        // Even with onlyOwner, this is dangerous
        // Attacker can pass malicious contract that modifies storage

        (bool success,) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    // ❌ VULNERABILITY 12: Unprotected delegatecall (dangerous-delegatecall)
    function executeAny(address target, bytes calldata data) external {
        // ❌ No access control AND delegatecall!
        // Complete contract takeover possible!
        (bool success,) = target.delegatecall(data);
        require(success);
    }

    // ❌ VULNERABILITY 13: Proxy pattern without checks (dangerous-delegatecall)
    function upgradeImplementation(address newImpl) external onlyOwner {
        // ❌ No validation of newImpl!
        // Owner can set malicious implementation
        (bool success,) = newImpl.delegatecall(
            abi.encodeWithSignature("initialize()")
        );
        require(success);
    }
}

/**
 * @notice Centralization risk
 */
contract VulnerableCentralization {
    // ❌ VULNERABILITY 14: Single owner - centralization risk (centralization-risk)
    address public owner;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    constructor() {
        // ❌ Single owner without multisig!
        // If owner key compromised = total loss
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // ❌ Single point of failure for critical operations
    function mint(address to, uint256 amount) external onlyOwner {
        balances[to] += amount;
        totalSupply += amount;
    }

    function burn(address from, uint256 amount) external onlyOwner {
        balances[from] -= amount;
        totalSupply -= amount;
    }

    // ❌ Owner can change critical parameters unilaterally
    function pause() external onlyOwner {
        // Pause entire protocol
    }

    function transferOwnership(address newOwner) external onlyOwner {
        // ❌ No timelock, no multi-sig requirement
        owner = newOwner;
    }
}

/**
 * @notice Time-locked admin bypass
 */
contract VulnerableTimelock {
    address public admin;
    address public pendingAdmin;
    uint256 public adminChangeTime;
    uint256 public constant TIMELOCK_DURATION = 2 days;

    mapping(bytes32 => bool) public queuedTransactions;

    constructor() {
        admin = msg.sender;
    }

    // ❌ VULNERABILITY 15: Timelock can be bypassed (time-locked-admin-bypass)
    function setAdmin(address newAdmin) external {
        // ❌ No timelock! Direct admin change
        // Should require queueing and delay
        require(msg.sender == admin, "Not admin");
        admin = newAdmin;
    }

    // ❌ VULNERABILITY 16: Queue without timelock enforcement (time-locked-admin-bypass)
    function queueAdminChange(address newAdmin) external {
        require(msg.sender == admin, "Not admin");

        pendingAdmin = newAdmin;
        adminChangeTime = block.timestamp + TIMELOCK_DURATION;
    }

    function executeAdminChange() external {
        require(msg.sender == admin, "Not admin");

        // ❌ No check for adminChangeTime!
        // Should require: block.timestamp >= adminChangeTime
        admin = pendingAdmin;
        pendingAdmin = address(0);
    }

    // ❌ VULNERABILITY 17: Cancel without restrictions (time-locked-admin-bypass)
    function cancelAdminChange() external {
        require(msg.sender == admin, "Not admin");

        // ❌ Admin can cancel and immediately set new admin via setAdmin()
        // Bypassing timelock completely!
        pendingAdmin = address(0);
        adminChangeTime = 0;
    }
}

/**
 * @notice Role hierarchy bypass
 */
contract VulnerableRoleHierarchy {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    mapping(bytes32 => mapping(address => bool)) public hasRole;
    mapping(address => uint256) public balances;

    constructor() {
        hasRole[ADMIN_ROLE][msg.sender] = true;
    }

    // ❌ VULNERABILITY 18: Missing role hierarchy check (role-hierarchy-bypass)
    function grantRole(bytes32 role, address account) external {
        // ❌ Any role holder can grant any role!
        // Should check: require(hasRole[ADMIN_ROLE][msg.sender])
        require(
            hasRole[ADMIN_ROLE][msg.sender] ||
            hasRole[MINTER_ROLE][msg.sender] ||
            hasRole[PAUSER_ROLE][msg.sender],
            "No role"
        );

        // ❌ MINTER can grant ADMIN role!
        hasRole[role][account] = true;
    }

    // ❌ VULNERABILITY 19: Role revocation without hierarchy (role-hierarchy-bypass)
    function revokeRole(bytes32 role, address account) external {
        // ❌ Lower roles can revoke higher roles!
        hasRole[role][account] = false;
    }

    function mint(address to, uint256 amount) external {
        require(hasRole[MINTER_ROLE][msg.sender], "Not minter");
        balances[to] += amount;
    }
}

/**
 * @notice Privilege escalation paths
 */
contract VulnerablePrivilegeEscalation {
    address public admin;
    mapping(address => bool) public moderators;
    mapping(address => bool) public operators;
    mapping(address => uint256) public balances;

    constructor() {
        admin = msg.sender;
    }

    // ❌ VULNERABILITY 20: Moderator can escalate to admin (privilege-escalation-paths)
    function promoteToAdmin(address user) external {
        // ❌ Only checks moderator, not admin!
        // Moderator can promote themselves to admin!
        require(moderators[msg.sender], "Not moderator");

        admin = user;
    }

    // ❌ VULNERABILITY 21: Operator can add moderators (privilege-escalation-paths)
    function addModerator(address user) external {
        // ❌ Operator can create moderators
        // Then moderator can become admin via promoteToAdmin!
        require(operators[msg.sender], "Not operator");

        moderators[user] = true;
    }

    // ❌ VULNERABILITY 22: Circular privilege escalation (privilege-escalation-paths)
    function addOperator(address user) external {
        // ❌ Moderator can add operators
        require(moderators[msg.sender], "Not moderator");

        operators[user] = true;
    }

    // Attack path:
    // 1. Become operator (low privilege)
    // 2. Add yourself as moderator via addModerator()
    // 3. Promote yourself to admin via promoteToAdmin()
    // 4. Full contract control!
}

/**
 * @notice Multi-role confusion
 */
contract VulnerableMultiRole {
    mapping(address => string[]) public userRoles;
    mapping(address => uint256) public balances;

    // ❌ VULNERABILITY 23: Multiple roles cause confusion (multi-role-confusion)
    function assignRole(address user, string memory role) external {
        // ❌ No validation! User can have conflicting roles
        // User can be both "admin" and "restricted"
        userRoles[user].push(role);
    }

    // ❌ VULNERABILITY 24: Role check without precedence (multi-role-confusion)
    function performAction() external {
        string[] memory roles = userRoles[msg.sender];

        // ❌ Checks for "operator" but what if user has both "operator" and "banned"?
        // No role precedence or conflict resolution!
        for (uint i = 0; i < roles.length; i++) {
            if (keccak256(bytes(roles[i])) == keccak256(bytes("operator"))) {
                // Execute action
                return;
            }
        }

        revert("Not authorized");
    }

    // ❌ VULNERABILITY 25: Conflicting role logic (multi-role-confusion)
    function withdraw(uint256 amount) external {
        string[] memory roles = userRoles[msg.sender];
        bool canWithdraw = false;

        // ❌ Last role wins - what if roles conflict?
        for (uint i = 0; i < roles.length; i++) {
            if (keccak256(bytes(roles[i])) == keccak256(bytes("withdrawer"))) {
                canWithdraw = true;
            }
            if (keccak256(bytes(roles[i])) == keccak256(bytes("frozen"))) {
                canWithdraw = false; // But frozen was added first!
            }
        }

        require(canWithdraw, "Cannot withdraw");
        payable(msg.sender).transfer(amount);
    }
}

/**
 * @notice Secure access control implementation
 */
contract SecureAccessControl {
    address public owner;
    bool private initialized;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    mapping(bytes32 => mapping(address => bool)) public hasRole;
    mapping(bytes32 => bytes32) public roleAdmin; // Role hierarchy

    constructor() {
        owner = msg.sender;
        hasRole[ADMIN_ROLE][msg.sender] = true;
        roleAdmin[MINTER_ROLE] = ADMIN_ROLE; // ✅ ADMIN controls MINTER
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyRole(bytes32 role) {
        require(hasRole[role][msg.sender], "Missing role");
        _;
    }

    // ✅ Protected initializer
    function initialize() external {
        require(!initialized, "Already initialized");
        require(msg.sender == owner, "Not owner");

        initialized = true;
        // Initialization logic
    }

    // ✅ Proper role hierarchy
    function grantRole(bytes32 role, address account) external {
        // ✅ Only role admin can grant role
        bytes32 adminRole = roleAdmin[role];
        require(hasRole[adminRole][msg.sender], "Not role admin");

        hasRole[role][account] = true;
    }

    // ✅ Uses msg.sender, not tx.origin
    function withdraw() external onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }
}
