// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Front-Running Vulnerability Example
 * @dev VULNERABLE - DO NOT USE IN PRODUCTION
 *
 * This contract is vulnerable to front-running attacks where attackers
 * can see pending transactions and submit their own with higher gas fees.
 */
contract VulnerablePuzzle {
    bytes32 public solutionHash;
    uint256 public reward = 10 ether;
    address public owner;
    bool public solved;

    constructor(bytes32 _solutionHash) payable {
        solutionHash = _solutionHash;
        owner = msg.sender;
    }

    // VULNERABLE: Solution is visible in mempool before confirmation
    function submitSolution(string memory _solution) public {
        require(!solved, "Already solved");

        // VULNERABILITY: Anyone can see the solution in the mempool and front-run it
        require(keccak256(abi.encodePacked(_solution)) == solutionHash, "Incorrect solution");

        solved = true;
        payable(msg.sender).transfer(reward);
    }

    receive() external payable {}
}

/**
 * @title Front-Running in DEX
 * @dev Shows front-running vulnerability in token swaps
 */
contract VulnerableDEX {
    mapping(address => uint256) public tokenABalance;
    mapping(address => uint256) public tokenBBalance;
    uint256 public tokenAReserve = 1000 ether;
    uint256 public tokenBReserve = 1000 ether;

    // Simplified constant product AMM
    function getSwapAmount(uint256 _tokenAAmount) public view returns (uint256) {
        // x * y = k
        uint256 k = tokenAReserve * tokenBReserve;
        uint256 newTokenAReserve = tokenAReserve + _tokenAAmount;
        uint256 newTokenBReserve = k / newTokenAReserve;
        return tokenBReserve - newTokenBReserve;
    }

    // VULNERABLE: Transaction ordering dependency
    function swapAforB(uint256 _tokenAAmount, uint256 _minTokenBAmount) public {
        uint256 tokenBAmount = getSwapAmount(_tokenAAmount);

        // VULNERABILITY: Front-runner can see this transaction and swap before it,
        // causing the price to move and potentially causing this transaction to fail
        // or execute at a worse rate
        require(tokenBAmount >= _minTokenBAmount, "Slippage too high");

        tokenABalance[msg.sender] -= _tokenAAmount;
        tokenBBalance[msg.sender] += tokenBAmount;

        tokenAReserve += _tokenAAmount;
        tokenBReserve -= tokenBAmount;
    }

    function deposit(uint256 _tokenA, uint256 _tokenB) public {
        tokenABalance[msg.sender] += _tokenA;
        tokenBBalance[msg.sender] += _tokenB;
    }
}

/**
 * @title Transaction Ordering Dependence
 * @dev Shows vulnerability where transaction order affects outcome
 */
contract VulnerableICO {
    uint256 public price = 1 ether;
    uint256 public tokensAvailable = 1000;
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: Price can be front-run
    function updatePrice(uint256 _newPrice) public {
        require(msg.sender == owner, "Not owner");
        // VULNERABILITY: Users buying tokens can be front-run by owner increasing price
        price = _newPrice;
    }

    function buyTokens(uint256 _amount) public payable {
        require(tokensAvailable >= _amount, "Not enough tokens");
        // VULNERABILITY: Price might change between when user submits transaction
        // and when it's mined
        require(msg.value >= price * _amount, "Insufficient payment");

        tokensAvailable -= _amount;
        balances[msg.sender] += _amount;
    }
}

/**
 * @title ERC20 Approval Front-Running
 * @dev Shows approve/transferFrom race condition
 */
contract VulnerableERC20 {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;

    string public name = "Vulnerable Token";
    string public symbol = "VULN";

    constructor(uint256 _initialSupply) {
        balances[msg.sender] = _initialSupply;
    }

    // VULNERABLE: Changing allowance can be front-run
    function approve(address _spender, uint256 _amount) public returns (bool) {
        // VULNERABILITY: If user tries to change allowance from N to M,
        // spender can front-run by:
        // 1. transferFrom N tokens (old allowance)
        // 2. Let approve transaction execute
        // 3. transferFrom M tokens (new allowance)
        // Result: spender transferred N+M tokens instead of M
        allowances[msg.sender][_spender] = _amount;
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _amount) public returns (bool) {
        require(balances[_from] >= _amount, "Insufficient balance");
        require(allowances[_from][msg.sender] >= _amount, "Insufficient allowance");

        balances[_from] -= _amount;
        balances[_to] += _amount;
        allowances[_from][msg.sender] -= _amount;

        return true;
    }
}
