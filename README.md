# vulnerable-smart-contract-examples

A collection of vulnerable smart contracts for security research and education.

## Repository Structure

```
├── contracts/                    # Single contracts organized by language
│   ├── solidity/                 # Solidity contracts
│   │   ├── access-control/
│   │   ├── account-abstraction/
│   │   ├── advanced-evm-defi/
│   │   ├── ai-agents/
│   │   ├── amm-advanced/
│   │   ├── code-quality/
│   │   ├── common-patterns/
│   │   ├── cross-chain/
│   │   ├── defi-protocols/
│   │   ├── diamond-advanced/
│   │   ├── eips/
│   │   ├── erc7683-intents/
│   │   ├── final-edge-cases/
│   │   ├── flash-loans/
│   │   ├── governance/
│   │   ├── mev-vulnerabilities/
│   │   ├── oracle-security/
│   │   ├── reentrancy/
│   │   ├── remaining-patterns/
│   │   ├── restaking/
│   │   ├── specialized-patterns/
│   │   ├── tokens/
│   │   ├── upgrades/
│   │   ├── zero-knowledge/
│   │   └── *.sol                 # Individual vulnerability examples
│   ├── move/                     # Move language contracts
│   ├── solana/                   # Solana/Rust programs
│   └── vyper/                    # Vyper contracts
├── foundry-projects/             # Foundry-based projects
│   └── foundry-test/
├── hardhat-projects/             # Hardhat-based projects
│   └── hardhat-test/
└── README.md
```

## Contract Categories

### Solidity
- **access-control/** - Access control vulnerabilities
- **account-abstraction/** - ERC-4337 related vulnerabilities
- **cross-chain/** - Bridge and cross-chain vulnerabilities
- **defi-protocols/** - DeFi-specific vulnerabilities
- **flash-loans/** - Flash loan attack vectors
- **mev-vulnerabilities/** - MEV and front-running issues
- **oracle-security/** - Oracle manipulation vulnerabilities
- **reentrancy/** - Reentrancy attack patterns
- **upgrades/** - Proxy and upgrade vulnerabilities

### Other Languages
- **move/** - Move language vulnerability examples
- **solana/** - Solana program vulnerabilities
- **vyper/** - Vyper contract vulnerabilities

## Projects

### Foundry Projects
Located in `foundry-projects/`. Run with:
```bash
cd foundry-projects/foundry-test
forge build
forge test
```

### Hardhat Projects
Located in `hardhat-projects/`. Run with:
```bash
cd hardhat-projects/hardhat-test
npm install
npx hardhat compile
```
