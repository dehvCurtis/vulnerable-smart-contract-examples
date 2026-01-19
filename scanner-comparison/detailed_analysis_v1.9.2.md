# SolidityDefend v1.9.2 Detailed Analysis Report

**Generated:** 2026-01-16
**Version:** 1.9.2
**Total Files Scanned:** 63 Solidity files

## Key Metrics

| Metric | Value |
|--------|-------|
| Total Findings | 31,870 |
| Unique Detectors | 284 |
| Critical Findings | 10,244 (32.1%) |
| High Findings | 15,750 (49.4%) |
| Medium Findings | 3,818 (12.0%) |
| Low Findings | 2,058 (6.5%) |
| Detection Rate (Ground Truth) | **100.0%** |

## Top 20 Detectors by Finding Count

| Rank | Detector | Count | Severity |
|------|----------|-------|----------|
| 1 | eip7702-storage-corruption | 1,517 | High |
| 2 | dos-revert-bomb | 1,248 | Medium |
| 3 | dos-block-gas-limit | 1,245 | High |
| 4 | bridge-merkle-bypass | 1,105 | Critical |
| 5 | l2-mev-sequencer-leak | 997 | High |
| 6 | delegatecall-in-loop | 950 | High |
| 7 | missing-visibility-modifier | 914 | Low |
| 8 | initcode-injection | 737 | Critical |
| 9 | jit-liquidity-extraction | 711 | High |
| 10 | eip7702-sweeper-attack | 704 | Critical |
| 11 | shadowing-variables | 572 | Medium |
| 12 | dos-push-pattern | 561 | Medium |
| 13 | contract-recreation-attack | 555 | Critical |
| 14 | eip7702-delegation-phishing | 511 | High |
| 15 | parameter-consistency | 491 | Low |
| 16 | constructor-reentrancy | 490 | High |
| 17 | delegatecall-to-self | 486 | High |
| 18 | timelock-bypass-delegatecall | 486 | High |
| 19 | eip7702-authorization-bypass | 446 | Critical |
| 20 | create2-salt-frontrunning | 401 | Medium |

## Files with Highest Finding Density

| Rank | File | Findings |
|------|------|----------|
| 1 | VulnerableRemainingPatterns.sol | 1,871 |
| 2 | VulnerableEIPs.sol | 1,791 |
| 3 | VulnerableCommonPatterns.sol | 1,403 |
| 4 | DelegatecallProxies.sol | 1,319 |
| 5 | VulnerableAdvancedPatterns.sol | 1,214 |
| 6 | VulnerableClassicReentrancy.sol | 1,175 |
| 7 | VulnerableAccessControl.sol | 1,155 |
| 8 | VulnerableTransientStorageReentrancy.sol | 1,146 |
| 9 | DelegatecallAdvanced_NoLibrary.sol | 900 |
| 10 | VulnerableZKProofs.sol | 853 |

## Per-Category Analysis

| Category | Findings |
|----------|----------|
| mev-vulnerabilities | 2,470 |
| reentrancy | 2,321 |
| eips | 1,791 |
| cross-chain | 1,584 |
| defi-protocols | 1,581 |
| account-abstraction | 1,490 |
| flash-loans | 1,256 |
| advanced-evm-defi | 1,214 |
| access-control | 1,155 |
| oracle-security | 863 |
| zero-knowledge | 853 |
| diamond-advanced | 654 |
| governance | 644 |
| restaking | 575 |
| amm-advanced | 538 |
| ai-agents | 370 |

## New in v1.9.2

### New Detectors
- **missing-visibility-modifier**: State variables without explicit visibility (914 findings)

### Updated Detectors
- **mev-toxic-flow-exposure**: Pattern 6 (slippage protection) refinements

## Comparison vs Other Scanners

| Scanner | Total Findings | Detection Rate |
|---------|---------------|----------------|
| SolidityDefend | 31,870 | 100.0% |
| Slither | 951 | 45.0% |
| Aderyn | 282 | 36.7% |

## Detector Categories

| Category | Detectors | Findings |
|----------|-----------|----------|
| EIP (Account Abstraction/7702) | 18 | 4,109 |
| MEV/Sandwich | 17 | 2,833 |
| DoS | 8 | 4,631 |
| Delegatecall | 6 | 3,358 |
| L2/Bridge/Cross-chain | 15 | 4,593 |
| Reentrancy | 5 | 774 |
| Access Control | 7 | 1,548 |
| Oracle | 8 | 238 |
