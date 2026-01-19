# Scanner Comparison Report: SolidityDefend vs Slither vs Aderyn

**Generated:** 2026-01-16

**Corpus:** 62 vulnerable Solidity contracts

**Ground Truth:** 69 documented vulnerabilities across 11 core contracts


## Executive Summary

| Metric | SolidityDefend | Slither | Aderyn |
|--------|---------------|---------|--------|
| Total Findings | **10,021** | 951 | 282 |
| Critical | 2,636 | 0 | 0 |
| High | 4,302 | 147 | 45 |
| Medium | 2,142 | 97 | 0 |
| Low | 941 | 217 | 237 |
| Info | 0 | 490 | 0 |

## Detection Rate vs Ground Truth (11 Core Contracts)

| Metric | SolidityDefend | Slither | Aderyn |
|--------|---------------|---------|--------|
| True Positives | **60** | 27 | 22 |
| False Negatives | 0 | 33 | 38 |
| Detection Rate | **100.0%** | 45.0% | 36.7% |

## Top Detectors by Scanner

### SolidityDefend Top 15 Detectors
| Detector | Count |
|----------|-------|
| parameter-consistency | 429 |
| shadowing-variables | 334 |
| missing-zero-address-check | 330 |
| mev-extractable-value | 283 |
| missing-transaction-deadline | 261 |
| test-governance | 258 |
| gas-griefing | 237 |
| missing-access-modifiers | 233 |
| inefficient-storage | 231 |
| excessive-gas-usage | 212 |
| eip7702-storage-corruption | 207 |
| dos-revert-bomb | 151 |
| unchecked-external-call | 141 |
| dos-block-gas-limit | 136 |
| invalid-state-transition | 135 |

### Slither Top 15 Detectors
| Detector | Count |
|----------|-------|
| immutable-states | 104 |
| naming-convention | 100 |
| missing-zero-check | 92 |
| constable-states | 83 |
| low-level-calls | 81 |
| timestamp | 61 |
| solc-version | 46 |
| unchecked-transfer | 46 |
| uninitialized-state | 36 |
| assembly | 35 |
| arbitrary-send-eth | 33 |
| reentrancy-benign | 29 |
| reentrancy-no-eth | 25 |
| unused-return | 24 |
| locked-ether | 20 |

### Aderyn Top 15 Detectors
| Detector | Count |
|----------|-------|
| unused-public-function | 81 |
| state-change-without-event | 61 |
| state-variable-could-be-immutable | 26 |
| state-no-address-check | 15 |
| eth-send-unchecked-address | 13 |
| unsafe-erc20-operation | 12 |
| unspecific-solidity-pragma | 10 |
| push-zero-opcode | 9 |
| contract-locks-ether | 7 |
| state-variable-could-be-constant | 7 |
| reused-contract-name | 6 |
| reentrancy-state-change | 5 |
| storage-array-length-not-cached | 5 |
| ecrecover | 4 |
| costly-loop | 4 |

## Missed Vulnerabilities (False Negatives)

### SolidityDefend Missed
*No missed vulnerabilities in core contracts*

### Slither Missed
| File | Line | Expected Detector | Severity |
|------|------|-------------------|----------|
| AccessControl.sol | 34 | unprotected-initialization | high |
| DelegateCall.sol | 150 | aa-initialization-vulnerability | high |
| DelegateCall.sol | 157 | unprotected-initialization | high |
| DenialOfService.sol | 15 | dos-failed-transfer | high |
| DenialOfService.sol | 72 | unbounded-loop | medium |
| DenialOfService.sol | 81 | unbounded-loop | medium |
| DenialOfService.sol | 50 | dos-failed-transfer | high |
| DenialOfService.sol | 105 | dos-failed-transfer | high |
| FrontRunning.sol | 56 | transaction-ordering-dependence | high |
| FrontRunning.sol | 62 | mev-toxic-flow-exposure | medium |
| FrontRunning.sol | 92 | front-running-vulnerability | high |
| FrontRunning.sol | 98 | transaction-ordering-dependence | medium |
| FrontRunning.sol | 125 | erc20-approve-race | medium |
| FrontRunning.sol | 0 | mev-extractable-value | medium |
| ShortAddress.sol | 30 | short-address-attack | medium |

### Aderyn Missed
| File | Line | Expected Detector | Severity |
|------|------|-------------------|----------|
| AccessControl.sol | 19 | missing-access-modifier | critical |
| AccessControl.sol | 101 | missing-access-modifier | critical |
| DelegateCall.sol | 21 | dangerous-delegatecall | critical |
| DelegateCall.sol | 73 | storage-collision | high |
| DelegateCall.sol | 82 | dangerous-delegatecall | critical |
| DelegateCall.sol | 124 | selfdestruct-vulnerability | critical |
| DelegateCall.sol | 150 | aa-initialization-vulnerability | high |
| DelegateCall.sol | 157 | unprotected-initialization | high |
| DelegateCall.sol | 163 | dangerous-delegatecall | high |
| DenialOfService.sol | 15 | dos-failed-transfer | high |
| DenialOfService.sol | 81 | unbounded-loop | medium |
| DenialOfService.sol | 109 | external-call-in-loop | high |
| FrontRunning.sol | 56 | transaction-ordering-dependence | high |
| FrontRunning.sol | 62 | mev-toxic-flow-exposure | medium |
| FrontRunning.sol | 92 | front-running-vulnerability | high |

## Unique Detection Categories

Categories where only one scanner has detectors:


### SolidityDefend-Exclusive Detector Categories
- **mev**: 12 detectors, 562 findings
- **sandwich**: 5 detectors, 131 findings
- **flashloan**: 3 detectors, 10 findings
- **flash-loan**: 5 detectors, 24 findings
- **eip**: 18 detectors, 630 findings
- **aa-**: 12 detectors, 166 findings
- **defi**: 3 detectors, 212 findings
- **oracle**: 8 detectors, 149 findings
- **l2**: 6 detectors, 178 findings
- **cross-chain**: 2 detectors, 81 findings
- **bridge**: 4 detectors, 111 findings
- **validator**: 2 detectors, 143 findings
- **sequencer**: 3 detectors, 116 findings

## Analysis Conclusion

SolidityDefend found **10.5x more findings** than Slither and **35.5x more** than Aderyn.

This is explained by:
1. **332 detectors** in SolidityDefend vs 99 in Slither and 88 in Aderyn
2. Specialized DeFi, MEV, Account Abstraction, and EIP detectors not present in other tools
3. More aggressive pattern matching (may include some false positives)

Detection rate against documented ground truth: **100.0%**