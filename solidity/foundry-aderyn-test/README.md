# Foundry Aderyn Test Project

This is a minimal Foundry project designed to test the Aderyn scanner integration in BlockSecOps.

## Purpose

This project contains an intentionally vulnerable ERC20-like token contract (`VulnerableToken.sol`) with multiple security issues that Aderyn should detect.

## Vulnerabilities Included

The `VulnerableToken` contract contains the following intentional vulnerabilities:

1. **Missing Access Control** - `mint()` function can be called by anyone
2. **Reentrancy** - `withdraw()` updates state after external call
3. **Unchecked External Call** - `withdrawToAddress()` doesn't check call result
4. **Missing Zero Address Checks** - Multiple functions don't validate addresses
5. **Missing Events** - Critical state changes without event emission
6. **Centralization Risk** - Single owner with god mode privileges
7. **State Changes After External Calls** - Multiple instances
8. **Approval Without Event** - `approve()` doesn't emit event
9. **Unauthorized Owner Change** - `changeOwner()` lacks access control
10. **Centralized Burn** - Owner can burn any user's tokens

## Testing Aderyn

To test Aderyn with this project:

1. **Upload to BlockSecOps Dashboard**:
   - Zip the entire `foundry-aderyn-test/` directory
   - Upload to http://127.0.0.1:3000/
   - Aderyn should now appear in the scanner list (requires project structure)

2. **Run Aderyn Scan**:
   - Select Aderyn from the scanner list
   - Run the scan
   - Expected: Aderyn should detect 10+ vulnerabilities

3. **Multi-Scanner Test**:
   - Select multiple scanners: Aderyn + Slither + Semgrep
   - Run combined scan
   - Verify deduplication groups are created for overlapping findings

## Expected Aderyn Detections

Aderyn should flag:
- `missing-access-control` - mint(), changeOwner()
- `reentrancy` - withdraw()
- `unchecked-call` - withdrawToAddress()
- `missing-zero-check` - mint(), approve(), changeOwner()
- `missing-event` - mint(), approve(), changeOwner()
- `centralization-risk` - burnAll(), single owner
- `state-variable-changes-after-call` - withdraw(), transferFrom()

## Project Structure

```
foundry-aderyn-test/
├── foundry.toml          # Foundry configuration
├── src/
│   └── VulnerableToken.sol   # Intentionally vulnerable contract
├── test/
│   └── VulnerableToken.t.sol # Basic tests demonstrating vulnerabilities
├── lib/                  # Empty (would contain forge-std)
└── README.md             # This file
```

## Notes

- This project is for testing purposes only
- The contract should NEVER be deployed to a live network
- All vulnerabilities are intentional for scanner testing
- No actual funds should be used with this contract

## Comparison with Single-File Scan

When uploading just `VulnerableToken.sol` as a single file:
- Aderyn will NOT appear (requires project structure)
- Only single-file scanners will be available (Slither, Semgrep, Solhint, Wake, Echidna, Halmos, Medusa)
- 7 scanners visible vs 8 for project upload

This demonstrates the difference between project-based scanners (Aderyn) and file-based scanners.
