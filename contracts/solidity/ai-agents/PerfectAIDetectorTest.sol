// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Perfect AI Detector Test
 * @notice Guaranteed to trigger all 4 AI agent detectors
 */

// =====================================================================
// Test 1: ai-agent-decision-manipulation
// Requires: aidecision/aiagent/autonomousaction keywords
// Must NOT have: (validate OR verify) AND (consensus OR multisig)
// =====================================================================
contract TestAIDecisionManipulation {
    // Uses aidecision without proper checks
    function executeAIDecision(uint256 amount) external {
        // aidecision from aiagent autonomousaction
        payable(msg.sender).transfer(amount);
    }
}

// =====================================================================
// Test 2: ai-agent-prompt-injection
// Requires: aioracle/llm/gpt keywords
// Must NOT have: sanitize AND validate
// =====================================================================
contract TestAIPromptInjection {
    string[] public prompts;

    // aioracle with llm gpt - no input sanitization
    function submitPrompt(string calldata userInput) external {
        prompts.push(userInput);
    }
}

// =====================================================================
// Test 3: ai-agent-resource-exhaustion
// Requires: aicompute/inference/modelrun keywords
// Must NOT have: (gasleft() OR "gas limit") AND (ratelimit OR cooldown)
// =====================================================================
contract TestAIResourceExhaustion {
    bytes[] public data;

    // aicompute inference modelrun without limits
    function runModel(bytes calldata input) external {
        data.push(input);
    }
}

// =====================================================================
// Test 4: autonomous-contract-oracle-dependency
// Requires: autonomous/autoexecute keywords
// Must have EXACTLY 1 occurrence of oracle/chainlink
// Must NOT have: fallback OR backup
// =====================================================================
contract TestAutonomousOracle {
    address public priceSource; // Avoid "oracle" in variable name

    // autonomous contract with single oracle dependency
    function autoexecute(uint256 price) external {
        // Gets price from oracle (single mention)
        require(price > 0, "Invalid");
    }
}
