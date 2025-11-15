// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Minimal AI Agent Vulnerabilities
 * @notice Focused test contracts to trigger specific AI agent detectors
 */

// =====================================================================
// Test 1: AI Agent Decision Manipulation
// =====================================================================
contract AIAgentDecisionTest {
    address public aiagent;

    // Uses aidecision pattern without validation or consensus
    function executeAIDecision(uint256 amount) external {
        // aidecision autonomousaction without checks
        payable(msg.sender).transfer(amount);
    }

    function setAgent(address newAgent) external {
        aiagent = newAgent;
    }
}

// =====================================================================
// Test 2: AI Agent Prompt Injection
// =====================================================================
contract AIPromptInjectionTest {
    address public aioracle;
    string[] public prompts;

    // Uses aioracle llm gpt without sanitization
    function submitPrompt(string calldata userPrompt) external {
        // llm gpt prompt goes directly to aioracle
        prompts.push(userPrompt);
    }

    function processLLMResponse(string calldata gptResponse) external {
        // Process gpt response from aioracle
    }
}

// =====================================================================
// Test 3: AI Agent Resource Exhaustion
// =====================================================================
contract AIResourceExhaustionTest {
    bytes[] public models;

    // Uses aicompute inference modelrun without limits
    function runInference(bytes calldata modelWeights) external {
        // aicompute inference modelrun
        models.push(modelWeights);
    }

    function executeModelRun(bytes calldata data) external {
        // modelrun without gas limits
        for (uint i = 0; i < models.length; i++) {
            // Process aicompute
        }
    }
}

// =====================================================================
// Test 4: Autonomous Contract Oracle Dependency
// =====================================================================
contract AutonomousOracleDependencyTest {
    address public oracle;

    // Autonomous contract relying on single oracle
    function autonomousAction(uint256 price) external {
        // autonomousaction based on oracle
        require(price > 0, "Invalid");
    }
}
