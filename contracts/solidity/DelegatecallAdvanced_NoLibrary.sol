// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Advanced Delegatecall Patterns Test (No Library)
 * @dev VULNERABLE - Tests for advanced delegatecall detection patterns
 *
 * This contract tests delegatecall patterns that may be missed by basic detectors:
 * 1. Control flow patterns (if/else, ternary, try-catch)
 * 2. Assembly delegatecall
 * 3. Delegatecall in loops
 * 4. Indirect delegatecall through function calls
 * 5. Complex delegatecall patterns
 *
 * NOTE: Library patterns excluded due to parser limitations
 */

// ============================================================================
// 1. CONTROL FLOW PATTERNS
// ============================================================================

contract ControlFlowDelegatecall {
    address public implementation;
    address public owner;

    constructor(address _implementation) {
        implementation = _implementation;
        owner = msg.sender;
    }

    // VULNERABLE: Delegatecall in if/else block
    function conditionalDelegate(bool useImplementation, bytes memory data) public returns (bytes memory) {
        if (useImplementation) {
            // VULNERABILITY: Delegatecall inside if block
            (bool success, bytes memory result) = implementation.delegatecall(data);
            require(success, "Delegatecall failed");
            return result;
        } else {
            return "Using local logic";
        }
    }

    // VULNERABLE: Delegatecall in nested if
    function nestedConditionalDelegate(address target, bytes memory data, bool condition1, bool condition2) public {
        if (condition1) {
            if (condition2) {
                // VULNERABILITY: Nested conditional delegatecall
                (bool success, ) = target.delegatecall(data);
                require(success);
            }
        }
    }

    // VULNERABLE: Ternary operator with delegatecall
    function ternaryDelegate(bool useImplementation, bytes memory data) public returns (bool) {
        // VULNERABILITY: Delegatecall in ternary operator
        return useImplementation
            ? implementation.delegatecall(data).gas
            : false;
    }

    // VULNERABLE: Try-catch with delegatecall
    function tryCatchDelegate(address target, bytes memory data) public returns (bool) {
        try this.externalDelegate(target, data) {
            return true;
        } catch {
            // VULNERABILITY: Delegatecall in catch block
            (bool success, ) = target.delegatecall(data);
            return success;
        }
    }

    function externalDelegate(address target, bytes memory data) external {
        (bool success, ) = target.delegatecall(data);
        require(success, "External delegate failed");
    }

    // VULNERABLE: Switch-case style delegatecall
    function switchStyleDelegate(uint8 option, address target, bytes memory data) public {
        if (option == 1) {
            (bool success, ) = target.delegatecall(data);
            require(success);
        } else if (option == 2) {
            // Different logic
            target.call(data);
        } else if (option == 3) {
            // VULNERABILITY: Another delegatecall path
            (bool success, ) = implementation.delegatecall(data);
            require(success);
        }
    }
}

// ============================================================================
// 2. ASSEMBLY DELEGATECALL PATTERNS
// ============================================================================

contract AssemblyDelegatecall {
    address public implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    // VULNERABLE: Inline assembly delegatecall
    function assemblyDelegate(bytes memory data) public returns (bytes memory) {
        address target = implementation;
        bytes memory result;

        assembly {
            // VULNERABILITY: Low-level delegatecall in assembly
            let success := delegatecall(
                gas(),                  // forward all gas
                target,                 // target address
                add(data, 0x20),       // input data
                mload(data),           // input size
                0,                     // output data (will be set)
                0                      // output size (will be set)
            )

            // Copy return data
            let size := returndatasize()
            result := mload(0x40)
            mstore(0x40, add(result, and(add(size, 0x3f), not(0x1f))))
            mstore(result, size)
            returndatacopy(add(result, 0x20), 0, size)

            if iszero(success) {
                revert(0, 0)
            }
        }

        return result;
    }

    // VULNERABLE: Gas-optimized assembly delegatecall
    function gasOptimizedDelegate(address target, bytes calldata data) external payable {
        assembly {
            // VULNERABILITY: Ultra-optimized delegatecall
            calldatacopy(0, data.offset, data.length)
            let success := delegatecall(gas(), target, 0, data.length, 0, 0)
            returndatacopy(0, 0, returndatasize())

            switch success
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    // VULNERABLE: Assembly delegatecall with manual memory management
    function manualMemoryDelegate(address target) public {
        assembly {
            // VULNERABILITY: Manual memory management with delegatecall
            let ptr := mload(0x40)
            mstore(ptr, 0xabcdef00) // function selector

            let success := delegatecall(gas(), target, ptr, 0x04, 0, 0)

            if iszero(success) {
                revert(0, 0)
            }
        }
    }
}

// ============================================================================
// 3. DELEGATECALL IN LOOPS
// ============================================================================

contract LoopDelegatecall {
    address[] public implementations;

    function addImplementation(address impl) public {
        implementations.push(impl);
    }

    // VULNERABLE: Delegatecall in for loop
    function batchDelegateFor(bytes memory data) public {
        // VULNERABILITY: Delegatecall in for loop
        for (uint256 i = 0; i < implementations.length; i++) {
            (bool success, ) = implementations[i].delegatecall(data);
            require(success, "Batch delegate failed");
        }
    }

    // VULNERABLE: Delegatecall in while loop
    function batchDelegateWhile(bytes memory data) public {
        uint256 i = 0;
        // VULNERABILITY: Delegatecall in while loop
        while (i < implementations.length) {
            (bool success, ) = implementations[i].delegatecall(data);
            require(success, "While delegate failed");
            i++;
        }
    }

    // VULNERABLE: Array iteration with delegatecall
    function multiExecute(address[] memory targets, bytes[] memory dataArray) public {
        require(targets.length == dataArray.length, "Length mismatch");

        // VULNERABILITY: Array iteration with delegatecall
        for (uint256 i = 0; i < targets.length; i++) {
            (bool success, ) = targets[i].delegatecall(dataArray[i]);
            require(success, "Multi execute failed");
        }
    }

    // VULNERABLE: Nested loop with delegatecall
    function nestedLoopDelegate(address[][] memory targetGroups, bytes memory data) public {
        // VULNERABILITY: Nested loop with delegatecall
        for (uint256 i = 0; i < targetGroups.length; i++) {
            for (uint256 j = 0; j < targetGroups[i].length; j++) {
                (bool success, ) = targetGroups[i][j].delegatecall(data);
                require(success, "Nested delegate failed");
            }
        }
    }

    // VULNERABLE: Do-while loop with delegatecall
    function doWhileDelegate(bytes memory data) public {
        uint256 i = 0;
        // VULNERABILITY: Do-while loop with delegatecall
        do {
            if (i < implementations.length) {
                (bool success, ) = implementations[i].delegatecall(data);
                require(success, "Do-while delegate failed");
            }
            i++;
        } while (i < implementations.length);
    }
}

// ============================================================================
// 4. INDIRECT DELEGATECALL
// ============================================================================

contract IndirectDelegatecall {
    address public implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    // VULNERABLE: Public function calls internal delegatecall
    function publicExecute(bytes memory data) public {
        // VULNERABILITY: Indirect delegatecall through internal call
        _internalDelegate(data);
    }

    // Internal function that does delegatecall
    function _internalDelegate(bytes memory data) internal {
        (bool success, ) = implementation.delegatecall(data);
        require(success, "Internal delegate failed");
    }

    // VULNERABLE: Function chain leading to delegatecall
    function chainedExecute(bytes memory data) public {
        // VULNERABILITY: Call chain A -> B -> delegatecall
        _stepOne(data);
    }

    function _stepOne(bytes memory data) internal {
        _stepTwo(data);
    }

    function _stepTwo(bytes memory data) internal {
        // Final step does delegatecall
        (bool success, ) = implementation.delegatecall(data);
        require(success, "Chained delegate failed");
    }

    // VULNERABLE: Callback pattern with delegatecall
    function executeWithCallback(address target, bytes memory data) public {
        // VULNERABILITY: Callback that triggers delegatecall
        (bool success, ) = target.call(
            abi.encodeWithSignature("callback(bytes)", data)
        );
        require(success, "Callback failed");
    }

    function callback(bytes memory data) public {
        // This function does delegatecall when called
        (bool success, ) = implementation.delegatecall(data);
        require(success, "Callback delegate failed");
    }

    // VULNERABLE: Modifier-based delegatecall
    modifier withDelegate(bytes memory data) {
        // VULNERABILITY: Delegatecall in modifier
        (bool success, ) = implementation.delegatecall(data);
        require(success, "Modifier delegate failed");
        _;
    }

    function executeWithModifier(bytes memory data) public withDelegate(data) {
        // Function body - delegatecall happens in modifier
    }
}

// ============================================================================
// 5. COMPLEX DELEGATECALL PATTERNS
// ============================================================================

contract ComplexDelegatecall {
    address public implementation;
    mapping(bytes4 => address) public selectorToImplementation;

    // VULNERABLE: Dynamic selector-based delegatecall
    function dynamicDelegate(bytes memory data) public {
        bytes4 selector;
        assembly {
            selector := mload(add(data, 32))
        }

        address target = selectorToImplementation[selector];
        if (target == address(0)) {
            target = implementation;
        }

        // VULNERABILITY: Dynamic target selection with delegatecall
        (bool success, ) = target.delegatecall(data);
        require(success, "Dynamic delegate failed");
    }

    // VULNERABLE: Delegatecall with return data manipulation
    function manipulatedReturnDelegate(address target, bytes memory data) public returns (uint256) {
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "Manipulated delegate failed");

        // Manipulate return data
        if (result.length >= 32) {
            return abi.decode(result, (uint256)) * 2;
        }
        return 0;
    }

    // VULNERABLE: Delegatecall with storage write
    function storageWriteDelegate(address target, bytes memory data) public {
        uint256 beforeBalance = address(this).balance;

        // VULNERABILITY: Delegatecall that can modify storage
        (bool success, ) = target.delegatecall(data);
        require(success, "Storage delegate failed");

        uint256 afterBalance = address(this).balance;
        require(afterBalance >= beforeBalance, "Balance decreased");
    }

    // VULNERABLE: Delegatecall with event emission
    event DelegateExecuted(address indexed target, bool success);

    function eventEmittingDelegate(address target, bytes memory data) public {
        // VULNERABILITY: Delegatecall with side effects
        (bool success, ) = target.delegatecall(data);
        emit DelegateExecuted(target, success);
    }

    // VULNERABLE: Delegatecall with reentrancy potential
    bool private locked;

    function reentrancyDelegate(address target, bytes memory data) public {
        require(!locked, "Reentrancy detected");
        locked = true;

        // VULNERABILITY: Delegatecall can modify locked state
        (bool success, ) = target.delegatecall(data);
        require(success, "Reentrancy delegate failed");

        locked = false;
    }
}

// ============================================================================
// MALICIOUS CONTRACTS FOR TESTING
// ============================================================================

contract MaliciousImplementation {
    uint256 public maliciousData;

    function exploit() public {
        // When called via delegatecall, this modifies caller's storage
        assembly {
            sstore(0, 0xdeadbeef)
        }
    }

    function stealOwnership() public {
        // Overwrites slot 0 (usually owner)
        assembly {
            sstore(0, caller())
        }
    }
}
