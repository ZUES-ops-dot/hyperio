// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableToken
 * @dev Example contract with intentional vulnerabilities for testing HyperionScan
 * 
 * WARNING: This contract is for TESTING ONLY. Do not deploy to production!
 */
contract VulnerableToken {
    mapping(address => uint256) public balances;
    address public owner;
    
    // VULNERABILITY: Hardcoded address (for testing)
    address constant TREASURY = 0x1234567890123456789012345678901234567890;
    
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    // VULNERABILITY: No access control on mint
    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }

    // VULNERABILITY: Reentrancy
    function withdraw() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");
        
        // Bad: External call before state update
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
        
        // State update after external call - REENTRANCY!
        balances[msg.sender] = 0;
        
        emit Withdrawal(msg.sender, balance);
    }

    // VULNERABILITY: tx.origin for authentication
    function transferOwnership(address newOwner) external {
        require(tx.origin == owner, "Not owner");
        owner = newOwner;
    }

    // VULNERABILITY: Unchecked send
    function unsafeSend(address payable to, uint256 amount) external {
        to.send(amount);  // Return value not checked!
    }

    // VULNERABILITY: Dangerous delegatecall
    function execute(address target, bytes calldata data) external {
        target.delegatecall(data);  // Arbitrary delegatecall!
    }

    // VULNERABILITY: Block timestamp dependence
    function isLotteryWinner() external view returns (bool) {
        return block.timestamp % 2 == 0;  // Miners can manipulate
    }

    // VULNERABILITY: Integer overflow (pre-0.8.0 pattern)
    function unsafeAdd(uint256 a, uint256 b) external pure returns (uint256) {
        // In Solidity < 0.8.0, this could overflow
        // Note: 0.8.0+ has built-in overflow checks
        unchecked {
            return a + b;
        }
    }

    // VULNERABILITY: Self-destruct without proper access control
    function destroy() external {
        // Missing: require(msg.sender == owner)
        selfdestruct(payable(owner));
    }

    // OK: Properly protected function
    function safeTransfer(address to, uint256 amount) external {
        require(msg.sender == owner, "Only owner");
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        balances[to] += amount;
        
        emit Transfer(msg.sender, to, amount);
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}

// VULNERABILITY: Contract with assembly
contract AssemblyUser {
    function riskyAssembly() external pure returns (uint256 result) {
        assembly {
            // Direct memory/storage access
            result := mload(0x40)
        }
    }
}
