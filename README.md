# approval-guard

Audit an EVM wallet's ERC-20 token approvals — and find the unlimited ones
before someone else finds them for you.

## The problem

Every time you swap, list, or stake, you usually sign an `approve()` that
lets a contract move your tokens. Most dapps ask for **unlimited**
approval, and it stays valid **forever** — even after you stop using the
dapp. If that contract is later exploited (or was malicious all along),
your balance can be swept without any further signature from you.

approval-guard reads the allowances a wallet has granted and flags the
risky ones. It is **read-only**: it never asks for a private key, never
signs anything, and never sends a transaction. All it needs is a public
wallet address.

## Quick start

Python 3.10+ only. No dependencies — standard library only, no API key.

```bash
python3 approval_guard.py 0xYourWalletAddress
python3 approval_guard.py 0xYourWalletAddress --chain bsc
python3 approval_guard.py 0xYourWalletAddress --all-chains
python3 approval_guard.py 0xYourWalletAddress --json   # machine-readable
```

## Example

Auditing a well-known public address on Ethereum mainnet (full output in
[`demo/sample-report.txt`](demo/sample-report.txt) — all data is public
on-chain state):

```
== ethereum ==
  [HIGH] USDT -> Uniswap V3 Router
       allowance: UNLIMITED USDT | balance: 291.3682 USDT
       why: unlimited allowance
  [HIGH] DAI -> Permit2
       allowance: UNLIMITED DAI | balance: 14.372 DAI
       why: unlimited allowance

Summary: 4 allowance(s) found (HIGH 4, MEDIUM 0, LOW 0)
```

## Risk levels

| Level | Meaning |
|-------|---------|
| HIGH | Unlimited allowance. The spender can move all of that token, now and in the future. An approval that started unlimited and has been partly spent still counts. |
| MEDIUM | Allowance to a spender outside the known-protocol list, or an allowance larger than the current balance. |
| LOW | Limited allowance to a known protocol contract. |

## Scope — read before trusting a clean report

The audit covers a curated matrix of popular tokens × well-known protocol
contracts per chain (see `CHAINS` in `approval_guard.py`), plus anything
you pass with `--token` / `--spender`. An approval to a token or spender
outside that set is **not seen**. A clean report means "nothing risky in
the checked set", not "nothing risky, period". Cross-check with a block
explorer approval tracker (e.g. revoke.cash) for a full history.

Supported chains: **Ethereum, BNB Smart Chain, Base**.

## Options

```
address                    wallet address to audit (0x...)
--chain {ethereum,bsc,base}  chain to audit (default: ethereum)
--all-chains               audit every supported chain
--token SYMBOL:0xADDR[:DECIMALS]
                           extra token to check (repeatable)
--spender NAME:0xADDR      extra spender to check (repeatable)
--rpc URL                  override the JSON-RPC endpoint
--timeout SECONDS          per-request timeout (default 15)
--json                     machine-readable JSON output
```

Exit codes: `0` = no HIGH findings, `2` = HIGH findings present,
`1` = usage error or RPC failure. Safe to run in CI as a wallet hygiene
check.

## How it works

For each chain it calls the ERC-20 `allowance(owner, spender)` view
function through a public JSON-RPC endpoint — one batched request per
token (balance + all allowances), with endpoint fallback and retries, so
a flaky public RPC cannot kill the audit. Results are classified by the
rules above. Nothing is written on-chain, ever.

## Revoking

approval-guard only reports; it never revokes. To remove an approval,
use [revoke.cash](https://revoke.cash), your wallet's approval manager,
or send `approve(spender, 0)` from the wallet itself.

## Tests

```bash
python3 -m unittest test_approval_guard -v
```

16 tests, no network access needed (the RPC layer is faked).

## Roadmap

- More chains (Arbitrum, Polygon, Solana SPL approvals).
- Full-history mode via explorer APIs (all approvals ever granted, not
  just the curated matrix).
- Revoke-helper: print the exact `approve(spender, 0)` calldata for each
  HIGH finding.

## License

MIT — see [LICENSE](LICENSE).
