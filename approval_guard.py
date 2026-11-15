#!/usr/bin/env python3
"""approval-guard: audit an EVM wallet's ERC-20 token approvals.

Unlimited token approvals are one of the most common ways wallets get
drained: you approve a contract once, it keeps the right to move your
tokens forever, and if that contract is later exploited (or was malicious
all along) your balance can be swept without any further signature.

approval-guard reads the allowances your wallet has granted and flags
the risky ones. It is READ-ONLY: it never asks for a private key, never
signs anything, and never sends a transaction. All it needs is a public
wallet address.

Usage:
    python3 approval_guard.py 0xYourWalletAddress
    python3 approval_guard.py 0xYourWalletAddress --chain bsc
    python3 approval_guard.py 0xYourWalletAddress --all-chains --json

How it works:
  For each supported chain it calls the ERC-20 `allowance(owner, spender)`
  view function (via a public JSON-RPC endpoint, no API key needed) for a
  curated matrix of popular tokens x well-known protocol contracts, plus
  any extra --token / --spender you pass. Each non-zero allowance is
  classified:

    HIGH    unlimited allowance (2**256 - 1) to any spender
    MEDIUM  allowance to a spender that is not a known protocol contract,
            or an allowance larger than your current balance
    LOW     limited allowance to a known protocol contract

Scope (read this before trusting a clean report): the check covers the
curated token/spender lists in CHAINS plus anything you pass with
--token / --spender. An approval to a token or spender outside those
lists is NOT seen. For a full history, cross-check with a block-explorer
approval tracker (e.g. revoke.cash, etherscan token approvals).

Exit codes: 0 = no HIGH findings, 2 = HIGH findings present,
1 = usage error or RPC failure on every endpoint.
"""

import argparse
import http.client
import json
import re
import sys
import time
import urllib.error
import urllib.request

VERSION = "1.0.0"
MAX_UINT256 = 2 ** 256 - 1
# An allowance this close to the max counts as unlimited: it is what an
# originally-unlimited approval looks like after the spender has used a
# little of it (allowance decreases as it is spent). 10**24 raw units is
# far above any realistic token balance.
UNLIMITED_SLACK = 10 ** 24


def is_unlimited(raw):
    """True when an allowance is exactly or effectively unlimited."""
    return raw >= MAX_UINT256 - UNLIMITED_SLACK

# ERC-20 function selectors.
SEL_ALLOWANCE = "dd62ed3e"   # allowance(address,address)
SEL_BALANCE_OF = "70a08231"  # balanceOf(address)

ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# Curated token lists: symbol -> (contract address, decimals).
# Spenders: display name -> contract address.
# A wrong address here is harmless: allowance() on it just returns 0.
CHAINS = {
    "ethereum": {
        "chain_id": 1,
        "rpc": [
            "https://ethereum.publicnode.com",
            "https://1rpc.io/eth",
        ],
        "explorer": "https://etherscan.io/address/",
        "tokens": {
            "USDC": ("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6),
            "USDT": ("0xdAC17F958D2ee523a2206206994597C13D831ec7", 6),
            "DAI": ("0x6B175474E89094C44Da98b954EedeAC495271d0F", 18),
            "WETH": ("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", 18),
            "WBTC": ("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", 8),
            "LINK": ("0x514910771AF9Ca656af840dff83E8264EcF986CA", 18),
            "UNI": ("0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", 18),
        },
        "spenders": {
            "Uniswap V2 Router": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
            "Uniswap V3 Router": "0xE592427A0AEce92De3Edee1F18E0157C05861564",
            "Uniswap Universal Router": "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
            "OpenSea Seaport": "0x00000000000000ADc04C56Bf30aC9d3c0aAF14DC",
            "1inch v5 Router": "0x1111111254EEB25477B68fb85Ed929f73A960582",
            "Permit2": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
            "Aave V3 Pool": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
        },
    },
    "bsc": {
        "chain_id": 56,
        "rpc": [
            "https://bsc-dataseed.binance.org",
            "https://bsc-dataseed1.defibit.io",
        ],
        "explorer": "https://bscscan.com/address/",
        "tokens": {
            # Note: BSC USDT/USDC use 18 decimals (unlike Ethereum's 6).
            "USDT": ("0x55d398326f99059fF775485246999027B3197955", 18),
            "USDC": ("0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", 18),
            "WBNB": ("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", 18),
            "BUSD": ("0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56", 18),
            "CAKE": ("0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82", 18),
        },
        "spenders": {
            "PancakeSwap V2 Router": "0x10ED43C718714eb63d5aA57B78B54704E256024E",
            "PancakeSwap V3 SwapRouter": "0x1b81D678ffb9C0263b24A97847620C99d213eB14",
            "PancakeSwap Smart Router": "0x13f4EA83D0bd40E75C8222255bc855a974568Dd4",
            "PancakeSwap Universal Router": "0x1b0e556B935E4E67fC0D5C2A21D666F081761D62",
            "PancakeSwap Permit2": "0x31c2F6fcFf4F8759b3Bd5Bf0e1084A055615c768",
            "1inch v5 Router": "0x1111111254EEB25477B68fb85Ed929f73A960582",
        },
    },
    "base": {
        "chain_id": 8453,
        "rpc": [
            "https://mainnet.base.org",
            "https://base.publicnode.com",
        ],
        "explorer": "https://basescan.org/address/",
        "tokens": {
            "USDC": ("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", 6),
            "WETH": ("0x4200000000000000000000000000000000000006", 18),
            "cbETH": ("0x2Ae3F1Ec7F1F5012CFEab0185bfc7aa3cf0DEc22", 18),
            "DAI": ("0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb", 18),
        },
        "spenders": {
            "Uniswap Universal Router": "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
            "Permit2": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
            "Aerodrome Router": "0xcF77a3Ba9A5ca399B7c97c74d54e5b1Beb874E43",
            "BaseSwap Router": "0x327Df1E6de1B484fe8e3Bd4Dd3Bf5aEca7e1dA5a",
        },
    },
}


def valid_address(addr):
    """True when addr looks like a 20-byte hex address (0x + 40 hex)."""
    return bool(addr) and bool(ADDR_RE.match(addr))


def _encode_call(selector, *addrs):
    """ABI-encode a call with only address arguments."""
    data = selector
    for addr in addrs:
        data += addr[2:].lower().rjust(64, "0")
    return "0x" + data


def _decode_uint256(hex_result):
    """Decode a 32-byte uint256 from an eth_call result."""
    raw = hex_result[2:] if hex_result.startswith("0x") else hex_result
    return int(raw.rjust(64, "0")[-64:], 16)


class RpcError(Exception):
    pass


class RpcClient:
    """Minimal JSON-RPC client (eth_call only) with endpoint fallback."""

    def __init__(self, endpoints, timeout=15):
        self.endpoints = list(endpoints)
        self.timeout = timeout
        self._id = 0

    def call_batch(self, calls):
        """One batched eth_call for many (to, data) pairs.

        Returns a list of decoded uint256 results in the same order.
        Public RPCs rate-limit bursts of single requests, so the audit
        sends one batch per token instead of one request per allowance.
        Raises RpcError when every endpoint fails.
        """
        items = []
        for to, data in calls:
            self._id += 1
            items.append({"jsonrpc": "2.0", "id": self._id,
                          "method": "eth_call",
                          "params": [{"to": to, "data": data}, "latest"]})
        payload = json.dumps(items).encode("utf-8")
        errors = []
        for url in self.endpoints:
            for _attempt in range(2):
                try:
                    req = urllib.request.Request(
                        url, data=payload, method="POST",
                        headers={"Content-Type": "application/json",
                                 "User-Agent": "approval-guard/" + VERSION})
                    with urllib.request.urlopen(
                            req, timeout=self.timeout) as r:
                        resp = json.loads(r.read().decode("utf-8"))
                    if not isinstance(resp, list):
                        raise RpcError("non-batch reply from %s" % url)
                    by_id = {}
                    for entry in resp:
                        if "error" in entry:
                            raise RpcError("RPC error from %s: %s"
                                           % (url, entry["error"]))
                        by_id[entry["id"]] = _decode_uint256(
                            entry["result"])
                    return [by_id[item["id"]] for item in items]
                except (urllib.error.URLError, http.client.HTTPException,
                        TimeoutError, OSError, RpcError, ValueError,
                        KeyError) as exc:
                    errors.append("%s: %s" % (url, exc))
                    time.sleep(0.5)
        raise RpcError("all RPC endpoints failed: " + "; ".join(errors))

    def call(self, to, data):
        """Single eth_call (convenience wrapper over call_batch)."""
        return self.call_batch([(to, data)])[0]


def classify(allowance, balance, spender_known):
    """Risk level for one non-zero allowance.

    HIGH   unlimited allowance (spender can drain the whole balance,
           present and future) -- regardless of who the spender is.
    MEDIUM allowance to a spender outside the known-protocol list, or an
           allowance larger than the current balance.
    LOW    limited allowance to a known protocol contract.
    """
    if is_unlimited(allowance):
        return "HIGH", "unlimited allowance"
    if not spender_known:
        return "MEDIUM", "spender is not a known protocol contract"
    if balance is not None and allowance > balance:
        return "MEDIUM", "allowance exceeds current balance"
    return "LOW", "limited allowance to a known protocol contract"


def fmt_amount(raw, decimals):
    """Human-readable token amount (up to 4 decimals, no trailing zeros)."""
    if is_unlimited(raw):
        return "UNLIMITED"
    whole, frac = divmod(raw, 10 ** decimals)
    frac_s = str(frac).rjust(decimals, "0")[:4].rstrip("0")
    return "%d.%s" % (whole, frac_s) if frac_s else str(whole)


def audit_chain(chain_name, owner, rpc=None, extra_tokens=None,
                extra_spenders=None, timeout=15):
    """Audit one chain. Returns (findings, error).

    findings: list of dicts, one per non-zero allowance.
    error: None on success, else a string describing the RPC failure.
    """
    cfg = CHAINS[chain_name]
    endpoints = [rpc] if rpc else cfg["rpc"]
    client = RpcClient(endpoints, timeout=timeout)
    tokens = dict(cfg["tokens"])
    for spec in extra_tokens or []:
        symbol, addr, dec = spec
        tokens[symbol] = (addr, dec)
    spenders = dict(cfg["spenders"])
    known = {addr.lower() for addr in spenders.values()}
    for name, addr in extra_spenders or []:
        spenders[name] = addr

    findings = []
    try:
        for symbol, (token_addr, decimals) in tokens.items():
            batch = [ (token_addr, _encode_call(SEL_BALANCE_OF, owner)) ]
            batch += [(token_addr, _encode_call(SEL_ALLOWANCE, owner, s))
                      for s in spenders.values()]
            results = client.call_batch(batch)
            balance = results[0]
            for (name, spender), allowance in zip(spenders.items(),
                                                  results[1:]):
                if allowance == 0:
                    continue
                level, reason = classify(allowance, balance,
                                         spender.lower() in known)
                findings.append({
                    "chain": chain_name,
                    "token": symbol,
                    "token_address": token_addr,
                    "spender": name,
                    "spender_address": spender,
                    "spender_known": spender.lower() in known,
                    "allowance_raw": str(allowance),
                    "allowance": fmt_amount(allowance, decimals),
                    "balance": fmt_amount(balance, decimals),
                    "risk": level,
                    "reason": reason,
                })
            time.sleep(0.3)  # be gentle with public endpoints
    except RpcError as exc:
        return findings, str(exc)
    return findings, None


def render_text(owner, results):
    """Human-readable report. results: {chain: (findings, error)}."""
    lines = ["approval-guard %s" % VERSION,
             "Wallet: %s" % owner,
             "Read-only audit: no keys asked, nothing signed.",
             ""]
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for chain, (findings, error) in results.items():
        lines.append("== %s ==" % chain)
        if error:
            lines.append("  RPC unavailable: %s" % error)
            lines.append("")
            continue
        if not findings:
            lines.append("  No allowances found in the checked set.")
            lines.append("")
            continue
        for f in findings:
            counts[f["risk"]] += 1
            lines.append("  [%s] %s -> %s" % (f["risk"], f["token"],
                                              f["spender"]))
            lines.append("       allowance: %s %s | balance: %s %s"
                         % (f["allowance"], f["token"],
                            f["balance"], f["token"]))
            lines.append("       spender: %s" % f["spender_address"])
            lines.append("       why: %s" % f["reason"])
        lines.append("")
    total = sum(counts.values())
    lines.append("Summary: %d allowance(s) found "
                 "(HIGH %d, MEDIUM %d, LOW %d)"
                 % (total, counts["HIGH"], counts["MEDIUM"], counts["LOW"]))
    if counts["HIGH"]:
        lines.append("HIGH findings mean a contract can move ALL of that "
                     "token, now and in the future.")
        lines.append("To revoke: revoke.cash, or call approve(spender, 0) "
                     "from your wallet.")
    lines.append("Scope: curated tokens x known protocol contracts, plus "
                 "any --token / --spender given. Approvals outside that "
                 "set are not seen; cross-check with an explorer.")
    return "\n".join(lines)


def parse_extra_token(spec):
    """Parse SYMBOL:0xaddress:decimals (decimals default 18)."""
    parts = spec.split(":")
    if len(parts) not in (2, 3) or not valid_address(parts[1]):
        raise argparse.ArgumentTypeError(
            "bad --token %r, want SYMBOL:0xaddress[:decimals]" % spec)
    dec = 18
    if len(parts) == 3:
        try:
            dec = int(parts[2])
        except ValueError:
            raise argparse.ArgumentTypeError(
                "bad decimals in --token %r" % spec)
    return (parts[0], parts[1], dec)


def parse_extra_spender(spec):
    """Parse NAME:0xaddress (name may contain ':' if quoted, keep simple)."""
    name, _, addr = spec.rpartition(":")
    if not name or not valid_address(addr):
        raise argparse.ArgumentTypeError(
            "bad --spender %r, want NAME:0xaddress" % spec)
    return (name, addr)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Audit an EVM wallet's ERC-20 token approvals "
                    "(read-only; no keys, no signing).")
    parser.add_argument("address", help="wallet address to audit (0x...)")
    parser.add_argument("--chain", choices=sorted(CHAINS),
                        default="ethereum",
                        help="chain to audit (default: ethereum)")
    parser.add_argument("--all-chains", action="store_true",
                        help="audit every supported chain")
    parser.add_argument("--token", action="append", type=parse_extra_token,
                        default=[], metavar="SYMBOL:0xADDR[:DECIMALS]",
                        help="extra token to check (repeatable)")
    parser.add_argument("--spender", action="append",
                        type=parse_extra_spender, default=[],
                        metavar="NAME:0xADDR",
                        help="extra spender to check (repeatable)")
    parser.add_argument("--rpc", default=None,
                        help="override the JSON-RPC endpoint URL")
    parser.add_argument("--timeout", type=float, default=15,
                        help="per-request timeout in seconds (default 15)")
    parser.add_argument("--json", action="store_true",
                        help="print machine-readable JSON instead of text")
    parser.add_argument("--version", action="version",
                        version="approval-guard " + VERSION)
    args = parser.parse_args(argv)

    if not valid_address(args.address):
        parser.error("'%s' is not a valid 0x address" % args.address)
    owner = args.address.lower()
    chains = sorted(CHAINS) if args.all_chains else [args.chain]

    results = {}
    for chain in chains:
        findings, error = audit_chain(
            chain, owner, rpc=args.rpc, extra_tokens=args.token,
            extra_spenders=args.spender, timeout=args.timeout)
        results[chain] = (findings, error)

    if args.json:
        out = {"version": VERSION, "address": owner, "chains": {}}
        for chain, (findings, error) in results.items():
            out["chains"][chain] = {"findings": findings, "error": error}
        print(json.dumps(out, indent=2))
    else:
        print(render_text(owner, results))

    if any(err for _, err in results.values()):
        return 1
    if any(f["risk"] == "HIGH"
           for findings, _ in results.values() for f in findings):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
