#!/usr/bin/env python3
"""Unit tests for approval_guard.py (no network access needed).

Run:  python3 -m unittest test_approval_guard -v
"""

import unittest

import approval_guard as ag

ALICE = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
BOB = "0x00000000000000ADc04C56Bf30aC9d3c0aAF14DC"


class TestValidation(unittest.TestCase):
    def test_valid_addresses(self):
        self.assertTrue(ag.valid_address(ALICE))
        self.assertTrue(ag.valid_address(ALICE.lower()))
        self.assertTrue(ag.valid_address(
            "0x0000000000000000000000000000000000000000"))

    def test_invalid_addresses(self):
        self.assertFalse(ag.valid_address(""))
        self.assertFalse(ag.valid_address("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"))
        self.assertFalse(ag.valid_address("0x1234"))
        self.assertFalse(ag.valid_address(
            "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"))
        self.assertFalse(ag.valid_address(None))


class TestEncoding(unittest.TestCase):
    def test_allowance_call(self):
        data = ag._encode_call(ag.SEL_ALLOWANCE, ALICE, BOB)
        self.assertTrue(data.startswith("0xdd62ed3e"))
        # selector (4 bytes) + 2 addresses (32 bytes each) = 68 bytes.
        self.assertEqual(len(data), 2 + 68 * 2)
        self.assertIn(ALICE[2:].lower(), data)
        self.assertIn(BOB[2:].lower(), data)

    def test_decode_uint256(self):
        self.assertEqual(ag._decode_uint256("0x" + "00" * 31 + "01"), 1)
        self.assertEqual(ag._decode_uint256("0x" + "ff" * 32),
                         ag.MAX_UINT256)
        self.assertEqual(ag._decode_uint256("0x0"), 0)


class TestClassify(unittest.TestCase):
    def test_unlimited_is_high_even_for_known_spender(self):
        level, _ = ag.classify(ag.MAX_UINT256, 100, True)
        self.assertEqual(level, "HIGH")

    def test_near_max_counts_as_unlimited(self):
        # An unlimited approval that has been partially spent still
        # leaves an allowance within a hair of the max.
        level, _ = ag.classify(ag.MAX_UINT256 - 10 ** 6, 0, True)
        self.assertEqual(level, "HIGH")
        self.assertEqual(ag.fmt_amount(ag.MAX_UINT256 - 10 ** 6, 18),
                         "UNLIMITED")

    def test_unknown_spender_is_medium(self):
        level, _ = ag.classify(100, 1000, False)
        self.assertEqual(level, "MEDIUM")

    def test_over_balance_is_medium(self):
        level, _ = ag.classify(2000, 1000, True)
        self.assertEqual(level, "MEDIUM")

    def test_limited_known_spender_is_low(self):
        level, _ = ag.classify(100, 1000, True)
        self.assertEqual(level, "LOW")

    def test_zero_balance_known_spender(self):
        # Allowance with nothing held yet: the approval is still live,
        # and any future deposit is immediately spendable up to the
        # allowance, so over-balance counts as MEDIUM.
        level, _ = ag.classify(100, 0, True)
        self.assertEqual(level, "MEDIUM")  # 100 > 0 balance


class TestFormatting(unittest.TestCase):
    def test_unlimited(self):
        self.assertEqual(ag.fmt_amount(ag.MAX_UINT256, 18), "UNLIMITED")

    def test_whole_and_fraction(self):
        self.assertEqual(ag.fmt_amount(1_250_000_000, 6), "1250")
        self.assertEqual(ag.fmt_amount(1_250_500_000, 6), "1250.5")
        self.assertEqual(ag.fmt_amount(5, 18), "0")

    def test_zero(self):
        self.assertEqual(ag.fmt_amount(0, 18), "0")


class TestChainConfig(unittest.TestCase):
    def test_all_addresses_valid(self):
        for name, cfg in ag.CHAINS.items():
            for symbol, (addr, dec) in cfg["tokens"].items():
                self.assertTrue(ag.valid_address(addr),
                                "%s token %s" % (name, symbol))
                self.assertIsInstance(dec, int)
                self.assertGreater(dec, 0)
            for sname, addr in cfg["spenders"].items():
                self.assertTrue(ag.valid_address(addr),
                                "%s spender %s" % (name, sname))

    def test_rpc_lists_nonempty(self):
        for name, cfg in ag.CHAINS.items():
            self.assertTrue(cfg["rpc"], name)
            for url in cfg["rpc"]:
                self.assertTrue(url.startswith("https://"), url)


class TestAuditWithFakeRpc(unittest.TestCase):
    def test_audit_uses_rpc_client(self):
        # Swap in a fake client that returns a fixed allowance for the
        # first token's first spender and zero otherwise.
        state = {"batches": 0}

        class FakeRpc(ag.RpcClient):
            def __init__(self, endpoints, timeout=15):
                pass

            def call_batch(self, calls):
                state["batches"] += 1
                out = [10 ** 18]  # balanceOf
                for i in range(len(calls) - 1):
                    if state["batches"] == 1 and i == 0:
                        out.append(ag.MAX_UINT256)
                    else:
                        out.append(0)
                return out

        orig = ag.RpcClient
        ag.RpcClient = FakeRpc
        try:
            findings, error = ag.audit_chain("ethereum", ALICE.lower())
        finally:
            ag.RpcClient = orig
        self.assertIsNone(error)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["risk"], "HIGH")
        self.assertEqual(findings[0]["allowance"], "UNLIMITED")


if __name__ == "__main__":
    unittest.main()
