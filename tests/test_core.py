import copy
import itertools
import json
import random
import re
import unittest
from urllib.parse import urlsplit

from hostgrant_diff.core import (
    MAX_BYTES,
    InputError,
    compare,
    load_manifest,
    matches_url,
    parse_pattern,
)


def manifest(required=(), optional=()):
    return {
        "manifest_version": 3,
        "host_permissions": list(required),
        "optional_host_permissions": list(optional),
    }


def atoms(patterns):
    return tuple(a for p in patterns for a in parse_pattern(p))


def oracle(patterns, url):
    """Independent regex matcher for the finite DNS fixtures, without core parsing."""
    parsed = urlsplit(url)
    actual_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    for pattern in patterns:
        if pattern == "<all_urls>":
            return parsed.scheme in ("http", "https", "file")
        scheme, address = pattern.split("://", 1)
        authority = address.split("/", 1)[0]
        if scheme != "*" and scheme != parsed.scheme:
            continue
        if scheme == "*" and parsed.scheme not in ("http", "https"):
            continue
        if scheme == "file":
            if not parsed.netloc:
                return True
            continue
        host, _, port = authority.partition(":")
        if port and port != "*" and int(port) != actual_port:
            continue
        if host == "*":
            return True
        if host.startswith("*."):
            expression = r"(?:[a-z0-9-]+\.)*" + re.escape(host[2:])
        else:
            expression = re.escape(host)
        if re.fullmatch(expression, parsed.hostname or "", flags=re.I):
            return True
    return False


class SemanticsTests(unittest.TestCase):
    def test_split_schemes_and_path_edit_are_equivalent(self):
        old = manifest(["http://*.example.test/*", "https://*.example.test/*"])
        new = manifest(["*://*.example.test/changed/path"])
        report = compare(old, new)
        for key in [
            "newly_required",
            "newly_requestable",
            "no_longer_required",
            "no_longer_requestable",
        ]:
            self.assertEqual(report[key], [])
        self.assertEqual(report["status"], "no-host-expansion")

    def test_wildcard_includes_apex(self):
        self.assertEqual(
            compare(manifest(["https://*.example.test/*"]), manifest(["https://example.test/*"]))[
                "newly_required"
            ],
            [],
        )

    def test_suffix_label_boundary(self):
        result = compare(
            manifest(["https://*.example.test/*"]), manifest(["https://badexample.test/*"])
        )
        self.assertEqual(result["status"], "host-expansion")

    def test_optional_to_required_promotion(self):
        report = compare(
            manifest([], ["https://*.example.test/*"]), manifest(["https://api.example.test/*"])
        )
        self.assertEqual(report["newly_requestable"], [])
        self.assertTrue(report["newly_required"][0]["previously_requestable"])

    def test_optional_broadening_counts(self):
        report = compare(
            manifest([], ["https://a.example.test/*"]), manifest([], ["https://*.example.test/*"])
        )
        self.assertEqual(report["newly_required"], [])
        self.assertEqual(len(report["newly_requestable"]), 1)

    def test_required_to_optional_is_not_expansion(self):
        report = compare(
            manifest(["https://*.example.test/*"]), manifest([], ["https://*.example.test/*"])
        )
        self.assertEqual(report["status"], "no-host-expansion")
        self.assertTrue(report["no_longer_required"])
        self.assertEqual(report["no_longer_requestable"], [])

    def test_port_widening_has_nondefault_witness(self):
        report = compare(
            manifest(["https://example.test:443/*"]), manifest(["https://example.test/*"])
        )
        self.assertEqual(report["newly_required"][0]["witness_url"], "https://example.test:1/")

    def test_any_port_contains_explicit_port(self):
        self.assertEqual(
            compare(
                manifest(["https://example.test:*/*"]), manifest(["https://example.test:8443/*"])
            )["status"],
            "no-host-expansion",
        )

    def test_ports_and_hosts_do_not_cross_product(self):
        old = manifest(["https://a.example.test:443/*", "https://b.example.test:8443/*"])
        new = manifest(["https://a.example.test:8443/*"])
        self.assertEqual(compare(old, new)["status"], "host-expansion")

    def test_file_is_added_by_all_urls_but_not_scheme_wildcard(self):
        report = compare(manifest(["*://*/*"]), manifest(["<all_urls>"]))
        self.assertEqual(
            report["newly_required"],
            [
                {
                    "within_pattern": "file:///*",
                    "witness_url": "file:///hostgrant-diff-witness",
                    "previously_requestable": False,
                }
            ],
        )

    def test_file_paths_are_ignored_for_host_grants(self):
        self.assertEqual(
            compare(manifest(["file:///old/*"]), manifest(["file:///new/*"]))["status"],
            "no-host-expansion",
        )

    def test_ipv4_ipv6_and_hostname_case(self):
        old = manifest(
            ["https://[2001:0db8:0:0:0:0:0:1]/*", "http://127.0.0.1/*", "https://EXAMPLE.test/*"]
        )
        new = manifest(
            ["https://[2001:db8::1]/*", "http://127.0.0.1:8080/*", "https://example.test/*"]
        )
        self.assertEqual(compare(old, new)["status"], "no-host-expansion")

    def test_apex_and_many_child_rules_do_not_cover_wildcard(self):
        old = ["https://example.test/*"] + [f"https://*.w{i}.example.test/*" for i in range(10)]
        report = compare(manifest(old), manifest(["https://*.example.test/*"]))
        self.assertEqual(report["newly_required"][0]["witness_url"], "https://w10.example.test/")

    def test_all_host_witness_avoids_exact_ipv6_rules(self):
        old = ["https://[2001:db8::1]/*", "https://[2001:db8::2]/*"]
        report = compare(manifest(old), manifest(["https://*/*"]))
        self.assertEqual(report["newly_required"][0]["witness_url"], "https://[2001:db8::3]/")

    def test_dedup_and_order_do_not_change_result(self):
        old = ["https://a.example.test/*", "http://b.example.test/*"]
        report = compare(manifest(old), manifest(list(reversed(old)) + [old[0]]))
        self.assertEqual(report["status"], "no-host-expansion")
        self.assertEqual(report["no_longer_required"], [])

    def test_other_surface_changes_are_explicit(self):
        old = manifest()
        new = manifest()
        new.update(
            content_scripts=[{"matches": ["<all_urls>"], "js": ["script.js"]}],
            permissions=["debugger"],
            version="2",
        )
        report = compare(old, new)
        self.assertEqual(report["unmodeled_changed_keys"], ["content_scripts", "permissions"])
        self.assertEqual(report["status"], "no-host-expansion")
        self.assertIn("declared", report["scope"])

    def test_input_unchanged_determinism(self):
        old = manifest(["https://*.example.test/*"])
        new = manifest(["<all_urls>"])
        snapshot = copy.deepcopy((old, new))
        self.assertEqual(compare(old, new), compare(old, new))
        self.assertEqual((old, new), snapshot)

    def test_300_seeded_finite_domain_oracle_checks(self):
        rng = random.Random(33033)
        choices = [
            f"{s}://{h}{p}/*"
            for s, h, p in itertools.product(
                ["http", "https", "*"],
                ["a.example.test", "b.example.test", "*.example.test", "*"],
                ["", ":80", ":443", ":8443"],
            )
            if s != "*" or not p
        ] + ["file:///*", "<all_urls>"]
        domain = [
            f"{s}://{h}:{p}/arbitrary"
            for s, h, p in itertools.product(
                ["http", "https"],
                [
                    "a.example.test",
                    "b.example.test",
                    "example.test",
                    "other.example.test",
                    "unrelated.test",
                ],
                [1, 80, 443, 8443],
            )
        ] + ["file:///sample"]
        for _ in range(300):
            old = rng.sample(choices, rng.randrange(6))
            new = rng.sample(choices, rng.randrange(6))
            report = compare(manifest(old), manifest(new))
            sampled_new = any(oracle(new, url) and not oracle(old, url) for url in domain)
            # This fixture domain contains representatives of every scheme/host/port class.
            self.assertEqual(bool(report["newly_required"]), sampled_new, (old, new))
            for item in report["newly_required"]:
                self.assertTrue(oracle(new, item["witness_url"]), (old, new, item))
                self.assertFalse(oracle(old, item["witness_url"]), (old, new, item))
            sampled_removed = any(oracle(old, url) and not oracle(new, url) for url in domain)
            self.assertEqual(bool(report["no_longer_required"]), sampled_removed, (old, new))


class ValidationTests(unittest.TestCase):
    def test_chromium_wildcard_scheme_does_not_accept_explicit_port(self):
        for value in ["*://example.test:443/*", "*://[::1]:80/*"]:
            with self.assertRaises(InputError):
                parse_pattern(value)
        self.assertTrue(parse_pattern("*://example.test:*/*"))

    def test_unicode_casefold_does_not_bypass_ascii_contract(self):
        with self.assertRaises(InputError):
            parse_pattern("https://\u212a.example.test/*")

    def test_unmodeled_null_addition_is_still_reported(self):
        before = manifest()
        after = manifest()
        after["custom"] = None
        self.assertEqual(compare(before, after)["unmodeled_changed_keys"], ["custom"])

    def test_supported_patterns(self):
        for pattern in [
            "http://localhost/*",
            "https://xn--bcher-kva.example/*",
            "https://example.test:65535/*",
            "file:///",
            "*://*.example.test:*/path",
        ]:
            self.assertTrue(parse_pattern(pattern))

    def test_unsupported_patterns_fail_closed(self):
        values = [
            None,
            3,
            True,
            "",
            "x" * 2049,
            "https://a.test",
            "http://a.test/\n",
            "https://a.test/a b",
            "ftp://a.test/*",
            "chrome://settings/*",
            "file://localhost/*",
            "https://user@a.test/*",
            "https://*.127.0.0.1/*",
            "https://*.com/*",
            "https://bücher.example/*",
            "https://a.test./*",
            "https://a..test/*",
            "https://x*y.test/*",
            "https:///*",
            "https://127.1/*",
            "http://0x7f000001/*",
            "http://0x7f.1/*",
            "http://[::1/*",
            "http://[bad]/*",
            "http://[::1]extra/*",
            "http://::1/*",
            "http://[fe80::1%eth0]/*",
            "https://a.test:0/*",
            "https://a.test:65536/*",
            "https://a.test:080/*",
            "https://a.test:/*",
            "https://-bad.test/*",
        ]
        for value in values:
            with self.subTest(value=value), self.assertRaises(InputError):
                parse_pattern(value)

    def test_manifest_structure_and_budget(self):
        for value in [
            None,
            [],
            {},
            {"manifest_version": True},
            {"manifest_version": 2},
            {"manifest_version": 3.0},
            {"manifest_version": 3, "host_permissions": "*://*/*"},
            manifest(["https://a.test/*"] * 257),
            manifest([7]),
        ]:
            with self.subTest(value=value), self.assertRaises(InputError):
                compare(value, manifest())

    def test_loader_limits_and_duplicates(self):
        for data in [
            b"[]",
            b"\xff",
            b"{",
            b'{"manifest_version":3,"manifest_version":3}',
            b'{"n":NaN}',
            b'{"n":1e9999}',
            b"[" * 65 + b"]" * 65,
            b" " * (MAX_BYTES + 1),
            b"9" * 5000,
        ]:
            with self.subTest(size=len(data)), self.assertRaises(InputError):
                load_manifest(data)
        self.assertEqual(
            load_manifest(b'\xef\xbb\xbf{"manifest_version":3}'), {"manifest_version": 3}
        )
        # Brackets and escaped quotes inside metadata strings do not count as nesting.
        value = {"manifest_version": 3, "description": '["\\' * 100, "numeric": 0.25}
        self.assertEqual(load_manifest(json.dumps(value).encode()), value)

    def test_url_matcher_rejects_nonmodel_urls(self):
        all_hosts = atoms(["<all_urls>"])
        for url in [
            "ftp://example.test/",
            "https://user:pw@example.test/",
            "https:///",
            "https://[invalid]/",
            "https://example.test:bad/",
            "file://server/path",
        ]:
            with self.subTest(url=url):
                self.assertFalse(matches_url(all_hosts, url))

    def test_maximum_pattern_lists(self):
        old = manifest([f"https://h{i}.example.test/*" for i in range(256)])
        result = compare(old, manifest(["https://*.example.test/*"]))
        self.assertEqual(result["status"], "host-expansion")


if __name__ == "__main__":
    unittest.main()
