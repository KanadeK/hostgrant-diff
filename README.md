# hostgrant-diff

Compare **declared host grants** between two Chrome Manifest V3 files and get concrete URLs showing newly requested access. Python 3.10+, offline, no runtime dependencies. It never loads an extension, reads a browser profile, resolves a hostname or opens a witness URL.

A textual diff treats replacing separate `http://*.example.test/*` and `https://*.example.test/*` declarations with `*://*.example.test/*` as a change. Their modeled host scope is the same. Moving a host from optional to required is a meaningful change even when total requestable access stays the same. This tool distinguishes both cases.

## Install and try

```sh
git clone https://github.com/KanadeK/hostgrant-diff.git
cd hostgrant-diff
python -m venv .venv
# Linux/macOS: . .venv/bin/activate
# PowerShell: .venv\Scripts\Activate.ps1
python -m pip install .
hostgrant-diff examples/before.json examples/after.json
```

The example exits **1** and reports newly required access under `https://*.example.test/*`, with a witness such as `https://example.test/`. Its `previously_requestable: true` shows that this witness was already available through an optional declaration. It also reports newly requestable HTTP access.

```sh
hostgrant-diff examples/equivalent-before.json examples/equivalent-after.json
# Exit 0: no-host-expansion; scheme consolidation and ignored host-path changes.
hostgrant-diff examples/before.json examples/after.json -o review.json
# Exit 1 is expected; review.json is created.
```

Existing output files are refused. Choose a new filename or remove a previous generated report before repeating `-o`. Without `-o`, JSON goes to stdout. One input may be `-` for stdin. `python -m hostgrant_diff ...` is equivalent to the installed command.

Uninstall with `python -m pip uninstall hostgrant-diff`. Delete the virtual environment and generated reports when no longer needed; no background process or application cache is created. Installation is from this repository or its release wheel; no PyPI publication is implied.

## What the report means

| Field | Set being compared |
|---|---|
| `newly_required` | New `host_permissions` minus old `host_permissions` |
| `no_longer_required` | Old required scope minus new required scope |
| `newly_requestable` | New required-or-optional scope minus old required-or-optional scope |
| `no_longer_requestable` | Old required-or-optional scope minus new required-or-optional scope |

Each item supplies a `within_pattern` and a `witness_url`. The URL belongs to the first set and not the second. **The entire containing pattern is not necessarily new or removed.** Reports provide representative counterexamples, not an enumeration of every URL in a difference. Overlapping declarations may produce multiple valid witnesses.

| Exit | Meaning |
|---|---|
| 0 | No expansion of the modeled required or requestable host sets. Removals may exist. |
| 1 | At least one modeled required or requestable host expansion. |
| 2 | Invalid/unsupported input, exceeded limit, CLI misuse or I/O failure. |

Reports also list `unmodeled_present_keys` and `unmodeled_changed_keys`. For example, changing `permissions: ["debugger"]` or `content_scripts` is explicitly listed but **does not change this host-only exit code**. Always inspect these fields or review them separately in your release process.

## Supported model

- Only Manifest V3 `host_permissions` and `optional_host_permissions`.
- HTTP, HTTPS and local `file` schemes. `*` expands to HTTP plus HTTPS. `<all_urls>` is projected onto HTTP, HTTPS and file only; any additional browser-supported schemes are outside this model.
- Exact ASCII/punycode DNS hosts, `localhost`, canonical IPv4, bracketed IPv6, `*`, and `*.example.test` (includes the apex and subdomains).
- Missing port and `:*` mean all ports. Explicit ports 1–65535 are compared individually and require an explicit HTTP or HTTPS scheme; split a `*` scheme into two declarations when using a numeric port.
- Host-permission paths are required but **ignored**, including file paths. These semantics must not be used for `content_scripts.matches`, where paths matter.
- DNS case and IPv6 text are normalized; duplicate declarations and rule ordering do not affect set comparison.

Inputs are UTF-8 JSON (BOM allowed), at most 1 MiB each, with nesting at most 64, at most 256 patterns in each host field, and at most 2,048 characters per pattern. Duplicate JSON keys, non-finite numbers and malformed fields are rejected. A minimal object with `manifest_version: 3` is accepted; this is not a complete extension-manifest validator.

Unsupported spellings fail with exit 2 rather than being silently skipped: other explicit schemes, Unicode hostnames (use ASCII/punycode), trailing dots, wildcard IPs, IPv6 zone IDs, noncanonical numeric IPs, wildcard suffixes with fewer than two labels, whitespace/control characters, and zero/leading-zero ports. DNS labels are bounded to 63 characters; hosts to 253, or 247 for wildcard suffixes to leave room for witness construction.

The model follows the documented concepts in [Chrome match patterns](https://developer.chrome.com/docs/extensions/develop/concepts/match-patterns) and [permission declarations](https://developer.chrome.com/docs/extensions/develop/concepts/declare-permissions). **Declared host scope is not effective installed access.** User approval, runtime-granted permissions, restricted sites, file access toggles, incognito behavior, content scripts, API capabilities and browser-specific versions are outside scope. It neither predicts Chrome's warning dialog nor decides whether an extension is trustworthy. Use the official [extension update testing workflow](https://developer.chrome.com/docs/extensions/develop/concepts/permission-warnings) to test actual browser behavior.

## Why semantic comparison

The parser's port restriction was also checked against Chromium's [URLPattern implementation](https://github.com/chromium/chromium/blob/main/extensions/common/url_pattern.cc). The forced all-path host behavior was checked against its [host-permission parser](https://github.com/chromium/chromium/blob/main/extensions/common/manifest_handlers/permissions_parser.cc). These are reference sources; this package contains its own implementation.

The algorithm splits schemes, compares host-pattern containment, and checks relevant port classes. For one scheme and port, a finite union of exact hosts and narrower suffixes cannot cover a broader suffix; a fresh subdomain supplies a witness. All-host witnesses use documentation IPv6 addresses. Results contain no fetched website content. Hostnames and unmodeled field names from your manifests are intentionally present in reports.

[Extension Permission Diff Lab](https://github.com/lxiaonan/extension-permission-diff-lab-day32) offers an interactive review interface covering more manifest surfaces. This project focuses on semantic host-set containment and machine-readable counterexamples suitable for local release checks. It provides no generic risk score.

## Development

```sh
python -m pip install -e . build ruff coverage
python -m unittest discover -s tests -v
ruff check src tests
ruff format --check src tests
python -m build
```

Tests cover optional-to-required transitions, scheme unions, suffix boundaries, ports, IPv6, file access, strict input limits, non-echoing errors and CLI writes. Seeded comparisons use an independent regex oracle over a representative URL domain, and verify every emitted addition witness. CI runs Python 3.10 and 3.13 on Linux/Windows, and 3.13 on macOS. MIT license; no third-party implementation code is bundled.

## 中文说明

离线比较两个 Chrome Manifest V3 文件声明的主机授权范围，给出能证明范围扩大的具体 URL。能识别 HTTP/HTTPS 规则合并、子域范围、端口以及“可选授权变为必需授权”，不只比较文本差异。

只分析 `host_permissions` 与 `optional_host_permissions` 的 HTTP、HTTPS 和本地 file 范围。内容脚本、API 权限等未建模字段会列出变更，但不影响本工具的主机范围退出码。它不是扩展安全评分器，也不能代替真实浏览器的权限更新测试。
