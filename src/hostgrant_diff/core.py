"""Compare declared host-grant sets without loading an extension or contacting any URL."""

import ipaddress
import json
import math
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

MAX_BYTES = 1024 * 1024
MAX_PATTERNS = 256
SCHEMES = ("http", "https", "file")
FIELDS = ("host_permissions", "optional_host_permissions")
METADATA = {
    "manifest_version",
    "name",
    "short_name",
    "version",
    "version_name",
    "description",
    "icons",
    "author",
    "homepage_url",
}


class InputError(ValueError):
    """Invalid or unsupported input, with no input value in the message."""


@dataclass(frozen=True)
class Grant:
    scheme: str
    host: str
    subdomains: bool = False
    port: int | None = None

    @property
    def pattern(self):
        if self.scheme == "file":
            return "file:///*"
        host = "*." + self.host if self.subdomains else self.host
        port = "" if self.port is None else ":" + str(self.port)
        return f"{self.scheme}://{host}{port}/*"

    def matches_host(self, host):
        return (
            self.host == "*"
            or self.host == host
            or (self.subdomains and host.endswith("." + self.host))
        )


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("duplicate JSON member")
        result[key] = value
    return result


def _constant(_):
    raise InputError("non-finite JSON number")


def _float(value):
    number = float(value)
    if not math.isfinite(number):
        raise InputError("non-finite JSON number")
    return number


def load_manifest(data: bytes) -> dict:
    if len(data) > MAX_BYTES:
        raise InputError("manifest exceeds 1 MiB")
    depth = 0
    quoted = escaped = False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 64:
                raise InputError("JSON nesting exceeds 64 levels")
        elif byte in (93, 125):
            depth -= 1
    try:
        result = json.loads(
            data.decode("utf-8-sig"),
            object_pairs_hook=_pairs,
            parse_constant=_constant,
            parse_float=_float,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, InputError):
            raise
        raise InputError("invalid UTF-8 JSON") from None
    if not isinstance(result, dict):
        raise InputError("manifest must be a JSON object")
    return result


def _port(value):
    if value == "*":
        return None
    if not re.fullmatch(r"[1-9][0-9]{0,4}", value) or int(value) > 65535:
        raise InputError("unsupported port; use 1..65535 or *")
    return int(value)


def _host(value):
    if not value.isascii():
        raise InputError("use bounded ASCII or punycode hosts")
    value = value.lower()
    if value == "*":
        return value, False
    subdomains = value.startswith("*.")
    host = value[2:] if subdomains else value
    if host.startswith("[") and host.endswith("]") and not subdomains:
        if "%" in host:
            raise InputError("IPv6 zone identifiers are unsupported")
        try:
            return f"[{ipaddress.IPv6Address(host[1:-1]).compressed}]", False
        except ValueError:
            raise InputError("invalid IPv6 host") from None
    try:
        address = ipaddress.IPv4Address(host)
    except ValueError:
        address = None
    if address is not None:
        if subdomains:
            raise InputError("wildcards on IP addresses are unsupported")
        return str(address), False
    # Reject noncanonical numeric IP spellings instead of guessing browser normalization.
    last_label = host.rsplit(".", 1)[-1]
    if last_label.isdigit() or re.fullmatch(r"0x[0-9a-f]+", last_label):
        raise InputError("noncanonical numeric host is unsupported")
    if not host.isascii() or len(host) > (247 if subdomains else 253):
        raise InputError("use bounded ASCII or punycode hosts")
    labels = host.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        raise InputError("unsupported hostname spelling")
    if subdomains and len(labels) < 2:
        raise InputError("wildcard suffix must have at least two labels")
    return host, subdomains


def parse_pattern(value: str) -> tuple[Grant, ...]:
    """Expand a supported pattern into single-scheme grants; host paths are ignored."""
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise InputError("host patterns must be strings of at most 2048 characters")
    if any(ord(char) < 33 or ord(char) == 127 for char in value):
        raise InputError("whitespace/control characters in pattern")
    if value == "<all_urls>":
        return (Grant("http", "*"), Grant("https", "*"), Grant("file", ""))
    scheme, separator, rest = value.partition("://")
    if not separator or scheme not in (*SCHEMES, "*"):
        raise InputError("unsupported scheme; model covers http, https and file")
    authority, slash, _path = rest.partition("/")
    if not slash:
        raise InputError("host pattern requires a path")
    if scheme == "file":
        if authority:
            raise InputError("file patterns must have an empty host")
        return (Grant("file", ""),)
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            raise InputError("invalid IPv6 authority")
        host_text = authority[: end + 1]
        tail = authority[end + 1 :]
        if tail and not tail.startswith(":"):
            raise InputError("invalid IPv6 authority suffix")
        port = _port(tail[1:]) if tail else None
    else:
        if authority.count(":") > 1:
            raise InputError("IPv6 addresses must be bracketed")
        host_text, colon, port_text = authority.partition(":")
        port = _port(port_text) if colon else None
    host, subdomains = _host(host_text)
    if scheme == "*" and port is not None:
        raise InputError("explicit ports require an explicit http or https scheme")
    schemes = ("http", "https") if scheme == "*" else (scheme,)
    return tuple(Grant(s, host, subdomains, port) for s in schemes)


def _grants(manifest):
    if (
        not isinstance(manifest, dict)
        or type(manifest.get("manifest_version")) is not int
        or manifest["manifest_version"] != 3
    ):
        raise InputError("only Manifest V3 objects are supported")
    result = []
    for field in FIELDS:
        patterns = manifest.get(field, [])
        if not isinstance(patterns, list) or len(patterns) > MAX_PATTERNS:
            raise InputError("each host-permission field must have at most 256 patterns")
        atoms = set()
        for pattern in patterns:
            atoms.update(parse_pattern(pattern))
        result.append(tuple(sorted(atoms, key=lambda a: a.pattern)))
    return tuple(result)


def _contains_host(cover: Grant, target: Grant):
    if cover.host == "*":
        return True
    if target.host == "*":
        return False
    if cover.subdomains:
        return cover.matches_host(target.host)
    return not target.subdomains and cover.host == target.host


def _fresh_host(target, covers):
    """Construct a host in target but outside a finite union of proper host subsets."""
    if target.host != "*" and not target.subdomains:
        return target.host
    if target.subdomains:
        if not any(g.matches_host(target.host) for g in covers):
            return target.host
        for i in range(len(covers) + 1):
            candidate = f"w{i}.{target.host}"
            if not any(g.matches_host(candidate) for g in covers):
                return candidate
    else:
        # Documentation-only IPv6 addresses avoid real service URLs and DNS lookups.
        for i in range(1, len(covers) + 2):
            candidate = f"[{ipaddress.IPv6Address(int(ipaddress.IPv6Address('2001:db8::')) + i).compressed}]"
            if not any(g.matches_host(candidate) for g in covers):
                return candidate
    raise AssertionError("finite host union unexpectedly exhausted witness candidates")


def _difference_witness(target: Grant, baseline):
    relevant = [g for g in baseline if g.scheme == target.scheme]
    if target.scheme == "file":
        return None if relevant else "file:///hostgrant-diff-witness"
    if any(g.port is None and _contains_host(g, target) for g in relevant):
        return None
    if target.port is not None:
        ports = [target.port]
    else:
        explicit = {g.port for g in relevant if g.port is not None}
        default = 443 if target.scheme == "https" else 80
        fresh = next(p for p in range(1, 65536) if p not in explicit)
        # Any unlisted port is covered only by any-port grants. If those do not
        # cover this host set, that port necessarily supplies a difference.
        ports = [default] if default == fresh else [default, fresh]
    for port in ports:
        covers = [g for g in relevant if g.port is None or g.port == port]
        if any(_contains_host(g, target) for g in covers):
            continue
        host = _fresh_host(target, covers)
        default = 443 if target.scheme == "https" else 80
        suffix = "" if port == default else f":{port}"
        return f"{target.scheme}://{host}{suffix}/"
    return None


def matches_url(grants, url):
    """Test a concrete HTTP/HTTPS/file witness against parsed grants; no I/O."""
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme not in SCHEMES
            or parsed.username is not None
            or parsed.password is not None
        ):
            return False
        if parsed.scheme == "file":
            return not parsed.netloc and any(g.scheme == "file" for g in grants)
        if not parsed.hostname:
            return False
        host = parsed.hostname.lower()
        if ":" in host:
            host = f"[{ipaddress.IPv6Address(host).compressed}]"
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        return any(
            g.scheme == parsed.scheme
            and (g.port is None or g.port == port)
            and g.matches_host(host)
            for g in grants
        )
    except ValueError:
        return False


def _gaps(target, baseline):
    result = []
    for grant in sorted(set(target), key=lambda g: g.pattern):
        witness = _difference_witness(grant, baseline)
        if witness is not None:
            # Guard the central evidence invariant even if the containment code changes.
            if not matches_url([grant], witness) or matches_url(baseline, witness):
                raise AssertionError("invalid difference witness")
            result.append({"within_pattern": grant.pattern, "witness_url": witness})
    return result


def compare(before: dict, after: dict) -> dict:
    """Compare required and total requestable declared host sets within the documented model."""
    old_required, old_optional = _grants(before)
    new_required, new_optional = _grants(after)
    old_total = tuple(set(old_required + old_optional))
    new_total = tuple(set(new_required + new_optional))
    newly_required = _gaps(new_required, old_required)
    for item in newly_required:
        item["previously_requestable"] = matches_url(old_total, item["witness_url"])
    requestable = _gaps(new_total, old_total)
    ignored_changes = sorted(
        key
        for key in set(before) | set(after)
        if key not in FIELDS
        and key not in METADATA
        and (key not in before or key not in after or before[key] != after[key])
    )
    ignored_present = sorted(
        key for key in set(before) | set(after) if key not in FIELDS and key not in METADATA
    )
    return {
        "schema": "hostgrant-diff/v1",
        "status": "host-expansion" if newly_required or requestable else "no-host-expansion",
        "scope": "declared-mv3-http-https-file-host-grants",
        "newly_required": newly_required,
        "no_longer_required": _gaps(old_required, new_required),
        "newly_requestable": requestable,
        "no_longer_requestable": _gaps(old_total, new_total),
        "unmodeled_changed_keys": ignored_changes,
        "unmodeled_present_keys": ignored_present,
        "limitations": [
            "Only HTTP, HTTPS and file host_permissions/optional_host_permissions are modeled.",
            "all_urls is projected onto those three schemes; other schemes are outside scope.",
            "Host-permission paths are ignored. Content-script paths and API grants are not analyzed.",
            "Declared scope is not installed access, browser warning behavior or a security verdict.",
            "Each URL witnesses one difference; its containing pattern is not wholly new access.",
        ],
    }
