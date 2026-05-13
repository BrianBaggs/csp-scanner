#!/usr/bin/env python3
# =============================================================================
#  Content Security Policy (CSP) Scanner v2.0
#  Fetches and analyzes the Content-Security-Policy header of a target URL,
#  flags misconfigurations and weaknesses by severity, and generates a rich
#  self-contained HTML report alongside JSON and plain-text outputs.
#
#  Checks performed:
#    Critical  — Missing CSP, wildcard script-src/default-src,
#                report-only with no enforcement
#    High      — unsafe-inline/eval in scripts, missing object-src/base-uri,
#                missing frame-ancestors, data:/blob:/http:/https: in
#                script-src, CDN/JSONP bypass domains, static/predictable nonce
#    Medium    — unsafe-inline in styles, unsafe-hashes, missing form-action,
#                broad wildcards, strict-dynamic without nonce/hash,
#                connect-src unrestricted, worker-src missing
#    Low       — Deprecated directives, no violation reporting, deprecated
#                headers, missing default-src fallback, navigate-to deprecated
#    Info      — Report-only mode, nonce/hash presence, upgrade-insecure-
#                requests, sandbox, trusted-types, wasm-unsafe-eval,
#                X-Frame-Options note
#
#  References:
#    - MDN CSP Guide        https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP
#    - MDN CSP Header       https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy
#    - OWASP CSP Cheat Sheet https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
#    - content-security-policy.com https://content-security-policy.com/
#    - Google CSP Evaluator  https://csp-evaluator.withgoogle.com/
#    - CSP Is Dead, Long Live CSP! (Weichselbaum et al., 2016)
#
#  Output:
#    Rich CLI summary + HTML, JSON, and plain-text reports saved to:
#      results/csp-scan_<host>_<timestamp>/report.html   ← NEW
#      results/csp-scan_<host>_<timestamp>/report.txt
#      results/csp-scan_<host>_<timestamp>/findings.json
#
#  Python 3 stdlib only — no pip dependencies required.
#  Authorized testing only.
# =============================================================================

import argparse
import html as html_lib
import json
import os
import re
import ssl
import sys
import textwrap
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

VERSION = "2.0.0"
TIMEOUT = 15

# ── Colors ────────────────────────────────────────────────────────────────────
class Colors:
    _tty = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    R    = "\033[0;31m"  if _tty else ""   # red
    G    = "\033[0;32m"  if _tty else ""   # green
    Y    = "\033[1;33m"  if _tty else ""   # yellow
    B    = "\033[0;34m"  if _tty else ""   # blue
    C    = "\033[0;36m"  if _tty else ""   # cyan
    M    = "\033[0;35m"  if _tty else ""   # magenta
    W    = "\033[1;37m"  if _tty else ""   # bold white
    D    = "\033[0;90m"  if _tty else ""   # dark grey
    NC   = "\033[0m"     if _tty else ""   # reset
    BOLD = "\033[1m"     if _tty else ""
    DIM  = "\033[2m"     if _tty else ""

CO = Colors

SCOLORS = {
    "CRITICAL": CO.R + CO.BOLD,
    "HIGH":     CO.R,
    "MEDIUM":   CO.Y,
    "LOW":      CO.B,
    "INFO":     CO.C,
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# ── Known CDN / JSONP bypass domains ─────────────────────────────────────────
# These domains are in widely-used allowlists but host endpoints that can be
# used to execute arbitrary JavaScript via JSONP callbacks, Angular payloads,
# or direct file hosting — effectively bypassing CSP script-src restrictions.
CDN_BYPASS_DOMAINS = {
    "ajax.googleapis.com":           "JSONP endpoint (Angular/jQuery bypass)",
    "*.googleapis.com":              "Broad Google APIs wildcard — JSONP bypasses possible",
    "accounts.google.com":           "JSONP bypass via accounts.google.com/o/oauth2/revoke",
    "www.googleapis.com":            "JSONP endpoint bypass",
    "maps.googleapis.com":           "JSONP endpoint bypass",
    "storage.googleapis.com":        "User-uploaded file serving (arbitrary JS possible)",
    "cdnjs.cloudflare.com":          "Serves user-specified library versions (arbitrary JS)",
    "cdn.jsdelivr.net":              "Serves arbitrary npm packages and GitHub content (arbitrary JS)",
    "unpkg.com":                     "Serves arbitrary npm packages (arbitrary JS)",
    "rawgit.com":                    "Serves raw GitHub files (arbitrary JS) — now defunct but may still be allowed",
    "raw.githubusercontent.com":     "Serves raw GitHub file content (arbitrary JS)",
    "*.github.io":                   "User-controlled GitHub Pages (arbitrary JS)",
    "gist.github.com":               "User-controlled Gist content (arbitrary JS)",
    "code.jquery.com":               "Serves many jQuery versions; older versions have known XSS",
    "stackpath.bootstrapcdn.com":    "Angular CDN — JSONP and Angular template bypass",
    "maxcdn.bootstrapcdn.com":       "Angular CDN — template injection bypass",
    "yastatic.net":                  "JSONP bypass via Yandex static CDN",
    "*.yandex.ru":                   "Broad Yandex wildcard — JSONP bypass possible",
    "mc.yandex.ru":                  "JSONP bypass via Yandex Metrica",
    "translate.google.com":          "JSONP bypass",
    "translate.googleapis.com":      "JSONP bypass via translate endpoint",
    "*.cloudfront.net":              "User-controlled CloudFront distribution (arbitrary JS possible)",
    "*.s3.amazonaws.com":            "User-controlled S3 bucket (arbitrary JS possible)",
    "*.blob.core.windows.net":       "User-controlled Azure Blob Storage (arbitrary JS possible)",
    "*.staticflickr.com":            "User-uploaded Flickr content (arbitrary JS possible)",
    "*.twimg.com":                   "Twitter CDN — some paths allow user content",
    "amd.cloudflare.com":            "AMD/Cloudflare JSONP endpoint bypass",
    "angular.io":                    "Angular template injection bypass via documentation site",
    "*.angularjs.org":               "Angular CDN with template injection bypass",
    "requirejs.org":                 "Hosts RequireJS; arbitrary module loading bypass",
    "semver.io":                     "JSONP endpoint bypass",
}


# ── Parsing helpers ───────────────────────────────────────────────────────────
def parse_csp(raw_csp: str) -> dict[str, list[str]]:
    """Parse a CSP string into a dict of {directive: [values]}."""
    directives: dict[str, list[str]] = {}
    for part in raw_csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        name = tokens[0].lower()
        values = [v.lower() for v in tokens[1:]]
        directives[name] = values
    return directives


def effective_script_src(directives: dict[str, list[str]]) -> list[str] | None:
    """
    Return the effective source list for scripts:
    script-src > default-src (per CSP fallback rules).
    Returns None if neither directive is set.
    """
    return directives.get("script-src") or directives.get("default-src")


def effective_style_src(directives: dict[str, list[str]]) -> list[str] | None:
    return directives.get("style-src") or directives.get("default-src")


def effective_connect_src(directives: dict[str, list[str]]) -> list[str] | None:
    """connect-src falls back to default-src."""
    return directives.get("connect-src") or directives.get("default-src")


def effective_worker_src(directives: dict[str, list[str]]) -> list[str] | None:
    """worker-src falls back to child-src, then default-src."""
    return (directives.get("worker-src")
            or directives.get("child-src")
            or directives.get("default-src"))


def has_wildcard(values: list[str]) -> bool:
    return "*" in values


def has_unsafe_inline(values: list[str]) -> bool:
    return "'unsafe-inline'" in values


def has_unsafe_eval(values: list[str]) -> bool:
    return "'unsafe-eval'" in values


def has_nonce(values: list[str]) -> bool:
    return any(v.startswith("'nonce-") for v in values)


def has_hash(values: list[str]) -> bool:
    return any(
        v.startswith(("'sha256-", "'sha384-", "'sha512-"))
        for v in values
    )


def is_static_nonce(values: list[str]) -> tuple[bool, str]:
    """
    Heuristic: detect if a nonce looks static or predictable.
    Returns (is_static, nonce_value). A proper nonce must be ≥128-bit random,
    usually 22+ base64 characters.
    """
    for v in values:
        if v.startswith("'nonce-"):
            nonce_val = v[7:].rstrip("'")
            # Too short to be cryptographically random
            if len(nonce_val) < 16:
                return True, nonce_val
            # Looks like a dictionary word or sequential token
            if re.match(r"^[a-z]{2,}[0-9]{0,4}$", nonce_val, re.IGNORECASE):
                return True, nonce_val
            # Common static placeholder values
            if nonce_val.lower() in ("random", "nonce", "placeholder", "abc123",
                                     "changeme", "secret", "token", "1234567890"):
                return True, nonce_val
    return False, ""


def host_matches_bypass(host_value: str, bypass_domain: str) -> bool:
    """Return True if host_value matches a known bypass domain pattern."""
    if bypass_domain.startswith("*."):
        suffix = bypass_domain[1:]  # e.g., ".googleapis.com"
        return host_value == bypass_domain or host_value.endswith(suffix)
    return host_value == bypass_domain


def extract_host_sources(values: list[str]) -> list[str]:
    """Return values that look like host sources (not keywords like 'self')."""
    keyword_prefixes = ("'", "data:", "blob:", "mediastream:", "filesystem:")
    result = []
    for v in values:
        if not any(v.startswith(p) for p in keyword_prefixes) and v not in ("*", "http:", "https:", "ws:", "wss:"):
            result.append(v)
    return result


# ── Finding class ─────────────────────────────────────────────────────────────
class Finding:
    def __init__(self, severity: str, directive: str, title: str, detail: str,
                 recommendation: str):
        self.severity = severity
        self.directive = directive
        self.title = title
        self.detail = detail
        self.recommendation = recommendation

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "directive": self.directive,
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
        }


# ── Analysis engine ───────────────────────────────────────────────────────────
def analyze_csp(directives: dict[str, list[str]], is_report_only: bool,
                response_headers: dict[str, str] | None = None) -> list["Finding"]:
    findings: list[Finding] = []
    response_headers = response_headers or {}

    def add(severity, directive, title, detail, recommendation):
        findings.append(Finding(severity, directive, title, detail, recommendation))

    # ── CRITICAL ──────────────────────────────────────────────────────────────

    if is_report_only and not directives:
        add("CRITICAL", "N/A",
            "CSP header present only in report-only mode (no enforcement)",
            "The server responds with Content-Security-Policy-Report-Only but no "
            "enforcing Content-Security-Policy header. Violations are logged but "
            "the policy is never enforced, providing no actual protection.",
            "Deploy a Content-Security-Policy header (enforcing mode) alongside "
            "or instead of the report-only header.")

    # Wildcard default-src
    default_src = directives.get("default-src", [])
    if "*" in default_src:
        add("CRITICAL", "default-src",
            "Wildcard (*) in default-src — all resource types unrestricted",
            "default-src * allows loading any resource from any origin. This "
            "effectively disables the protection offered by CSP.",
            "Replace * with explicit trusted origins. Start with 'self' and "
            "add only required external sources.")

    # Wildcard script-src
    script_src = directives.get("script-src", [])
    if "*" in script_src:
        add("CRITICAL", "script-src",
            "Wildcard (*) in script-src — arbitrary JavaScript execution allowed",
            "script-src * permits loading scripts from any origin, giving "
            "an attacker complete freedom to inject and execute JavaScript.",
            "Replace * with specific trusted script origins. Use nonces or "
            "hashes for a strict CSP.")

    # ── HIGH ──────────────────────────────────────────────────────────────────

    effective_script = effective_script_src(directives)

    # unsafe-inline in script context
    if effective_script and has_unsafe_inline(effective_script):
        # Only flag if no nonce/hash (browsers ignore unsafe-inline when nonce/hash present)
        if not (has_nonce(effective_script) or has_hash(effective_script)):
            directive_name = "script-src" if "script-src" in directives else "default-src"
            add("HIGH", directive_name,
                "'unsafe-inline' in script source — inline JavaScript allowed",
                f"The {directive_name} directive contains 'unsafe-inline'. This "
                "permits all inline <script> blocks, inline event handlers, and "
                "javascript: URLs — the most common XSS injection vectors. "
                "The protection CSP is meant to provide is largely negated.",
                "Remove 'unsafe-inline'. Use nonces ('nonce-<random>') or hashes "
                "('sha256-...') for any required inline scripts instead.")

    # unsafe-eval in script context
    if effective_script and has_unsafe_eval(effective_script):
        directive_name = "script-src" if "script-src" in directives else "default-src"
        add("HIGH", directive_name,
            "'unsafe-eval' in script source — eval() and dynamic code execution allowed",
            f"'unsafe-eval' in {directive_name} permits eval(), new Function(), "
            "setTimeout(string), and setInterval(string). These are prime targets "
            "for XSS exploitation because they evaluate arbitrary strings as JavaScript.",
            "Remove 'unsafe-eval'. Refactor code to avoid eval() and similar APIs. "
            "If WebAssembly is required, use 'wasm-unsafe-eval' instead.")

    # data: in script-src
    if effective_script and "data:" in effective_script:
        directive_name = "script-src" if "script-src" in directives else "default-src"
        add("HIGH", directive_name,
            "'data:' URI scheme in script source — base64-encoded script injection possible",
            "Allowing data: in script sources permits attackers to inject and execute "
            "base64-encoded JavaScript via <script src='data:text/javascript,...'> tags.",
            "Remove 'data:' from the script source list. There is almost never a "
            "legitimate need to load scripts from data URIs.")

    # http: scheme in script-src
    if effective_script and "http:" in effective_script:
        directive_name = "script-src" if "script-src" in directives else "default-src"
        add("HIGH", directive_name,
            "'http:' scheme in script source — scripts from any HTTP host permitted",
            "Allowing http: in script sources permits loading scripts from any HTTP "
            "origin, including attacker-controlled infrastructure. It also exposes "
            "scripts to network interception (MitM) because they are unencrypted.",
            "Remove 'http:'. Use 'https:' if a scheme-based policy is required, "
            "or enumerate specific trusted hosts.")

    # blob: in script-src — XSS via blob URL
    if effective_script and "blob:" in effective_script:
        directive_name = "script-src" if "script-src" in directives else "default-src"
        add("HIGH", directive_name,
            "'blob:' URI scheme in script source — blob URL script execution possible",
            "Allowing blob: in script-src permits executing scripts loaded from Blob "
            "object URLs. An attacker who can inject JavaScript (e.g., via XSS) can "
            "create a Blob containing malicious code and execute it as a script via "
            "a generated blob: URL, bypassing most content restrictions.",
            "Remove 'blob:' from script-src. If Web Workers require it, scope it "
            "to worker-src 'blob:' only rather than the full script-src.")

    # https: scheme in script-src — loads from any HTTPS host
    if effective_script and "https:" in effective_script:
        directive_name = "script-src" if "script-src" in directives else "default-src"
        add("HIGH", directive_name,
            "'https:' scheme in script source — scripts from any HTTPS origin permitted",
            "Allowing the bare 'https:' scheme in script-src is nearly equivalent to "
            "a wildcard (*). Any HTTPS host — including attacker-controlled domains — "
            "may serve scripts that the browser will execute. This defeats the purpose "
            "of restricting script origins and was highlighted in the landmark "
            "'CSP Is Dead, Long Live CSP' paper as a common allowlist bypass.",
            "Replace 'https:' with explicit trusted host origins. Switch to a strict "
            "nonce- or hash-based policy for the strongest protection.")

    # Static/predictable nonce detection
    if effective_script and has_nonce(effective_script):
        static, nonce_val = is_static_nonce(effective_script)
        if static:
            directive_name = "script-src" if "script-src" in directives else "default-src"
            add("HIGH", directive_name,
                f"Nonce appears static or predictable: '{nonce_val}'",
                "A nonce must be cryptographically random and unique per HTTP response "
                "to be effective. A static or predictable nonce can be guessed by an "
                "attacker who has observed any previous response, allowing them to "
                "inject a <script nonce='...'> tag with the known value and execute "
                "arbitrary JavaScript, completely bypassing the CSP.",
                "Generate the nonce server-side using a CSPRNG (e.g., "
                "crypto.randomUUID(), os.urandom(16)) for every HTTP response. "
                "The nonce should be at least 128 bits (22+ base64 characters) "
                "and must never be reused.")

    # object-src not locked down
    obj_src = directives.get("object-src")
    if obj_src is None:
        # Falls back to default-src
        if not default_src or "*" in default_src or (
            default_src and "'none'" not in default_src
        ):
            add("HIGH", "object-src",
                "object-src not defined — plugin/object elements unrestricted",
                "Without object-src (or a restrictive default-src), <object> and "
                "<embed> elements can load plugins from any origin. Legacy Flash and "
                "Java plugins can be leveraged to bypass CSP and execute arbitrary code.",
                "Add 'object-src 'none';' to the policy. Plugins are obsolete and "
                "should be blocked outright.")
    elif "'none'" not in obj_src and "*" in obj_src:
        add("HIGH", "object-src",
            "Wildcard (*) in object-src — plugin/object elements unrestricted",
            "object-src * permits loading arbitrary plugins from any origin.",
            "Change object-src to 'none'. Plugin support is obsolete.")

    # base-uri
    base_uri = directives.get("base-uri")
    if base_uri is None:
        add("HIGH", "base-uri",
            "base-uri not defined — base tag injection possible",
            "Without base-uri, an attacker who can inject a <base href='...'> element "
            "can redirect all relative URLs in the page to an attacker-controlled "
            "origin, bypassing CSP restrictions on relative-URL script/resource loads.",
            "Add 'base-uri 'none';' or 'base-uri 'self';' to the policy.")
    elif "'none'" not in base_uri and "'self'" not in base_uri and "*" in base_uri:
        add("HIGH", "base-uri",
            "Wildcard (*) in base-uri — base tag can point to any origin",
            "base-uri * allows an attacker to inject a <base> element pointing to "
            "any origin, redirecting relative resource loads.",
            "Restrict base-uri to 'none' or 'self'.")

    # frame-ancestors
    frame_ancestors = directives.get("frame-ancestors")
    if frame_ancestors is None:
        add("HIGH", "frame-ancestors",
            "frame-ancestors not defined — clickjacking risk",
            "Without frame-ancestors, any site can embed this page inside an <iframe> "
            "or <frame>. This enables clickjacking attacks where the attacker overlays "
            "the page and tricks users into clicking sensitive UI elements.",
            "Add 'frame-ancestors 'none';' if the page should not be embedded, "
            "or 'frame-ancestors 'self';' to allow same-origin embedding only.")

    # CDN / JSONP bypass domains in script-src
    if effective_script:
        host_sources = extract_host_sources(effective_script)
        for host in host_sources:
            # Strip scheme prefix for matching
            clean = re.sub(r"^https?://", "", host)
            for bypass_domain, reason in CDN_BYPASS_DOMAINS.items():
                if host_matches_bypass(clean, bypass_domain):
                    directive_name = "script-src" if "script-src" in directives else "default-src"
                    add("HIGH", directive_name,
                        f"Known CSP bypass domain in script-src: {clean}",
                        f"The domain '{clean}' is in the script-src allowlist. "
                        f"This domain is known to host or serve endpoints that allow "
                        f"attackers to bypass CSP restrictions: {reason}. "
                        f"An attacker can load arbitrary JavaScript from this origin.",
                        f"Remove '{clean}' from the allowlist. If this CDN is required, "
                        f"use a strict nonce- or hash-based policy instead, which makes "
                        f"allowlist domains irrelevant.")

    # ── MEDIUM ────────────────────────────────────────────────────────────────

    # unsafe-inline in style-src
    effective_style = effective_style_src(directives)
    if effective_style and has_unsafe_inline(effective_style):
        if not has_nonce(effective_style) and not has_hash(effective_style):
            directive_name = "style-src" if "style-src" in directives else "default-src"
            add("MEDIUM", directive_name,
                "'unsafe-inline' in style source — CSS injection possible",
                f"'unsafe-inline' in {directive_name} permits inline <style> blocks and "
                "style= attributes. Attackers can exploit this to exfiltrate data via "
                "CSS attribute selectors (e.g., input[value^='a']{background:url(...)}) "
                "or to conduct UI redressing attacks.",
                "Remove 'unsafe-inline' from style-src. Use nonces, hashes, or move "
                "styles to external stylesheets.")

    # unsafe-hashes in script-src
    if effective_script and "'unsafe-hashes'" in effective_script:
        directive_name = "script-src" if "script-src" in directives else "default-src"
        add("MEDIUM", directive_name,
            "'unsafe-hashes' in script source — inline event handler bypass risk",
            "'unsafe-hashes' allows hash expressions to apply to inline event handlers "
            "(onclick=, onerror=, etc.). An attacker who can inject the hashed code "
            "inside a <script> tag will have it executed automatically, bypassing "
            "the protection hashes are supposed to provide.",
            "Avoid 'unsafe-hashes'. Migrate inline event handlers to addEventListener() "
            "calls in external or nonce/hash-protected scripts.")

    # form-action not set
    form_action = directives.get("form-action")
    if form_action is None:
        add("MEDIUM", "form-action",
            "form-action not defined — HTML form submission target unrestricted",
            "Without form-action, HTML forms on this page can submit data to any URL. "
            "An attacker who injects a phishing form can exfiltrate credentials or "
            "sensitive input values to an external server. Note: form-action does not "
            "fall back to default-src.",
            "Add 'form-action 'self';' or enumerate trusted submission endpoints.")

    # Broad wildcards (*.example.com) in script-src
    if effective_script:
        for v in effective_script:
            clean = re.sub(r"^https?://", "", v)
            if clean.startswith("*.") and clean not in CDN_BYPASS_DOMAINS:
                directive_name = "script-src" if "script-src" in directives else "default-src"
                add("MEDIUM", directive_name,
                    f"Subdomain wildcard in script-src: {clean}",
                    f"The wildcard '{clean}' in script-src allows loading scripts from "
                    f"any subdomain of {clean[2:]}. If any subdomain is compromised or "
                    f"allows user-controlled content, an attacker can host and load "
                    f"arbitrary scripts from that subdomain.",
                    f"Replace '{clean}' with specific subdomains that are actually "
                    f"required, e.g., 'cdn.{clean[2:]}'.")

    # strict-dynamic present but no nonce or hash (makes it a no-op)
    if effective_script and "'strict-dynamic'" in effective_script:
        if not has_nonce(effective_script) and not has_hash(effective_script):
            directive_name = "script-src" if "script-src" in directives else "default-src"
            add("MEDIUM", directive_name,
                "'strict-dynamic' present without a nonce or hash — directive has no effect",
                "'strict-dynamic' is only meaningful when used with a nonce or hash. "
                "Without one, 'strict-dynamic' is silently ignored by the browser, "
                "providing no additional protection while giving a false sense of security.",
                "Pair 'strict-dynamic' with a nonce ('nonce-<random>') or a hash "
                "('sha256-...') for it to take effect.")

    # script-src missing entirely with a permissive default-src
    if "script-src" not in directives:
        if default_src and "'none'" not in default_src and "*" not in default_src:
            add("MEDIUM", "script-src",
                "script-src not explicitly defined — falling back to default-src",
                "The script-src directive is not set. Browsers fall back to default-src "
                "for JavaScript controls. If default-src is loosened in the future, "
                "scripts will immediately become less restricted without an obvious "
                "indication. An explicit script-src is always recommended.",
                "Define an explicit script-src directive rather than relying on "
                "default-src as a fallback for scripts.")

    # connect-src wildcard or unrestricted
    eff_connect = effective_connect_src(directives)
    if eff_connect is None or "*" in eff_connect or "https:" in eff_connect or "http:" in eff_connect:
        if "connect-src" not in directives or "*" in (directives.get("connect-src") or []):
            add("MEDIUM", "connect-src",
                "connect-src not restricted — XHR/fetch/WebSocket allowed to any origin",
                "The connect-src directive controls which URLs can be contacted via "
                "XMLHttpRequest, fetch(), WebSocket, EventSource, and the Beacon API. "
                "Without restriction, malicious code can exfiltrate sensitive data "
                "(cookies, tokens, PII) to any external server, and can be used as a "
                "command-and-control channel for XSS payloads. Note: connect-src does "
                "not fall back to default-src in all directive positions.",
                "Add 'connect-src 'self';' and enumerate only the API endpoints your "
                "application legitimately calls. Block all other outbound connections.")

    # worker-src missing — ServiceWorker / Web Worker CSP bypass
    eff_worker = effective_worker_src(directives)
    if "worker-src" not in directives:
        if eff_worker is None or "*" in eff_worker or "https:" in eff_worker:
            add("MEDIUM", "worker-src",
                "worker-src not explicitly defined — Web Worker/ServiceWorker scripts unrestricted",
                "Without worker-src, Web Worker and ServiceWorker script sources fall "
                "back to child-src and then default-src. ServiceWorkers are particularly "
                "dangerous: a ServiceWorker registered from an allowed source can "
                "intercept all network requests, modify responses, and persist across "
                "page navigations — providing a persistent XSS foothold even after "
                "the initial injection point is fixed.",
                "Add 'worker-src 'self';' to restrict Worker and ServiceWorker scripts "
                "to same-origin only. If no workers are used, set 'worker-src 'none';'.")

    # ── LOW ───────────────────────────────────────────────────────────────────

    # No violation reporting endpoint
    has_report_to  = "report-to"  in directives
    has_report_uri = "report-uri" in directives
    if not has_report_to and not has_report_uri:
        add("LOW", "report-to / report-uri",
            "No violation reporting endpoint configured",
            "Neither report-to nor report-uri is set in the CSP. CSP violations will "
            "be silently ignored and no telemetry will be generated. This makes it "
            "impossible to detect active attacks or policy violations in production.",
            "Add 'report-to <endpoint-name>;' and configure a Reporting-Endpoints "
            "header. Include 'report-uri <url>;' for backward compatibility with "
            "older browsers.")

    # report-uri without report-to (deprecated)
    if has_report_uri and not has_report_to:
        add("LOW", "report-uri",
            "Deprecated report-uri used without the newer report-to directive",
            "The report-uri directive is deprecated in CSP Level 3 and may be removed "
            "in future browser versions. The replacement is report-to, which uses the "
            "Reporting API and supports endpoint groups.",
            "Add a report-to directive and define the endpoint in a Reporting-Endpoints "
            "response header. Keep report-uri for backward compatibility until report-to "
            "is universally supported.")

    # block-all-mixed-content (deprecated)
    if "block-all-mixed-content" in directives:
        add("LOW", "block-all-mixed-content",
            "Deprecated block-all-mixed-content directive in use",
            "block-all-mixed-content is deprecated. Modern browsers already block "
            "active mixed content by default, and passive mixed content blocking is "
            "handled by the browser's built-in mixed content algorithm.",
            "Remove block-all-mixed-content. Use upgrade-insecure-requests instead, "
            "or ensure all resources are served over HTTPS natively.")

    # plugin-types (deprecated)
    if "plugin-types" in directives:
        add("LOW", "plugin-types",
            "Deprecated plugin-types directive in use",
            "plugin-types is deprecated and removed from the CSP specification. "
            "It was used to restrict MIME types for plugins, but browser plugin "
            "support has been dropped. The directive is now ignored by all modern browsers.",
            "Remove plugin-types from the policy. Use object-src 'none'; to block "
            "all plugin elements instead.")

    # prefetch-src (deprecated/non-standard)
    if "prefetch-src" in directives:
        add("LOW", "prefetch-src",
            "Deprecated/non-standard prefetch-src directive in use",
            "prefetch-src is non-standard and deprecated. It is only supported in "
            "Safari and is ignored by Chromium and Firefox. Relying on it provides "
            "a false sense of security in other browsers.",
            "Remove prefetch-src. Control prefetch behavior through other means "
            "or use nonce/hash-based policies.")

    # unsafe-eval in style-src
    effective_style = effective_style_src(directives)
    if effective_style and has_unsafe_eval(effective_style):
        directive_name = "style-src" if "style-src" in directives else "default-src"
        add("LOW", directive_name,
            "'unsafe-eval' in style source — CSS dynamic evaluation enabled",
            "'unsafe-eval' in style-src is unusual and unnecessary in most cases. "
            "It has limited applicability to styles but may indicate a copy-paste "
            "error that should be cleaned up.",
            "Remove 'unsafe-eval' from style-src if not specifically required.")

    # img-src not restricted
    img_src = directives.get("img-src")
    if img_src is None and (not default_src or "*" in default_src):
        add("LOW", "img-src",
            "img-src not defined — images can be loaded from any origin",
            "Without img-src (and with an open default-src), images can be loaded "
            "from any URL. Attackers can use img src tags to conduct DNS-based "
            "data exfiltration or CSRF-style resource inclusion attacks.",
            "Define img-src with a specific allowlist, e.g., 'img-src 'self' data:;'.")

    # navigate-to deprecated directive present
    if "navigate-to" in directives:
        add("LOW", "navigate-to",
            "Deprecated navigate-to directive in use",
            "The navigate-to directive was proposed for CSP Level 3 to restrict "
            "document navigation targets but was removed from the spec before "
            "standardisation. It is unsupported in Chrome and Firefox, and support "
            "was removed from Safari. Including it gives a false sense of restriction "
            "on navigation.",
            "Remove navigate-to. Use frame-ancestors for embedding protection and "
            "enforce server-side redirect validation for navigation control.")

    # Missing default-src entirely — no fallback for unspecified resource types
    if "default-src" not in directives:
        add("LOW", "default-src",
            "No default-src defined — resource types without explicit directives are unrestricted",
            "When default-src is absent, any fetch directive not explicitly listed in "
            "the policy has no restriction at all. This means resource types like "
            "font-src, media-src, object-src, or others without an explicit directive "
            "are completely unrestricted. An attacker could load content from arbitrary "
            "origins for those resource categories.",
            "Add 'default-src 'none';' as a baseline, then explicitly allow only "
            "the resource types your application needs. This ensures unknown or "
            "future resource categories default to a deny stance.")

    # font-src wildcard or unconstrained
    font_src = directives.get("font-src")
    if font_src and ("*" in font_src or "https:" in font_src):
        add("LOW", "font-src",
            "Overly permissive font-src — fonts can be loaded from any origin",
            "A wildcard or scheme-only value in font-src allows loading web fonts "
            "from arbitrary servers. Attackers can abuse @font-face rules to "
            "trigger network requests to attacker-controlled servers, enabling "
            "CSS-based timing attacks, CSS injection exfiltration, and data "
            "exfiltration via font-loading side-channels.",
            "Restrict font-src to specific trusted font providers such as "
            "'self' or 'https://fonts.gstatic.com'.")

    # X-Frame-Options present but frame-ancestors not set (note)
    xfo_present = "x-frame-options" in response_headers
    if xfo_present and "frame-ancestors" not in directives:
        add("LOW", "frame-ancestors",
            "X-Frame-Options present but CSP frame-ancestors not set",
            "The response includes an X-Frame-Options header, but the more modern "
            "and flexible frame-ancestors CSP directive is not set. X-Frame-Options "
            "is not respected by modern CSP-aware parsers when frame-ancestors is "
            "present, but having only X-Frame-Options means the page relies on an "
            "older mechanism. frame-ancestors supersedes X-Frame-Options and provides "
            "more granular control.",
            "Add 'frame-ancestors 'none';' or 'frame-ancestors 'self';' to the CSP. "
            "Keep X-Frame-Options for legacy browser compatibility.")

    # ── INFO ──────────────────────────────────────────────────────────────────

    if is_report_only:
        add("INFO", "header",
            "CSP is in report-only mode (Content-Security-Policy-Report-Only)",
            "The policy is set using Content-Security-Policy-Report-Only. "
            "This is useful for testing but does not enforce any restrictions — "
            "all resources are allowed to load and violations are only reported.",
            "Once the policy is validated against real traffic, switch to the "
            "enforcing Content-Security-Policy header.")

    if effective_script and has_nonce(effective_script):
        add("INFO", "script-src",
            "Nonce-based script restriction detected",
            "The script-src directive includes a nonce source expression ('nonce-...'). "
            "Nonces are a strong mechanism when generated securely per response and "
            "used correctly in script tags.",
            "Ensure the nonce is cryptographically random, unique per HTTP response, "
            "and not predictable. Avoid generating nonces in static HTML.")

    if effective_script and has_hash(effective_script):
        add("INFO", "script-src",
            "Hash-based script restriction detected",
            "The script-src directive includes a hash source expression ('sha256-...', "
            "'sha384-...', or 'sha512-...'). Hashes are a robust mechanism for "
            "whitelisting known inline scripts or external scripts with integrity checks.",
            "Keep hashes up to date if script content changes. Consider pairing with "
            "'strict-dynamic' to allow trusted scripts to load additional scripts.")

    if "upgrade-insecure-requests" in directives:
        add("INFO", "upgrade-insecure-requests",
            "upgrade-insecure-requests directive is present",
            "upgrade-insecure-requests instructs browsers to upgrade HTTP sub-resource "
            "requests to HTTPS automatically. This helps prevent mixed-content issues "
            "during HTTP→HTTPS migrations.",
            "Ensure Strict-Transport-Security (HSTS) is also set, as "
            "upgrade-insecure-requests does not upgrade cross-origin navigation links.")

    # wasm-unsafe-eval (better alternative to unsafe-eval for WebAssembly)
    if effective_script and "'wasm-unsafe-eval'" in effective_script:
        add("INFO", "script-src",
            "'wasm-unsafe-eval' in script-src — WebAssembly compilation enabled",
            "'wasm-unsafe-eval' allows WebAssembly.compile() and related APIs without "
            "enabling the broader 'unsafe-eval'. This is the correct, narrow permission "
            "for applications that require WebAssembly, avoiding the full risks of "
            "'unsafe-eval'.",
            "Ensure 'unsafe-eval' is not also present. 'wasm-unsafe-eval' alone is "
            "the preferred approach when WebAssembly is required.")

    # strict-dynamic effective (nonce/hash + strict-dynamic)
    if effective_script and "'strict-dynamic'" in effective_script:
        if has_nonce(effective_script) or has_hash(effective_script):
            add("INFO", "script-src",
                "'strict-dynamic' is active — trusted scripts may load additional scripts",
                "'strict-dynamic' is paired with a nonce or hash, making it effective. "
                "Scripts with the correct nonce/hash may dynamically load additional "
                "scripts without requiring those scripts to be in the allowlist. "
                "This eases deployment of strict CSPs for sites using third-party loaders.",
                "Ensure only trusted entry-point scripts receive nonces/hashes. "
                "Be aware that strict-dynamic reduces the value of host allowlists — "
                "any trusted script can load scripts from any origin.")

    # sandbox directive
    if "sandbox" in directives:
        sandbox_vals = directives.get("sandbox", [])
        desc = f"Values: {', '.join(sandbox_vals) if sandbox_vals else '(all restrictions active)'}"
        add("INFO", "sandbox",
            f"sandbox directive present — additional page restrictions active ({desc})",
            "The sandbox directive applies iframe-like sandboxing restrictions to "
            "the document: same-origin policy, popups, form submissions, and script "
            "execution may be restricted depending on the sandbox flags. This provides "
            "a meaningful additional layer of defense.",
            "Review the sandbox flags to ensure no unnecessary capabilities are "
            "granted (e.g., avoid 'allow-same-origin allow-scripts' together as "
            "that combination negates the sandbox).")

    # require-trusted-types-for (client-side XSS defense)
    if "require-trusted-types-for" in directives:
        add("INFO", "require-trusted-types-for",
            "require-trusted-types-for is set — Trusted Types enforced for DOM sinks",
            "require-trusted-types-for 'script' requires all DOM XSS injection sinks "
            "(innerHTML, document.write, etc.) to receive TrustedType objects rather "
            "than raw strings. This is a powerful client-side XSS mitigation that "
            "forces all DOM manipulation through sanitization policies.",
            "Pair with the trusted-types directive to restrict which Trusted Type "
            "policy names are allowed. Test thoroughly in older browsers that lack "
            "Trusted Types support.")

    # trusted-types policy names
    if "trusted-types" in directives:
        tt_vals = directives.get("trusted-types", [])
        add("INFO", "trusted-types",
            f"trusted-types directive present — allowed policy names: {', '.join(tt_vals) or '(none)'}",
            "The trusted-types directive restricts which Trusted Type policy names "
            "can be created via trustedTypes.createPolicy(). This prevents attackers "
            "from creating arbitrary sanitization policies to bypass require-trusted-types-for.",
            "Keep the policy list as small as possible. Avoid the 'allow-duplicates' "
            "keyword unless required for third-party library compatibility.")

    # X-Frame-Options note when frame-ancestors IS set
    if xfo_present and "frame-ancestors" in directives:
        add("INFO", "frame-ancestors",
            "Both X-Frame-Options and CSP frame-ancestors are set",
            "Both X-Frame-Options and the more modern frame-ancestors CSP directive "
            "are present. When frame-ancestors is present in a CSP, it takes precedence "
            "and X-Frame-Options is ignored by supporting browsers. Having both provides "
            "backward compatibility for very old browsers.",
            "This is acceptable — both headers provide defense in depth. Ensure they "
            "are not contradictory (e.g., X-Frame-Options: DENY vs. frame-ancestors "
            "'self' would confuse legacy browsers).")

    return findings


# ── Risk score ────────────────────────────────────────────────────────────────
def calculate_risk_score(findings: list[Finding]) -> tuple[int, str, str, str]:
    """Return (score, risk_label, risk_class, description)."""
    score = 100
    for f in findings:
        deductions = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2, "INFO": 0}
        score -= deductions.get(f.severity, 0)
    score = max(0, score)

    if score >= 85:
        return (score, "Strong", "strong",
                "The CSP is well-configured with minimal security risks. "
                "Continue monitoring for regressions as the application evolves.")
    elif score >= 65:
        return (score, "Moderate", "moderate",
                "The CSP has some issues that should be addressed to improve protection. "
                "Resolve the flagged findings to harden the policy.")
    elif score >= 45:
        return (score, "Weak", "weak",
                "The CSP has significant weaknesses that substantially reduce its "
                "effectiveness against XSS and related attacks.")
    elif score >= 25:
        return (score, "Poor", "poor",
                "The CSP has critical misconfigurations that leave the application "
                "largely unprotected. Immediate remediation is recommended.")
    else:
        return (score, "Critical Risk", "critical",
                "The CSP is severely misconfigured or missing, providing no meaningful "
                "security protection. Treat this as an urgent security issue.")


# ── HTML report helpers ────────────────────────────────────────────────────────
def _h(s: object) -> str:
    """HTML-escape a value for safe insertion into HTML."""
    return html_lib.escape(str(s), quote=True)


def _build_css() -> str:
    return """
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --c-critical: #dc2626; --c-critical-bg: #fef2f2; --c-critical-border: #fecaca;
      --c-high:     #c2410c; --c-high-bg:     #fff7ed; --c-high-border:     #fed7aa;
      --c-medium:   #b45309; --c-medium-bg:   #fffbeb; --c-medium-border:   #fde68a;
      --c-low:      #1d4ed8; --c-low-bg:      #eff6ff; --c-low-border:      #bfdbfe;
      --c-info:     #0e7490; --c-info-bg:     #ecfeff; --c-info-border:     #a5f3fc;
      --c-ok:       #16a34a; --c-ok-bg:       #f0fdf4;
      --bg:         #f1f5f9;
      --surface:    #ffffff;
      --header-bg:  #0f172a;
      --text:       #1e293b;
      --text-2:     #64748b;
      --border:     #e2e8f0;
      --radius:     10px;
    }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
           'Helvetica Neue', Arial, sans-serif; background: var(--bg);
           color: var(--text); line-height: 1.6; font-size: 15px; }
    a { color: #3b82f6; }
    .container { max-width: 1080px; margin: 0 auto; padding: 0 24px; }

    /* ── Header ── */
    .site-header { background: var(--header-bg); color: #f8fafc;
                   padding: 28px 0; border-bottom: 3px solid #3b82f6; }
    .hdr-inner { display: flex; align-items: flex-start; gap: 32px;
                 flex-wrap: wrap; justify-content: space-between; }
    .brand { display: flex; align-items: center; gap: 14px; }
    .brand-icon { font-size: 2.8rem; line-height: 1; }
    .brand h1 { font-size: 1.9rem; font-weight: 800; letter-spacing: -0.03em;
                color: #f8fafc; }
    .brand .ver { font-size: 0.8rem; font-weight: 400; color: #64748b;
                  margin-left: 6px; }
    .brand .subtitle { color: #94a3b8; font-size: 0.82rem; margin-top: 3px; }
    .hdr-meta { display: grid; grid-template-columns: repeat(auto-fit,minmax(170px,1fr));
                gap: 10px; flex: 1; min-width: 260px; }
    .meta-pill { background: rgba(255,255,255,0.06);
                 border: 1px solid rgba(255,255,255,0.1);
                 border-radius: 8px; padding: 10px 14px; }
    .meta-pill .lbl { display: block; font-size: 0.65rem; text-transform: uppercase;
                      letter-spacing: .1em; color: #94a3b8; margin-bottom: 3px; }
    .meta-pill .val { font-size: 0.88rem; font-weight: 500; color: #e2e8f0;
                      word-break: break-all; }
    .val.enforcing { color: #4ade80; }
    .val.report-only { color: #fbbf24; }

    /* ── Main ── */
    main { padding: 32px 0 48px; }
    section { margin-bottom: 28px; }
    .section-title { font-size: 1.1rem; font-weight: 700; color: #0f172a;
                     margin-bottom: 14px; padding-bottom: 8px;
                     border-bottom: 2px solid var(--border);
                     display: flex; align-items: center; gap: 8px; }
    .section-icon { font-size: 1rem; }

    /* ── Report-only banner ── */
    .ro-banner { background: #fef9c3; border: 1px solid #fde047;
                 border-radius: var(--radius); padding: 12px 18px;
                 color: #713f12; font-weight: 600; margin-bottom: 24px;
                 display: flex; align-items: center; gap: 10px; font-size: 0.9rem; }

    /* ── Risk card ── */
    .risk-card { background: var(--surface); border-radius: var(--radius);
                 box-shadow: 0 1px 4px rgba(0,0,0,.08); padding: 24px 28px;
                 display: flex; align-items: center; gap: 28px; flex-wrap: wrap; }
    .score-ring { width: 110px; height: 110px; border-radius: 50%;
                  display: flex; flex-direction: column; align-items: center;
                  justify-content: center; flex-shrink: 0; border: 7px solid; }
    .score-ring.strong  { border-color:#16a34a; background:#f0fdf4; }
    .score-ring.moderate{ border-color:#65a30d; background:#f7fee7; }
    .score-ring.weak    { border-color:#d97706; background:#fffbeb; }
    .score-ring.poor    { border-color:#dc2626; background:#fef2f2; }
    .score-ring.critical{ border-color:#7f1d1d; background:#fef2f2; }
    .score-num  { font-size: 2rem; font-weight: 800; line-height: 1; }
    .score-ring.strong   .score-num { color:#16a34a; }
    .score-ring.moderate .score-num { color:#65a30d; }
    .score-ring.weak     .score-num { color:#d97706; }
    .score-ring.poor     .score-num { color:#dc2626; }
    .score-ring.critical .score-num { color:#7f1d1d; }
    .score-denom { font-size: 0.7rem; color: var(--text-2); margin-top: 2px; }
    .risk-info h2 { font-size: 1.3rem; font-weight: 700; margin-bottom: 6px; }
    .risk-lbl { font-size: 1.4rem; font-weight: 800; }
    .risk-lbl.strong   { color:#16a34a; }
    .risk-lbl.moderate { color:#65a30d; }
    .risk-lbl.weak     { color:#d97706; }
    .risk-lbl.poor     { color:#dc2626; }
    .risk-lbl.critical { color:#7f1d1d; }
    .risk-desc { color: var(--text-2); font-size: 0.9rem; max-width: 520px;
                 margin-top: 6px; }

    /* ── Severity cards ── */
    .sev-cards { display: grid; grid-template-columns: repeat(5,1fr); gap: 14px; }
    @media(max-width:680px){ .sev-cards { grid-template-columns: repeat(3,1fr); } }
    .sev-card { background: var(--surface); border-radius: var(--radius);
                box-shadow: 0 1px 4px rgba(0,0,0,.08); padding: 18px 16px;
                text-align: center; border-top: 4px solid; }
    .sev-card.critical { border-color: var(--c-critical); }
    .sev-card.high     { border-color: var(--c-high);     }
    .sev-card.medium   { border-color: var(--c-medium);   }
    .sev-card.low      { border-color: var(--c-low);      }
    .sev-card.info     { border-color: var(--c-info);     }
    .sev-count { font-size: 2.4rem; font-weight: 800; line-height: 1; }
    .sev-card.critical .sev-count { color: var(--c-critical); }
    .sev-card.high     .sev-count { color: var(--c-high);     }
    .sev-card.medium   .sev-count { color: var(--c-medium);   }
    .sev-card.low      .sev-count { color: var(--c-low);      }
    .sev-card.info     .sev-count { color: var(--c-info);     }
    .sev-name { font-size: 0.68rem; font-weight: 700; text-transform: uppercase;
                letter-spacing: .1em; margin-top: 5px; }
    .sev-card.critical .sev-name { color: var(--c-critical); }
    .sev-card.high     .sev-name { color: var(--c-high);     }
    .sev-card.medium   .sev-name { color: var(--c-medium);   }
    .sev-card.low      .sev-name { color: var(--c-low);      }
    .sev-card.info     .sev-name { color: var(--c-info);     }
    .sev-bar { height: 5px; border-radius: 3px; background: var(--border);
               margin-top: 10px; overflow: hidden; }
    .sev-bar-fill { height: 100%; border-radius: 3px; }
    .sev-card.critical .sev-bar-fill { background: var(--c-critical); }
    .sev-card.high     .sev-bar-fill { background: var(--c-high);     }
    .sev-card.medium   .sev-bar-fill { background: var(--c-medium);   }
    .sev-card.low      .sev-bar-fill { background: var(--c-low);      }
    .sev-card.info     .sev-bar-fill { background: var(--c-info);     }

    /* ── CSP box ── */
    .csp-box { background: var(--surface); border-radius: var(--radius);
               box-shadow: 0 1px 4px rgba(0,0,0,.08); overflow: hidden; }
    .csp-box-bar { background: var(--header-bg); color: #94a3b8; font-size: 0.65rem;
                   font-weight: 600; letter-spacing: .12em; text-transform: uppercase;
                   padding: 8px 16px; }
    .csp-box-value { padding: 16px 20px; font-family: 'SFMono-Regular', Consolas,
                     'Liberation Mono', Menlo, monospace; font-size: 0.82rem;
                     line-height: 1.85; white-space: pre-wrap; word-break: break-all;
                     border-left: 4px solid #3b82f6; color: var(--text); }
    .csp-absent { padding: 16px 20px; color: var(--c-critical); font-weight: 600;
                  background: var(--c-critical-bg); border-left: 4px solid var(--c-critical); }
    .kw-unsafe  { color: var(--c-critical); font-weight: 700; }
    .kw-wild    { color: var(--c-high);     font-weight: 700; }
    .kw-nonce   { color: var(--c-ok);       font-weight: 600; }
    .kw-hash    { color: var(--c-ok);       font-weight: 600; }
    .kw-self    { color: #7c3aed;           font-weight: 600; }
    .kw-scheme  { color: #0369a1;           }

    /* ── Directives table ── */
    .dir-table { width: 100%; border-collapse: collapse; background: var(--surface);
                 border-radius: var(--radius); box-shadow: 0 1px 4px rgba(0,0,0,.08);
                 overflow: hidden; }
    .dir-table th { background: var(--header-bg); color: #94a3b8; font-size: 0.65rem;
                    font-weight: 600; letter-spacing: .1em; text-transform: uppercase;
                    padding: 10px 16px; text-align: left; }
    .dir-table td { padding: 11px 16px; border-bottom: 1px solid #f1f5f9;
                    font-size: 0.87rem; vertical-align: top; }
    .dir-table tr:last-child td { border-bottom: none; }
    .dir-table tr:hover td { background: #f8fafc; }
    .dir-table tr.missing td { color: var(--text-2); font-style: italic; }
    .dir-name { font-family: monospace; font-weight: 700; white-space: nowrap;
                color: var(--text); }
    .dir-values { font-family: monospace; font-size: 0.8rem; color: #475569;
                  max-width: 380px; word-break: break-word; }
    .dir-coverage { font-size: 0.78rem; color: var(--text-2); }
    .st-badge { display: inline-flex; align-items: center; gap: 4px; padding: 3px 10px;
                border-radius: 999px; font-size: 0.68rem; font-weight: 700;
                letter-spacing: .05em; white-space: nowrap; }
    .st-ok      { background: #dcfce7; color: #166534; }
    .st-warn    { background: #fef9c3; color: #713f12; }
    .st-danger  { background: #fee2e2; color: #991b1b; }
    .st-missing { background: #f1f5f9; color: #64748b; }

    /* ── Findings ── */
    details.sev-group { background: var(--surface); border-radius: var(--radius);
                        box-shadow: 0 1px 4px rgba(0,0,0,.08); margin-bottom: 14px;
                        overflow: hidden; }
    details.sev-group > summary { padding: 15px 20px; cursor: pointer; list-style: none;
                                   display: flex; align-items: center; gap: 12px;
                                   user-select: none; }
    details.sev-group > summary::-webkit-details-marker { display: none; }
    details.sev-group > summary:hover { background: #f8fafc; }
    details.sev-group[open] > summary { border-bottom: 1px solid var(--border); }
    .sev-badge { padding: 3px 10px; border-radius: 4px; font-size: 0.68rem;
                 font-weight: 800; letter-spacing: .12em; text-transform: uppercase;
                 color: #fff; }
    .sev-badge.critical { background: var(--c-critical); }
    .sev-badge.high     { background: var(--c-high);     }
    .sev-badge.medium   { background: var(--c-medium);   }
    .sev-badge.low      { background: var(--c-low);      }
    .sev-badge.info     { background: var(--c-info);     }
    .sev-group-count { color: var(--text-2); font-size: 0.88rem; }
    .sev-arrow { margin-left: auto; color: #94a3b8; font-size: 0.75rem;
                 transition: transform .2s; }
    details.sev-group[open] .sev-arrow { transform: rotate(90deg); }
    .finding-cards { padding: 14px 16px; display: flex; flex-direction: column;
                     gap: 12px; }
    .finding-card { border: 1px solid var(--border); border-radius: 8px;
                    overflow: hidden; }
    .finding-hdr { padding: 13px 16px; border-left: 4px solid; display: flex;
                   flex-wrap: wrap; align-items: flex-start; gap: 8px; }
    .finding-card.critical .finding-hdr {
      border-color: var(--c-critical); background: var(--c-critical-bg); }
    .finding-card.high .finding-hdr {
      border-color: var(--c-high); background: var(--c-high-bg); }
    .finding-card.medium .finding-hdr {
      border-color: var(--c-medium); background: var(--c-medium-bg); }
    .finding-card.low .finding-hdr {
      border-color: var(--c-low); background: var(--c-low-bg); }
    .finding-card.info .finding-hdr {
      border-color: var(--c-info); background: var(--c-info-bg); }
    .finding-title { font-size: 0.93rem; font-weight: 700; color: #0f172a;
                     flex: 1; }
    .dir-badge { font-family: monospace; font-size: 0.75rem; background: rgba(0,0,0,.07);
                 padding: 2px 8px; border-radius: 4px; color: #475569;
                 align-self: flex-start; white-space: nowrap; }
    .finding-body { padding: 14px 16px; display: grid;
                    grid-template-columns: 1fr 1fr; gap: 16px; }
    @media(max-width:620px){ .finding-body { grid-template-columns: 1fr; } }
    .f-label { font-size: 0.67rem; font-weight: 700; text-transform: uppercase;
               letter-spacing: .1em; color: var(--text-2); margin-bottom: 5px; }
    .f-desc p { font-size: 0.86rem; color: #374151; line-height: 1.65; }
    .f-rec { background: var(--c-ok-bg); border-radius: 6px; padding: 12px 14px; }
    .f-rec .f-label { color: #166534; }
    .f-rec p { font-size: 0.86rem; color: #166534; line-height: 1.65; }

    /* ── Recommendations ── */
    .rec-list { display: flex; flex-direction: column; gap: 12px; }
    .rec-item { background: var(--surface); border-radius: var(--radius);
                box-shadow: 0 1px 4px rgba(0,0,0,.08); padding: 16px 20px;
                display: flex; gap: 16px; align-items: flex-start; }
    .rec-num { width: 30px; height: 30px; border-radius: 50%; background: var(--header-bg);
               color: #fff; font-weight: 700; font-size: 0.8rem; display: flex;
               align-items: center; justify-content: center; flex-shrink: 0; }
    .rec-title { font-weight: 700; font-size: 0.93rem; margin-bottom: 3px; }
    .rec-body { font-size: 0.85rem; color: var(--text-2); line-height: 1.6; }

    /* ── No findings ── */
    .no-findings { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0;
                   border-radius: var(--radius); padding: 20px; font-weight: 600;
                   text-align: center; }

    /* ── Footer ── */
    .site-footer { background: var(--header-bg); color: #64748b; padding: 22px 0;
                   font-size: 0.8rem; text-align: center; margin-top: 40px; }
    .site-footer p { margin-bottom: 5px; }
    .site-footer a { color: #60a5fa; text-decoration: none; }
    .site-footer a:hover { text-decoration: underline; }
    .disclaimer { color: #475569; font-style: italic; margin-top: 8px; }

    /* ── Print ── */
    @media print {
      body { background: #fff; }
      .site-header, .site-footer { -webkit-print-color-adjust: exact;
                                   print-color-adjust: exact; }
      details { display: block !important; }
      details > * { display: block !important; }
    }
"""


def _colorize_csp_value(val: str) -> str:
    """Wrap CSP source-list tokens in colored spans for the HTML display."""
    unsafe = {"'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'"}
    wild   = {"*", "http:", "https:", "data:", "blob:"}
    nonce_pfx  = "'nonce-"
    hash_pfxs  = ("'sha256-", "'sha384-", "'sha512-")
    self_kw    = ("'self'", "'none'", "'strict-dynamic'",
                  "'unsafe-hashes'", "'wasm-unsafe-eval'",
                  "'trusted-types-eval'")

    parts = val.split()
    out = []
    for p in parts:
        pl = p.lower()
        if pl in unsafe:
            out.append(f'<span class="kw-unsafe">{_h(p)}</span>')
        elif pl in wild:
            out.append(f'<span class="kw-wild">{_h(p)}</span>')
        elif pl.startswith(nonce_pfx):
            out.append(f'<span class="kw-nonce">{_h(p)}</span>')
        elif any(pl.startswith(pfx) for pfx in hash_pfxs):
            out.append(f'<span class="kw-hash">{_h(p)}</span>')
        elif pl in self_kw:
            out.append(f'<span class="kw-self">{_h(p)}</span>')
        else:
            out.append(f'<span class="kw-scheme">{_h(p)}</span>')
    return " ".join(out)


def _directive_status(directive: str, values: list[str],
                      findings: list[Finding]) -> str:
    """Return an HTML status badge for a directive based on findings."""
    sev_for = [f.severity for f in findings if f.directive == directive]
    if not values:
        return '<span class="st-badge st-missing">— Not Set</span>'
    if "CRITICAL" in sev_for:
        return '<span class="st-badge st-danger">✖ Critical</span>'
    if "HIGH" in sev_for:
        return '<span class="st-badge st-danger">✖ Issue</span>'
    if "MEDIUM" in sev_for or "LOW" in sev_for:
        return '<span class="st-badge st-warn">⚠ Warning</span>'
    return '<span class="st-badge st-ok">✓ OK</span>'


def _build_directive_table(directives: dict[str, list[str]],
                           findings: list[Finding]) -> str:
    COVERAGE = {
        "default-src":   "Fallback for all fetch directives",
        "script-src":    "JavaScript sources",
        "script-src-elem": "Inline &lt;script&gt; elements",
        "script-src-attr": "Inline script event handlers",
        "style-src":     "CSS stylesheets",
        "style-src-elem": "Inline &lt;style&gt; elements",
        "style-src-attr": "Inline style attributes",
        "img-src":       "Image sources",
        "font-src":      "Web font sources",
        "connect-src":   "XHR / fetch / WebSocket",
        "media-src":     "Audio &amp; video sources",
        "object-src":    "Plugin / &lt;object&gt; sources",
        "frame-src":     "Nested frame / iframe sources",
        "child-src":     "Workers &amp; nested contexts",
        "worker-src":    "Web Worker / ServiceWorker sources",
        "manifest-src":  "Web app manifest",
        "prefetch-src":  "Prefetch / prerender sources",
        "base-uri":      "Allowed &lt;base&gt; URIs",
        "form-action":   "Form submission targets",
        "frame-ancestors": "Allowed embedding contexts (clickjacking)",
        "navigate-to":   "Allowed navigation targets (deprecated)",
        "sandbox":       "Page sandbox restrictions",
        "upgrade-insecure-requests": "Upgrade HTTP → HTTPS",
        "block-all-mixed-content":   "Block mixed content (deprecated)",
        "report-uri":    "Violation reporting URI (deprecated)",
        "report-to":     "Violation reporting group",
        "require-trusted-types-for": "Trusted Types enforcement",
        "trusted-types": "Allowed Trusted Type policies",
        "plugin-types":  "Allowed plugin MIME types (deprecated)",
    }

    # Important directives to show even when missing
    KEY_DIRECTIVES = [
        "default-src", "script-src", "style-src", "img-src", "connect-src",
        "font-src", "object-src", "worker-src", "base-uri", "form-action",
        "frame-ancestors",
    ]

    all_dirs = list(directives.keys())
    # Show key missing directives + all present directives (deduplicated, ordered)
    shown = list(dict.fromkeys(KEY_DIRECTIVES + all_dirs))

    rows = []
    for d in shown:
        values = directives.get(d, [])
        is_missing = d not in directives
        cls = ' class="missing"' if is_missing else ""
        name_cell = f'<td><code class="dir-name">{_h(d)}</code></td>'
        if is_missing:
            val_cell = '<td class="dir-values"><span style="color:#94a3b8">not set</span></td>'
        else:
            colored = _colorize_csp_value(" ".join(values)) if values else \
                      '<span class="kw-self">\'none\'</span>'
            val_cell = f'<td class="dir-values">{colored}</td>'
        coverage = COVERAGE.get(d, "")
        cov_cell = f'<td class="dir-coverage">{coverage}</td>'
        status = _directive_status(d, values, findings)
        st_cell = f'<td>{status}</td>'
        rows.append(f"<tr{cls}>{name_cell}{val_cell}{cov_cell}{st_cell}</tr>")

    return (
        '<table class="dir-table">'
        '<thead><tr><th>Directive</th><th>Values</th>'
        '<th>Coverage</th><th>Status</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def _build_findings_html(findings: list[Finding]) -> str:
    if not findings:
        return '<div class="no-findings">✓ No security issues found.</div>'

    parts: list[str] = []
    for sev in SEVERITY_ORDER:
        sev_f = [f for f in findings if f.severity == sev]
        if not sev_f:
            continue
        cls = sev.lower()
        is_open = sev in ("CRITICAL", "HIGH")
        open_attr = " open" if is_open else ""
        n = len(sev_f)
        label = f'{n} finding{"s" if n != 1 else ""}'
        parts.append(
            f'<details class="sev-group"{open_attr}>'
            f'<summary>'
            f'<span class="sev-badge {cls}">{sev}</span>'
            f'<span class="sev-group-count">{label}</span>'
            f'<span class="sev-arrow">&#9654;</span>'
            f'</summary>'
            f'<div class="finding-cards">'
        )
        for f in sev_f:
            parts.append(
                f'<div class="finding-card {cls}">'
                f'<div class="finding-hdr">'
                f'<span class="finding-title">{_h(f.title)}</span>'
                f'<code class="dir-badge">{_h(f.directive)}</code>'
                f'</div>'
                f'<div class="finding-body">'
                f'<div class="f-desc">'
                f'<div class="f-label">Description</div>'
                f'<p>{_h(f.detail)}</p>'
                f'</div>'
                f'<div class="f-rec">'
                f'<div class="f-label">Recommendation</div>'
                f'<p>{_h(f.recommendation)}</p>'
                f'</div>'
                f'</div>'
                f'</div>'
            )
        parts.append("</div></details>")

    return "\n".join(parts)


def _build_recommendations_html(findings: list[Finding]) -> str:
    """Deduplicated top recommendations from HIGH+ findings, plus baseline tips."""
    TOP_RECS = [
        ("Adopt a strict nonce- or hash-based CSP",
         "Replace host allowlists with 'script-src \\'nonce-{RANDOM}\\' \\'strict-dynamic\\'; "
         "object-src \\'none\\'; base-uri \\'none\\';' — this pattern is resistant to most "
         "CSP bypass techniques documented in research literature."),
        ("Set object-src 'none' and base-uri 'none'",
         "Plugin elements and base-tag injection are two of the most common CSP bypass "
         "vectors. Explicitly blocking both is a baseline requirement for any effective policy."),
        ("Add frame-ancestors 'none' or 'self' for clickjacking protection",
         "The frame-ancestors directive prevents the page from being embedded in an iframe "
         "by untrusted origins, protecting against clickjacking and XS-Leaks."),
        ("Configure violation reporting (report-to + Reporting-Endpoints)",
         "Without reporting, CSP violations are invisible. Setting up a reporting endpoint "
         "enables detection of active attacks, policy gaps, and regressions."),
        ("Restrict connect-src and worker-src to known origins",
         "Unrestricted fetch/XHR and ServiceWorker sources allow data exfiltration and "
         "provide persistent XSS footholds. Lock both down to 'self' plus explicit APIs."),
        ("Remove deprecated directives (report-uri, block-all-mixed-content, plugin-types)",
         "Deprecated directives add noise, may behave unpredictably, and can create a "
         "false sense of security. Replace them with their modern equivalents."),
        ("Add upgrade-insecure-requests alongside HSTS",
         "upgrade-insecure-requests ensures sub-resources are loaded over HTTPS, "
         "while HSTS (Strict-Transport-Security) enforces HTTPS for all connections."),
        ("Consider Trusted Types (require-trusted-types-for 'script')",
         "Trusted Types enforce that all DOM XSS sinks receive sanitized values, "
         "providing a powerful client-side XSS mitigation layer beyond traditional CSP."),
    ]

    # Only include recommendations that are relevant to actual findings
    sev_set = {f.severity for f in findings}
    relevant_recs = TOP_RECS if any(s in sev_set for s in ("CRITICAL", "HIGH", "MEDIUM")) \
        else TOP_RECS[3:]  # only reporting/operational recs for clean policies

    parts = ['<div class="rec-list">']
    for i, (title, body) in enumerate(relevant_recs, 1):
        parts.append(
            f'<div class="rec-item">'
            f'<div class="rec-num">{i}</div>'
            f'<div>'
            f'<div class="rec-title">{_h(title)}</div>'
            f'<div class="rec-body">{_h(body)}</div>'
            f'</div>'
            f'</div>'
        )
    parts.append("</div>")
    return "\n".join(parts)


def generate_html_report(
    findings: list[Finding],
    url: str,
    raw_csp: str | None,
    is_report_only: bool,
    status: int,
    directives: dict[str, list[str]],
    response_headers: dict[str, str],
) -> str:
    """Build and return a self-contained HTML report string."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    parsed = urlparse(url)
    host = parsed.netloc
    counts = severity_counts(findings)
    score, risk_label, risk_class, risk_desc = calculate_risk_score(findings)
    total = len(findings)

    css = _build_css()

    # ── header ────────────────────────────────────────────────────────────────
    mode_cls   = "report-only" if is_report_only else "enforcing"
    mode_label = "Report-Only (not enforced)" if is_report_only else "Enforcing"
    header_html = f"""
<header class="site-header">
  <div class="container">
    <div class="hdr-inner">
      <div class="brand">
        <span class="brand-icon">&#x1F6E1;</span>
        <div>
          <h1>CSP Scanner <span class="ver">v{_h(VERSION)}</span></h1>
          <p class="subtitle">Content Security Policy Analyzer &mdash; Authorized Testing Only</p>
        </div>
      </div>
      <div class="hdr-meta">
        <div class="meta-pill">
          <span class="lbl">Target</span>
          <span class="val">{_h(url)}</span>
        </div>
        <div class="meta-pill">
          <span class="lbl">Scanned</span>
          <span class="val">{_h(ts)}</span>
        </div>
        <div class="meta-pill">
          <span class="lbl">HTTP Status</span>
          <span class="val">{_h(status)}</span>
        </div>
        <div class="meta-pill">
          <span class="lbl">CSP Mode</span>
          <span class="val {mode_cls}">{_h(mode_label)}</span>
        </div>
      </div>
    </div>
  </div>
</header>"""

    # ── report-only banner ────────────────────────────────────────────────────
    ro_banner = ""
    if is_report_only:
        ro_banner = (
            '<div class="ro-banner">&#9888; '
            "This CSP is in <strong>Report-Only mode</strong> — policy violations are "
            "logged but the policy is <strong>not enforced</strong>. No actual protection "
            "is provided until a standard Content-Security-Policy header is deployed."
            "</div>"
        )

    # ── risk card ─────────────────────────────────────────────────────────────
    risk_card = f"""
<section>
  <h2 class="section-title"><span class="section-icon">&#x26A0;</span> Risk Assessment</h2>
  <div class="risk-card">
    <div class="score-ring {risk_class}">
      <span class="score-num">{score}</span>
      <span class="score-denom">/ 100</span>
    </div>
    <div class="risk-info">
      <h2>Security Rating: <span class="risk-lbl {risk_class}">{_h(risk_label)}</span></h2>
      <p class="risk-desc">{_h(risk_desc)}</p>
    </div>
  </div>
</section>"""

    # ── severity cards ────────────────────────────────────────────────────────
    max_count = max(counts.values()) or 1
    sev_card_html = '<div class="sev-cards">'
    for sev in SEVERITY_ORDER:
        c = counts[sev]
        pct = int(c / max_count * 100)
        sev_card_html += (
            f'<div class="sev-card {sev.lower()}">'
            f'<div class="sev-count">{c}</div>'
            f'<div class="sev-name">{sev}</div>'
            f'<div class="sev-bar"><div class="sev-bar-fill" style="width:{pct}%"></div></div>'
            f'</div>'
        )
    sev_card_html += "</div>"
    summary_section = f"""
<section>
  <h2 class="section-title"><span class="section-icon">&#x1F4CA;</span> Finding Summary</h2>
  {sev_card_html}
</section>"""

    # ── CSP header ────────────────────────────────────────────────────────────
    if raw_csp:
        # Color-code each directive block
        blocks = []
        for part in raw_csp.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split(None, 1)
            dname = _h(tokens[0])
            rest  = _colorize_csp_value(tokens[1]) if len(tokens) > 1 else ""
            sep   = " " if rest else ""
            blocks.append(f"<strong>{dname}</strong>{sep}{rest}")
        csp_display = ";\n".join(blocks) + ";"
        csp_content = f'<div class="csp-box-value">{csp_display}</div>'
    else:
        csp_content = '<div class="csp-absent">&#x2717; No Content-Security-Policy header detected.</div>'

    csp_section = f"""
<section>
  <h2 class="section-title"><span class="section-icon">&#x1F4DC;</span> CSP Header</h2>
  <div class="csp-box">
    <div class="csp-box-bar">Content-Security-Policy{' (Report-Only)' if is_report_only else ''}</div>
    {csp_content}
  </div>
</section>"""

    # ── directives table ──────────────────────────────────────────────────────
    dir_section = f"""
<section>
  <h2 class="section-title"><span class="section-icon">&#x1F4CB;</span> Directive Breakdown</h2>
  {_build_directive_table(directives, findings)}
</section>"""

    # ── findings ──────────────────────────────────────────────────────────────
    findings_section = f"""
<section>
  <h2 class="section-title">
    <span class="section-icon">&#x1F50D;</span> Findings
    <span style="font-size:.85rem;font-weight:400;color:var(--text-2)">&mdash; {total} total</span>
  </h2>
  {_build_findings_html(findings)}
</section>"""

    # ── recommendations ───────────────────────────────────────────────────────
    rec_section = f"""
<section>
  <h2 class="section-title"><span class="section-icon">&#x2705;</span> Key Recommendations</h2>
  {_build_recommendations_html(findings)}
</section>"""

    # ── footer ────────────────────────────────────────────────────────────────
    footer_html = f"""
<footer class="site-footer">
  <div class="container">
    <p>Generated by <strong>CSP Scanner v{_h(VERSION)}</strong> on {_h(ts)}</p>
    <p>
      <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP" target="_blank" rel="noopener">MDN CSP Guide</a> &middot;
      <a href="https://content-security-policy.com/" target="_blank" rel="noopener">CSP Reference</a> &middot;
      <a href="https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html" target="_blank" rel="noopener">OWASP Cheat Sheet</a> &middot;
      <a href="https://csp-evaluator.withgoogle.com/" target="_blank" rel="noopener">Google CSP Evaluator</a>
    </p>
    <p class="disclaimer">Authorized testing only &mdash; do not use against systems without explicit permission.</p>
  </div>
</footer>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CSP Scan Report &mdash; {_h(host)}</title>
  <style>{css}</style>
</head>
<body>
{header_html}
<main class="container">
  {ro_banner}
  {risk_card}
  {summary_section}
  {csp_section}
  {dir_section}
  {findings_section}
  {rec_section}
</main>
{footer_html}
</body>
</html>"""


# ── HTTP fetch ────────────────────────────────────────────────────────────────
def fetch_headers(url: str) -> tuple[dict[str, str], int]:
    """Fetch response headers from the given URL. Returns (headers_dict, status_code)."""
    ctx = ssl.create_default_context()
    req = Request(
        url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (compatible; CSP-Scanner/1.0; "
                "+https://github.com/pentest/csp-scanner)"
            )
        },
        method="HEAD",
    )
    try:
        with urlopen(req, context=ctx, timeout=TIMEOUT) as resp:
            headers = dict(resp.getheaders())
            return {k.lower(): v for k, v in headers.items()}, resp.status
    except HTTPError as e:
        # Still capture headers from error responses
        headers = dict(e.headers)
        return {k.lower(): v for k, v in headers.items()}, e.code
    except Exception:
        # Fall back to GET if HEAD fails
        req2 = Request(url, headers=req.headers)
        try:
            with urlopen(req2, context=ctx, timeout=TIMEOUT) as resp:
                headers = dict(resp.getheaders())
                return {k.lower(): v for k, v in headers.items()}, resp.status
        except HTTPError as e2:
            headers = dict(e2.headers)
            return {k.lower(): v for k, v in headers.items()}, e2.code


# ── Output helpers ────────────────────────────────────────────────────────────
def severity_icon(sev: str) -> str:
    return {
        "CRITICAL": "✖✖",
        "HIGH":     "✖ ",
        "MEDIUM":   "⚠ ",
        "LOW":      "▸ ",
        "INFO":     "ℹ ",
    }.get(sev, "  ")


def print_banner():
    print(f"""
{CO.C}{CO.BOLD}╔══════════════════════════════════════════════════════════╗
║          Content Security Policy (CSP) Scanner           ║
║                        v{VERSION}                            ║
╚══════════════════════════════════════════════════════════╝{CO.NC}
""")


def print_finding(f: Finding, index: int, total: int):
    col = SCOLORS.get(f.severity, "")
    icon = severity_icon(f.severity)
    print(f"  {col}{icon} [{f.severity}]{CO.NC} {CO.W}{f.title}{CO.NC}")
    print(f"  {CO.D}Directive : {CO.NC}{f.directive}")
    wrapped_detail = textwrap.fill(f.detail, width=72, subsequent_indent="              ")
    print(f"  {CO.D}Detail    : {CO.NC}{wrapped_detail}")
    wrapped_rec = textwrap.fill(f.recommendation, width=72, subsequent_indent="              ")
    print(f"  {CO.D}Fix       : {CO.NC}{CO.G}{wrapped_rec}{CO.NC}")
    if index < total - 1:
        print(f"  {CO.D}{'─' * 60}{CO.NC}")


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def print_summary(findings: list[Finding], url: str, raw_csp: str | None,
                  is_report_only: bool, status: int):
    counts = severity_counts(findings)
    score, risk_label, _, _ = calculate_risk_score(findings)
    print(f"\n{CO.BOLD}{'═' * 62}{CO.NC}")
    print(f"{CO.BOLD}  SUMMARY{CO.NC}")
    print(f"{'═' * 62}")
    print(f"  Target       : {CO.C}{url}{CO.NC}")
    print(f"  HTTP Status  : {status}")
    mode = f"{CO.Y}Report-Only (not enforced){CO.NC}" if is_report_only else f"{CO.G}Enforcing{CO.NC}"
    print(f"  CSP Mode     : {mode}")
    if raw_csp:
        wrapped = textwrap.fill(raw_csp, width=56, subsequent_indent="               ")
        print(f"  CSP Header   : {CO.DIM}{wrapped}{CO.NC}")
    else:
        print(f"  CSP Header   : {CO.R}Not present{CO.NC}")
    print(f"  Risk Score   : {score}/100 — {risk_label}")
    print()
    for sev in SEVERITY_ORDER:
        count = counts[sev]
        col = SCOLORS.get(sev, "")
        bar = "█" * count if count else CO.D + "none" + CO.NC
        print(f"  {col}{sev:<10}{CO.NC}  {col}{bar}{CO.NC} {count}")
    print(f"{'═' * 62}")
    total = len(findings)
    print(f"  {CO.BOLD}Total findings: {total}{CO.NC}")
    print(f"{'═' * 62}\n")


# ── Report saving ─────────────────────────────────────────────────────────────
def save_report(findings: list[Finding], url: str, raw_csp: str | None,
                is_report_only: bool, status: int, out_dir: str,
                directives: dict[str, list[str]],
                response_headers: dict[str, str]) -> tuple[str, str, str]:
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()

    # ── HTML ──────────────────────────────────────────────────────────────────
    html_path = os.path.join(out_dir, "report.html")
    html_content = generate_html_report(
        findings, url, raw_csp, is_report_only, status, directives, response_headers
    )
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html_content)

    # ── JSON ──────────────────────────────────────────────────────────────────
    json_path = os.path.join(out_dir, "findings.json")
    score, risk_label, risk_class, _ = calculate_risk_score(findings)
    report = {
        "tool": "CSP Scanner",
        "version": VERSION,
        "timestamp": ts,
        "target": url,
        "http_status": status,
        "csp_mode": "report-only" if is_report_only else "enforcing",
        "csp_header": raw_csp,
        "risk_score": score,
        "risk_label": risk_label,
        "finding_count": len(findings),
        "severity_counts": severity_counts(findings),
        "findings": [f.to_dict() for f in findings],
    }
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    # ── Plain text ─────────────────────────────────────────────────────────────
    txt_path = os.path.join(out_dir, "report.txt")
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write(f"CSP Scanner v{VERSION} — Report\n")
        fh.write(f"Generated : {ts}\n")
        fh.write(f"Target    : {url}\n")
        fh.write(f"HTTP Status: {status}\n")
        fh.write(f"CSP Mode  : {'report-only' if is_report_only else 'enforcing'}\n")
        fh.write(f"CSP Header: {raw_csp or 'NOT PRESENT'}\n")
        fh.write(f"Risk Score: {score}/100 ({risk_label})\n")
        fh.write("=" * 70 + "\n\n")
        counts = severity_counts(findings)
        for sev in SEVERITY_ORDER:
            fh.write(f"  {sev}: {counts[sev]}\n")
        fh.write(f"\n  Total findings: {len(findings)}\n")
        fh.write("=" * 70 + "\n\n")
        for i, f in enumerate(findings, 1):
            fh.write(f"[{i}] [{f.severity}] {f.title}\n")
            fh.write(f"    Directive      : {f.directive}\n")
            fh.write(f"    Detail         : {textwrap.fill(f.detail, width=70, subsequent_indent=' ' * 21)}\n")
            fh.write(f"    Recommendation : {textwrap.fill(f.recommendation, width=70, subsequent_indent=' ' * 21)}\n\n")

    return html_path, json_path, txt_path


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="csp-scanner",
        description="Content Security Policy (CSP) scanner — fetch, parse, and audit a CSP header.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 csp-scanner.py -u https://example.com
              python3 csp-scanner.py -u https://example.com -o results/csp/
              python3 csp-scanner.py -u https://example.com --no-save
        """),
    )
    parser.add_argument("-u", "--url", required=True,
                        help="Target URL (must start with http:// or https://)")
    parser.add_argument("-o", "--output", default="",
                        help="Directory to save the report (default: auto-generated under results/)")
    parser.add_argument("--no-save", action="store_true",
                        help="Print findings to stdout only, do not save to disk")
    parser.add_argument("--min-severity", default="INFO",
                        choices=SEVERITY_ORDER,
                        help="Minimum severity to display (default: INFO)")
    args = parser.parse_args()

    url = args.url
    if not url.startswith(("http://", "https://")):
        print(f"{CO.R}[!] URL must start with http:// or https://{CO.NC}")
        sys.exit(1)

    print_banner()
    print(f"  {CO.B}[*]{CO.NC} Fetching headers from: {CO.C}{url}{CO.NC}")

    try:
        headers, status = fetch_headers(url)
    except (URLError, OSError) as exc:
        print(f"\n  {CO.R}[!] Connection failed: {exc}{CO.NC}")
        sys.exit(1)

    # ── Detect CSP header ─────────────────────────────────────────────────────
    raw_csp: str | None = None
    is_report_only = False

    if "content-security-policy" in headers:
        raw_csp = headers["content-security-policy"]
        is_report_only = False
    elif "content-security-policy-report-only" in headers:
        raw_csp = headers["content-security-policy-report-only"]
        is_report_only = True

    # Check for deprecated CSP headers (informational)
    deprecated_headers_present = [
        h for h in ("x-content-security-policy", "x-webkit-csp")
        if h in headers
    ]

    print(f"  {CO.B}[*]{CO.NC} HTTP status : {status}")

    if raw_csp:
        mode_label = f"{CO.Y}report-only{CO.NC}" if is_report_only else f"{CO.G}enforcing{CO.NC}"
        print(f"  {CO.G}[+]{CO.NC} CSP header found ({mode_label})")
        directives = parse_csp(raw_csp)
        print(f"  {CO.B}[*]{CO.NC} Directives parsed: {', '.join(directives.keys()) or 'none'}")
    else:
        print(f"  {CO.R}[!]{CO.NC} No Content-Security-Policy header detected")
        directives = {}

    print(f"\n  {CO.B}[*]{CO.NC} Analyzing policy…\n")

    # ── Analyze ───────────────────────────────────────────────────────────────
    findings: list[Finding] = []

    if not raw_csp:
        findings.append(Finding(
            severity="CRITICAL",
            directive="N/A",
            title="Content-Security-Policy header is missing",
            detail=(
                "The server does not return a Content-Security-Policy (or "
                "Content-Security-Policy-Report-Only) header. Without a CSP, "
                "the browser applies no restrictions on resource loading, "
                "inline script execution, or embedded framing. This leaves the "
                "application fully exposed to XSS, clickjacking, and other "
                "client-side injection attacks."
            ),
            recommendation=(
                "Implement a Content-Security-Policy header on all HTTP responses. "
                "Start with a strict policy: "
                "\"script-src 'nonce-{RANDOM}'; object-src 'none'; base-uri 'none'\" "
                "and progressively refine it using Content-Security-Policy-Report-Only "
                "to capture violations before switching to enforcement mode."
            ),
        ))
    else:
        findings.extend(analyze_csp(directives, is_report_only))

    # Deprecated headers finding
    for dep_hdr in deprecated_headers_present:
        findings.append(Finding(
            severity="LOW",
            directive=dep_hdr,
            title=f"Deprecated proprietary CSP header in use: {dep_hdr}",
            detail=(
                f"The response includes the non-standard '{dep_hdr}' header. "
                "This was a vendor-specific predecessor to Content-Security-Policy "
                "(supported in older Firefox/Chrome). Its implementation is buggy, "
                "limited, and inconsistent — it should not be relied upon."
            ),
            recommendation=(
                f"Remove '{dep_hdr}'. Use the standard "
                "'Content-Security-Policy' header instead."
            ),
        ))

    # Sort by severity order
    order_map = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    findings.sort(key=lambda f: order_map.get(f.severity, 99))

    # Filter by minimum severity
    min_idx = order_map.get(args.min_severity, 99)
    visible = [f for f in findings if order_map.get(f.severity, 99) <= min_idx]

    # ── Print findings ────────────────────────────────────────────────────────
    if visible:
        print(f"{CO.BOLD}{'─' * 62}")
        print(f"  FINDINGS ({len(visible)})")
        print(f"{'─' * 62}{CO.NC}\n")
        for i, f in enumerate(visible):
            print_finding(f, i, len(visible))
        print()
    else:
        print(f"  {CO.G}[✓] No issues found at or above severity '{args.min_severity}'.{CO.NC}\n")

    # ── Summary ───────────────────────────────────────────────────────────────
    print_summary(findings, url, raw_csp, is_report_only, status)

    # ── Save ──────────────────────────────────────────────────────────────────
    if not args.no_save:
        parsed = urlparse(url)
        host_slug = re.sub(r"[^\w\-.]", "_", parsed.netloc)
        ts_slug = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = args.output or os.path.join(
            "results", f"csp-scan_{host_slug}_{ts_slug}"
        )
        html_path, json_path, txt_path = save_report(
            findings, url, raw_csp, is_report_only, status,
            out_dir, directives, headers
        )
        print(f"  {CO.G}[+]{CO.NC} Reports saved:")
        print(f"       HTML : {CO.C}{html_path}{CO.NC}")
        print(f"       JSON : {CO.C}{json_path}{CO.NC}")
        print(f"       Text : {CO.C}{txt_path}{CO.NC}\n")


if __name__ == "__main__":
    main()
