"""
header_parser.py
-----------------
Parses a raw .eml file (or raw email text) and extracts:
  - SPF / DKIM / DMARC authentication results
  - Return-Path, Reply-To, From (for spoofing/mismatch checks)
  - The Received header chain (relay path)
  - A best-guess originating IP address

This is Week 1 of the build plan: get this working reliably on
10-15 sample emails before moving to the AI layer.

Usage:
    python header_parser.py path/to/email.eml
"""

import sys
import re
import json
from email import message_from_file, message_from_string
from email.policy import default as default_policy


IP_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)

# IPs that should never be treated as "the originating IP" — internal /
# private ranges commonly seen in relay chains.
PRIVATE_IP_PREFIXES = ("10.", "127.", "192.168.", "169.254.")


def _is_private_ip(ip: str) -> bool:
    if ip.startswith(PRIVATE_IP_PREFIXES):
        return True
    if ip.startswith("172."):
        try:
            second_octet = int(ip.split(".")[1])
            return 16 <= second_octet <= 31
        except (IndexError, ValueError):
            return False
    return False


def load_email(path: str):
    """Load a .eml file from disk using the modern email.policy API."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return message_from_file(f, policy=default_policy)


def load_email_from_string(raw_text: str):
    return message_from_string(raw_text, policy=default_policy)


def extract_auth_results(msg) -> dict:
    """
    Pulls SPF / DKIM / DMARC verdicts out of Authentication-Results
    and Received-SPF headers. Real mail servers stamp these when the
    message arrives, so we trust (but flag) what's already there.
    """
    auth_header = msg.get("Authentication-Results", "") or ""
    received_spf = msg.get("Received-SPF", "") or ""

    def _extract(pattern, text):
        m = re.search(pattern, text, re.IGNORECASE)
        return m.group(1).lower() if m else "not found"

    spf = _extract(r"spf=(\w+)", auth_header) or _extract(r"^(\w+)", received_spf)
    dkim = _extract(r"dkim=(\w+)", auth_header)
    dmarc = _extract(r"dmarc=(\w+)", auth_header)

    return {
        "spf": spf or "not found",
        "dkim": dkim or "not found",
        "dmarc": dmarc or "not found",
        "raw_authentication_results": auth_header,
    }


def extract_identity_fields(msg) -> dict:
    """From / Reply-To / Return-Path — mismatches here are a classic
    spoofing / BEC (business email compromise) signal."""
    from_addr = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")

    def _domain(addr: str) -> str:
        m = re.search(r"@([\w\.-]+)", addr or "")
        return m.group(1).lower() if m else ""

    from_domain = _domain(from_addr)
    reply_domain = _domain(reply_to)
    return_domain = _domain(return_path)

    mismatch_flags = []
    if reply_domain and reply_domain != from_domain:
        mismatch_flags.append(f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})")
    if return_domain and return_domain != from_domain:
        mismatch_flags.append(f"Return-Path domain ({return_domain}) differs from From domain ({from_domain})")

    return {
        "from": from_addr,
        "reply_to": reply_to,
        "return_path": return_path,
        "from_domain": from_domain,
        "mismatch_flags": mismatch_flags,
    }


def extract_received_chain(msg) -> list:
    """Received headers are stacked newest-first by each hop. We keep
    them in that order and also try to pull an IP out of each one."""
    chain = []
    for header_value in msg.get_all("Received", []):
        ips_found = IP_REGEX.findall(header_value)
        public_ips = [ip for ip in ips_found if not _is_private_ip(ip)]
        chain.append({
            "raw": " ".join(header_value.split()),  # collapse whitespace
            "ips_found": ips_found,
            "public_ips": public_ips,
        })
    return chain


def guess_originating_ip(received_chain: list) -> str:
    """
    Heuristic: the ORIGINATING server is usually the LAST 'Received' header
    in the chain (since each hop prepends its own), and the first public IP
    within it is the best guess at the true source.
    """
    for hop in reversed(received_chain):
        if hop["public_ips"]:
            return hop["public_ips"][0]
    return None


def analyze_headers(msg) -> dict:
    received_chain = extract_received_chain(msg)
    originating_ip = guess_originating_ip(received_chain)

    return {
        "subject": msg.get("Subject", ""),
        "auth_results": extract_auth_results(msg),
        "identity": extract_identity_fields(msg),
        "received_chain_length": len(received_chain),
        "received_chain": received_chain,
        "originating_ip_guess": originating_ip,
    }


def get_body_text(msg) -> str:
    """Pull the plain-text body (falls back to stripped HTML) for the
    AI analysis stage (Week 2)."""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                return part.get_content()
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                html = part.get_content()
                return re.sub("<[^<]+?>", " ", html)
        return ""
    return msg.get_content()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python header_parser.py path/to/email.eml")
        sys.exit(1)

    email_msg = load_email(sys.argv[1])
    result = analyze_headers(email_msg)
    result["body_preview"] = get_body_text(email_msg)[:300]

    print(json.dumps(result, indent=2, default=str))
