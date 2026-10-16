"""
PII Redaction Engine (FR-5)
Complies with UK GDPR / data-minimisation requirements.
Detects and redacts personal data (emails, phone numbers, IP/MAC addresses,
passwords/credentials, and names) before external model or LLM calls.
"""
from typing import Dict, List, Tuple, Any
import re

# RFC-5322 compliant practical email regex
EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b",
    re.IGNORECASE
)

# UK and international phone formats (e.g. +44 7911 123456, 07123 456789, 020 7946 0991, (0161) 496 0123)
PHONE_REGEX = re.compile(
    r"(?:(?:\+44\s?\(0\)\s?\d{2,4}|\+44\s?\d{2,4}|0\d{2,4})\s?\d{3,4}\s?\d{3,4}|\b\+?[1-9]\d{1,2}[-.\s]?(?:\(\d{1,4}\)|\d{1,4})[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b)"
)

# IPv4 address regex (including standard private & public ranges)
IPV4_REGEX = re.compile(
    r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# IPv6 address regex
IPV6_REGEX = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|\b::(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}\b"
)

# MAC address regex
MAC_REGEX = re.compile(
    r"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b"
)

# Passwords, tokens, API keys, and sensitive credentials
PASSWORD_REGEX = re.compile(
    r"(?:(?:temporary\s+)?password(?:[\s:=]+|[\s]+is[\s:=]+)|pwd(?:[\s:=]+|[\s]+is[\s:=]+)|passphrase(?:[\s:=]+|[\s]+is[\s:=]+)|credentials?(?:[\s:=]+|[\s]+are[\s:=]+)|api[_-]?key(?:[\s:=]+|[\s]+is[\s:=]+)|token(?:[\s:=]+|[\s]+is[\s:=]+))([^\s,;]+)",
    re.IGNORECASE
)

# Name detection heuristics for service desk tickets (greetings, signoffs, new starters, user accounts)
NAME_OPENERS = re.compile(
    r"^(?:hi|hello|dear|good\s+morning|good\s+afternoon)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)[,\s]",
    re.IGNORECASE | re.MULTILINE
)

NAME_SIGNOFFS = re.compile(
    r"(?:thanks|thank\s+you|regards|kind\s+regards|best\s+regards|cheers|best)[,\s\n]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s*$",
    re.IGNORECASE | re.MULTILINE
)

NAME_CONTEXTUAL = re.compile(
    r"(?:new\s+starter|user|employee|contractor|colleague|for|account\s+for)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b"
)

# Common IT words to exclude from accidental name redactions
COMMON_IT_TERMS = {
    "Laptop", "Outlook", "Windows", "Office", "Teams", "Azure", "SharePoint", "Excel",
    "Word", "PowerPoint", "Printer", "Internet", "Wifi", "Vpn", "Network", "Server",
    "Computer", "Monitor", "Password", "Mfa", "Authenticator", "Backup", "Security",
    "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday",
    "January", "February", "March", "April", "May", "June", "July", "August",
    "September", "October", "November", "December", "Support", "Service", "Desk", "Team",
    "Please", "Thanks", "Urgent", "Help", "Hello", "Dear", "Good", "Error", "Issue", "Problem"
}


class RedactionResult:
    """Stores sanitized text, mapping table, and audit statistics."""
    def __init__(self, sanitized_text: str, mapping: Dict[str, str], counts: Dict[str, int]):
        self.sanitized_text = sanitized_text
        self.mapping = mapping  # placeholder -> original value
        self.counts = counts    # entity_type -> count

    @property
    def has_pii(self) -> bool:
        return sum(self.counts.values()) > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sanitized_text": self.sanitized_text,
            "has_pii": self.has_pii,
            "counts": self.counts,
            "redacted_items_count": len(self.mapping)
        }


class RedactionEngine:
    """
    Detects and sanitizes PII/credentials from ticket texts.
    Ensures safe handling before sending ticket content to external LLMs.
    """
    def __init__(self):
        pass

    def redact(self, text: str) -> RedactionResult:
        mapping: Dict[str, str] = {}
        counts: Dict[str, int] = {
            "email": 0,
            "phone": 0,
            "ip": 0,
            "mac": 0,
            "password": 0,
            "name": 0
        }

        sanitized = text

        # 1. Passwords / Credentials (must redact first to protect credential values)
        def _replace_pwd(match):
            pwd_val = match.group(1)
            full = match.group(0)
            token = f"[PASSWORD_REDACTED]"
            mapping[token] = pwd_val
            counts["password"] += 1
            return full.replace(pwd_val, token)

        sanitized = PASSWORD_REGEX.sub(_replace_pwd, sanitized)

        # 2. Email Addresses
        def _replace_email(match):
            val = match.group(0)
            counts["email"] += 1
            token = f"[EMAIL_{counts['email']}]"
            mapping[token] = val
            return token

        sanitized = EMAIL_REGEX.sub(_replace_email, sanitized)

        # 3. IP Addresses (IPv4 and IPv6)
        def _replace_ip(match):
            val = match.group(0)
            counts["ip"] += 1
            token = f"[IP_ADDRESS_{counts['ip']}]"
            mapping[token] = val
            return token

        sanitized = IPV4_REGEX.sub(_replace_ip, sanitized)
        sanitized = IPV6_REGEX.sub(_replace_ip, sanitized)

        # 4. MAC Addresses
        def _replace_mac(match):
            val = match.group(0)
            counts["mac"] += 1
            token = f"[MAC_ADDRESS_{counts['mac']}]"
            mapping[token] = val
            return token

        sanitized = MAC_REGEX.sub(_replace_mac, sanitized)

        # 5. Phone numbers
        def _replace_phone(match):
            val = match.group(0).strip()
            # Avoid replacing simple small digit sequences or dates
            if len(re.sub(r"\D", "", val)) < 7:
                return match.group(0)
            counts["phone"] += 1
            token = f"[PHONE_{counts['phone']}]"
            mapping[token] = val
            return token

        sanitized = PHONE_REGEX.sub(_replace_phone, sanitized)

        # 6. Personal Names (Greetings, Signoffs, Contextual)
        def _replace_name(match):
            full_match = match.group(0)
            val = match.group(1).strip()
            # Filter out common false positives
            parts = val.split()
            if any(p in COMMON_IT_TERMS for p in parts):
                return full_match
            counts["name"] += 1
            token = f"[NAME_{counts['name']}]"
            mapping[token] = val
            return full_match.replace(val, token)

        sanitized = NAME_OPENERS.sub(_replace_name, sanitized)
        sanitized = NAME_SIGNOFFS.sub(_replace_name, sanitized)
        sanitized = NAME_CONTEXTUAL.sub(_replace_name, sanitized)

        return RedactionResult(sanitized, mapping, counts)

    @staticmethod
    def rehydrate(text: str, mapping: Dict[str, str]) -> str:
        """
        Safely restores redacted placeholders back to their original values
        for internal engineer inspection or approved dispatch.
        """
        rehydrated = text
        for placeholder, original in mapping.items():
            rehydrated = rehydrated.replace(placeholder, original)
        return rehydrated
