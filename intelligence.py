import re
import logging
from typing import List
from models import ExtractedIntelligence

logger = logging.getLogger(__name__)

# ── Pre-compiled patterns ──────────────────────────────────────────────

# Phone: 10-digit Indian numbers (optionally prefixed with +91 or 91)
PHONE_PATTERN = re.compile(r'(?:\+91|91)?[6-9]\d{9}')

# Bank account: 9-18 digit numeric strings (standalone)
BANK_ACCOUNT_PATTERN = re.compile(r'\b\d{9,18}\b')

# UPI: name@bankhandle (specific Indian UPI handles)
UPI_HANDLES = (
    'ybl|paytm|oksbi|okaxis|okicici|okhdfcbank|upi|apl|axl|ibl|sbi|'
    'icici|hdfcbank|axisbank|kotak|indus|federal|barodampay|mahb|'
    'canbk|pnb|unionbank|dbs|rbl|yes|idbi|hsbc|sc|citi|bob|'
    'indianbank|iob|centralbank|allbank|pingpay|gpay|freecharge|'
    'airtel|jio|slice|jupiteraxis|postbank|dlb|kvb|kbl|'
    'abfspay|ratn|aubank|equitas|bandhan|boi|syndicate|uco|nsdl'
)
UPI_PATTERN = re.compile(
    r'[a-zA-Z0-9._\-]+@(?:' + UPI_HANDLES + r')\b',
    re.IGNORECASE
)

# Email: standard email pattern (not UPI)
EMAIL_PATTERN = re.compile(
    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
)

# Phishing links: http/https URLs
URL_PATTERN = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')


# ── Extractors ─────────────────────────────────────────────────────────

def extract_phone_numbers(text: str) -> List[str]:
    """Extract Indian phone numbers (10-digit, starting 6-9)."""
    raw = PHONE_PATTERN.findall(text)
    result = set()
    for m in raw:
        # Normalize: strip prefix, keep raw 10-digit
        digits = m.lstrip('+')
        if digits.startswith('91') and len(digits) == 12:
            digits = digits[2:]
        if len(digits) == 10:
            result.add(digits)
            result.add('+91' + digits)
    return list(result)


def extract_bank_accounts(text: str) -> List[str]:
    """Extract bank account numbers (9-18 digits), excluding phone numbers."""
    matches = BANK_ACCOUNT_PATTERN.findall(text)
    phones = set(extract_phone_numbers(text))
    # Also build set of raw 10-digit phone numbers for filtering
    phone_digits = set()
    for p in phones:
        d = p.lstrip('+')
        if d.startswith('91'):
            d = d[2:]
        phone_digits.add(d)

    filtered = []
    for m in matches:
        # Skip if this looks like a phone number (10 digits starting 6-9)
        if len(m) == 10 and m[0] in '6789':
            continue
        # Skip 12-digit phone numbers with 91 country code
        if len(m) == 12 and m.startswith('91') and m[2] in '6789':
            continue
        if m in phone_digits:
            continue
        # Skip timestamps (13-digit ms timestamps)
        if len(m) == 13 and m.startswith('1'):
            continue
        filtered.append(m)
    return list(set(filtered))


def extract_upi_ids(text: str) -> List[str]:
    """Extract UPI IDs (name@bankhandle)."""
    return list(set(UPI_PATTERN.findall(text)))


def extract_phishing_links(text: str) -> List[str]:
    """Extract suspicious URLs."""
    return list(set(URL_PATTERN.findall(text)))


def extract_email_addresses(text: str) -> List[str]:
    """Extract email addresses, excluding UPI IDs."""
    all_emails = set(EMAIL_PATTERN.findall(text))
    upi_ids = set(extract_upi_ids(text))
    # Remove any email that is also a UPI ID
    return list(all_emails - upi_ids)


def extract_all_intelligence(text: str, existing: ExtractedIntelligence = None) -> ExtractedIntelligence:
    """Extract all intelligence from text and optionally merge with existing."""
    new_intel = ExtractedIntelligence(
        phoneNumbers=extract_phone_numbers(text),
        bankAccounts=extract_bank_accounts(text),
        upiIds=extract_upi_ids(text),
        phishingLinks=extract_phishing_links(text),
        emailAddresses=extract_email_addresses(text),
    )

    if existing:
        return ExtractedIntelligence(
            phoneNumbers=list(set(existing.phoneNumbers + new_intel.phoneNumbers)),
            bankAccounts=list(set(existing.bankAccounts + new_intel.bankAccounts)),
            upiIds=list(set(existing.upiIds + new_intel.upiIds)),
            phishingLinks=list(set(existing.phishingLinks + new_intel.phishingLinks)),
            emailAddresses=list(set(existing.emailAddresses + new_intel.emailAddresses)),
        )

    return new_intel


def extract_from_conversation(messages: List[dict]) -> ExtractedIntelligence:
    """Extract intelligence from entire conversation history."""
    intel = ExtractedIntelligence()
    for msg in messages:
        text = msg.get("text", "")
        intel = extract_all_intelligence(text, intel)
    return intel
