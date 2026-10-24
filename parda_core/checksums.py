"""
Parda Checksum Utilities:
1. Luhn Algorithm (Credit Cards, Global Financials)
2. Verhoeff Algorithm (Dihedral D5 Checksum for Aadhaar & Identity)
"""

# --- Luhn Algorithm ---
def validate_luhn(card_number: str) -> bool:
    """Validates credit cards and identifiers using the Luhn mod-10 algorithm."""
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


def generate_luhn(prefix: str) -> str:
    """Computes check digit and returns complete Luhn valid string."""
    digits = [int(c) for c in prefix if c.isdigit()]
    # When calculating check digit, the check digit will be at index 0 (even) of reversed string,
    # so the existing digits will be at odd indices (doubled) starting with the last existing digit.
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 0:
            doubled = d * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += d
    check_digit = (10 - (checksum % 10)) % 10
    return f"{prefix}{check_digit}"


# --- Verhoeff Algorithm ---
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def validate_verhoeff(num_str: str) -> bool:
    """Validate Dihedral D5 Verhoeff checksum."""
    digits = [int(c) for c in num_str if c.isdigit()]
    if not digits:
        return False
    c = 0
    for i, item in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][item]]
    return c == 0


def generate_verhoeff(num_str: str) -> str:
    """Generate and append Verhoeff check digit."""
    digits = [int(c) for c in num_str if c.isdigit()]
    c = 0
    for i, item in enumerate(reversed(digits)):
        c = _D[c][_P[(i + 1) % 8][item]]
    check_digit = _INV[c]
    return f"{num_str}{check_digit}"
