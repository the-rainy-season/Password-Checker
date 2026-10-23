"""
PASSWORD SECURITY & BREACH-RISK CHECKER
Cybersecurity Internship Project
Uses: Entropy Analysis + HIBP API + Pattern Detection
"""

import re
import math
import hashlib
import string
import secrets
import urllib.request
import urllib.error
import sys
import getpass
from typing import Tuple

# Force UTF-8 on Windows so the terminal won't mangle special characters
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ──────────────────────────────────────────────
#  ANSI colour helpers
# ──────────────────────────────────────────────
RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
DIM     = "\033[2m"

def color(text: str, *codes: str) -> str:
    return "".join(codes) + text + RESET


# ──────────────────────────────────────────────
#  Common weak passwords (top ~50)
# ──────────────────────────────────────────────
COMMON_PASSWORDS = {
    "password", "password1", "123456", "12345678", "1234", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
    "master", "sunshine", "ashley", "bailey", "passw0rd", "shadow", "123123",
    "654321", "superman", "qazwsx", "michael", "football", "mustang", "access",
    "696969", "123456789", "batman", "admin", "pass", "login", "welcome",
    "hello", "charlie", "donald", "password123", "qwerty123", "1q2w3e4r",
    "1qaz2wsx", "zxcvbnm", "asdfghjkl", "summer", "winter", "spring", "autumn",
}

# Keyboard walk patterns
KEYBOARD_WALKS = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
    "1qaz2wsx", "qazwsx", "1234567890", "0987654321", "poiuytrewq",
]


# ──────────────────────────────────────────────
#  1. ENTROPY CALCULATOR
# ──────────────────────────────────────────────
def calculate_entropy(password: str) -> float:
    """Shannon entropy in bits: H = L * log2(pool_size)"""
    pool = 0
    if re.search(r"[a-z]", password): pool += 26
    if re.search(r"[A-Z]", password): pool += 26
    if re.search(r"\d",    password): pool += 10
    if re.search(r'[ !"#$%&\'()*+,\-./:;<=>?@\[\\\]^_`{|}~]', password): pool += 32
    pool = pool or 26
    return len(password) * math.log2(pool)


# ──────────────────────────────────────────────
#  2. STRENGTH ANALYSER
# ──────────────────────────────────────────────
def analyse_strength(password: str) -> dict:
    """Return a detailed strength report dictionary."""
    results = {
        "length"     : len(password),
        "has_upper"  : bool(re.search(r"[A-Z]", password)),
        "has_lower"  : bool(re.search(r"[a-z]", password)),
        "has_digit"  : bool(re.search(r"\d",    password)),
        "has_special": bool(re.search(r"[^A-Za-z0-9]", password)),
        "entropy"    : round(calculate_entropy(password), 2),
        "issues"     : [],
        "score"      : 0,   # 0-100
        "grade"      : "",  # A/B/C/D/F
    }

    score = 0

    # --- Length scoring ---
    if results["length"] >= 16:
        score += 30
    elif results["length"] >= 12:
        score += 22
    elif results["length"] >= 8:
        score += 12
    else:
        results["issues"].append("Password is too short (minimum 8 characters recommended)")

    # --- Character variety ---
    variety = sum([results["has_upper"], results["has_lower"],
                   results["has_digit"], results["has_special"]])
    score += variety * 10

    if not results["has_upper"]:
        results["issues"].append("Add UPPERCASE letters (A-Z)")
    if not results["has_lower"]:
        results["issues"].append("Add lowercase letters (a-z)")
    if not results["has_digit"]:
        results["issues"].append("Add digits (0-9)")
    if not results["has_special"]:
        results["issues"].append("Add special characters  e.g. !@#$%^&*()")

    # --- Entropy bonus ---
    if results["entropy"] >= 80:
        score += 20
    elif results["entropy"] >= 60:
        score += 12
    elif results["entropy"] >= 40:
        score += 5
    else:
        results["issues"].append(
            f"Low entropy ({results['entropy']} bits) - password is highly predictable"
        )

    # --- Pattern penalties ---
    lower_pw = password.lower()

    if lower_pw in COMMON_PASSWORDS:
        score -= 40
        results["issues"].append("[!] This is one of the most COMMONLY USED passwords!")

    for walk in KEYBOARD_WALKS:
        if walk in lower_pw:
            score -= 20
            results["issues"].append(f"[!] Keyboard walk pattern detected: '{walk}'")
            break

    if re.search(r"(.)\1{2,}", password):
        score -= 10
        results["issues"].append("[!] Repeated character sequence detected (e.g. 'aaa')")

    if re.search(r"(012|123|234|345|456|567|678|789|890|987|876|765|654|543|432|321|210)", password):
        score -= 10
        results["issues"].append("[!] Sequential number pattern detected (e.g. '123')")

    # --- Clamp and grade ---
    score = max(0, min(100, score))
    results["score"] = score

    if score >= 85:
        results["grade"] = "A"
    elif score >= 70:
        results["grade"] = "B"
    elif score >= 50:
        results["grade"] = "C"
    elif score >= 30:
        results["grade"] = "D"
    else:
        results["grade"] = "F"

    return results


# ──────────────────────────────────────────────
#  3. HAVE I BEEN PWNED  (k-Anonymity API)
# ──────────────────────────────────────────────
def check_hibp(password: str) -> Tuple[bool, int]:
    """
    Query the HIBP Pwned Passwords v3 API using k-Anonymity.
    Only the first 5 hex chars of the SHA-1 hash are sent over the
    network. The full password NEVER leaves the local machine.
    Returns: (found: bool | None, count: int)
      - None  -> API unreachable
      - True  -> password found in breaches, count = occurrence count
      - False -> password not found
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PasswordChecker/1.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            body = resp.read().decode("utf-8")
        for line in body.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return True, int(count)
        return False, 0
    except urllib.error.URLError:
        return None, 0


# ──────────────────────────────────────────────
#  4. SECURE PASSWORD GENERATOR
# ──────────────────────────────────────────────
def generate_password(length: int = 16) -> str:
    """Generate a cryptographically secure random password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.isupper() for c in pwd) and
                any(c.islower() for c in pwd) and
                any(c.isdigit() for c in pwd) and
                any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pwd)):
            return pwd


# ──────────────────────────────────────────────
#  5. DISPLAY HELPERS
# ──────────────────────────────────────────────
BANNER = (
    f"\n{CYAN}{BOLD}"
    "+======================================================+\n"
    "|   [*]  PASSWORD SECURITY & BREACH-RISK CHECKER       |\n"
    "|            Cybersecurity Internship Project           |\n"
    "+======================================================+"
    f"{RESET}\n"
)


def print_banner():
    print(BANNER)


def print_section(title: str):
    print(f"\n{CYAN}{BOLD}{'-'*54}{RESET}")
    print(f"{CYAN}{BOLD}  {title}{RESET}")
    print(f"{CYAN}{BOLD}{'-'*54}{RESET}")


def score_bar(score: int, width: int = 30) -> str:
    filled = int(score / 100 * width)
    bar = "#" * filled + "." * (width - filled)
    c = GREEN if score >= 70 else (YELLOW if score >= 40 else RED)
    return f"{c}[{bar}]{RESET} {BOLD}{score}/100{RESET}"


def grade_color(grade: str) -> str:
    colors = {"A": GREEN, "B": CYAN, "C": YELLOW, "D": YELLOW, "F": RED}
    return color(f" {grade} ", BOLD, colors.get(grade, WHITE))


def print_strength_report(report: dict, password: str):
    print_section("STRENGTH ANALYSIS")

    if len(password) > 4:
        masked = password[:2] + "*" * (len(password) - 4) + password[-2:]
    else:
        masked = "****"

    print(f"  Password  : {DIM}{masked}{RESET}")
    print(f"  Length    : {BOLD}{report['length']}{RESET} characters")
    print(f"  Entropy   : {BOLD}{report['entropy']}{RESET} bits")

    def flag(label, ok):
        return color(f"{label} YES", GREEN) if ok else color(f"{label} NO ", RED)

    flags = [
        flag("A-Z", report["has_upper"]),
        flag("a-z", report["has_lower"]),
        flag("0-9", report["has_digit"]),
        flag("!@#", report["has_special"]),
    ]
    print(f"  Char sets : {' | '.join(flags)}")
    print(f"\n  Score     : {score_bar(report['score'])}")
    print(f"  Grade     : {grade_color(report['grade'])}")

    if report["issues"]:
        print(f"\n  {YELLOW}{BOLD}Recommendations:{RESET}")
        for issue in report["issues"]:
            print(f"    {YELLOW}>>{RESET} {issue}")
    else:
        print(f"\n  {GREEN}[OK] No issues detected. This is a strong password!{RESET}")


def print_breach_report(found, count: int):
    print_section("BREACH DATABASE CHECK  (Have I Been Pwned)")
    print(f"  {DIM}Using k-Anonymity -- your password is NEVER sent over the network.{RESET}")

    if found is None:
        print(f"\n  {YELLOW}[!] Could not reach the HIBP API (check your internet connection).{RESET}")
    elif found:
        print(f"\n  {RED}{BOLD}[X] PWNED!  This password appeared {count:,} time(s) in known data breaches.{RESET}")
        print(f"  {RED}      >> DO NOT use this password anywhere. Change it immediately!{RESET}")
    else:
        print(f"\n  {GREEN}{BOLD}[OK] Not found in any known breach database.{RESET}")
        print(f"  {DIM}  (This does not guarantee safety -- always use unique passwords per site.){RESET}")


def print_suggestions(base_length: int = 16):
    print_section("SUGGESTED STRONG PASSWORDS")
    print(f"  {DIM}Cryptographically generated -- store in a password manager.{RESET}\n")
    for i in range(4):
        pwd = generate_password(base_length + i * 2)
        print(f"  {GREEN}{i + 1}.{RESET} {BOLD}{pwd}{RESET}  {DIM}({len(pwd)} chars){RESET}")


# ──────────────────────────────────────────────
#  6. MAIN CLI FLOW
# ──────────────────────────────────────────────
def run_checker():
    print_banner()

    while True:
        print(f"\n{WHITE}{BOLD}Options:{RESET}")
        print(f"  {CYAN}[1]{RESET} Check a password")
        print(f"  {CYAN}[2]{RESET} Generate strong passwords")
        print(f"  {CYAN}[3]{RESET} About this tool")
        print(f"  {CYAN}[Q]{RESET} Quit")

        choice = input(f"\n{BOLD}>> Choose an option: {RESET}").strip().lower()

        if choice == "1":
            _check_password_flow()
        elif choice == "2":
            try:
                length = int(input(f"\n{BOLD}Desired password length (default 16): {RESET}").strip() or "16")
            except ValueError:
                length = 16
            print_suggestions(max(12, length))
        elif choice == "3":
            _print_about()
        elif choice in ("q", "quit", "exit"):
            print(f"\n{CYAN}Stay secure! Goodbye.{RESET}\n")
            break
        else:
            print(f"{YELLOW}  Invalid option, try again.{RESET}")


def _check_password_flow():
    print(f"\n{DIM}  (Input is hidden -- your password will not be displayed on screen){RESET}")
    try:
        password = getpass.getpass(f"  {BOLD}Enter password to check: {RESET}")
    except Exception:
        password = input(f"  {BOLD}Enter password to check: {RESET}")

    if not password:
        print(f"{YELLOW}  No password entered.{RESET}")
        return

    report = analyse_strength(password)
    print_strength_report(report, password)

    ask = input(f"\n  {BOLD}Check against breach database? (y/n) [y]: {RESET}").strip().lower()
    found, count = None, 0
    if ask in ("", "y", "yes"):
        print(f"\n  {DIM}Querying HIBP API...{RESET}", end="", flush=True)
        found, count = check_hibp(password)
        print("\r" + " " * 40 + "\r", end="")
        print_breach_report(found, count)

    _print_verdict(report, found, count)


def _print_verdict(report: dict, found, count: int):
    print_section("FINAL VERDICT")
    grade  = report["grade"]
    score  = report["score"]
    pwned  = found is True

    if pwned:
        verdict = color("  [X] CRITICAL RISK  --  Password is BREACHED", RED, BOLD)
    elif grade == "F" or score < 30:
        verdict = color("  [X] VERY WEAK  --  Replace this password immediately", RED, BOLD)
    elif grade == "D":
        verdict = color("  [!] WEAK  --  Password needs significant improvement", YELLOW, BOLD)
    elif grade == "C":
        verdict = color("  [!] MODERATE  --  Could be stronger", YELLOW, BOLD)
    elif grade == "B":
        verdict = color("  [OK] GOOD  --  Password is reasonably strong", GREEN, BOLD)
    else:
        verdict = color("  [OK] STRONG  --  Excellent password security", GREEN, BOLD)

    print(verdict)

    if pwned or grade in ("D", "F"):
        print(f"\n  {CYAN}>> Run option [2] to generate a strong replacement.{RESET}")


def _print_about():
    print_section("ABOUT THIS TOOL")
    info = [
        ("Tool",       "Password Security & Breach-Risk Checker"),
        ("Author",     "Cybersecurity Internship Project"),
        ("Techniques", "Entropy Analysis, Pattern Detection, HIBP k-Anonymity"),
        ("HIBP API",   "https://haveibeenpwned.com/API/v3"),
        ("Privacy",    "Only first 5 SHA-1 chars sent -- password never leaves device"),
        ("Language",   "Python 3.8+  (stdlib only, zero pip installs needed)"),
    ]
    for k, v in info:
        print(f"  {CYAN}{BOLD}{k:<12}{RESET}: {v}")


# ──────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────
if __name__ == "__main__":
    try:
        run_checker()
    except KeyboardInterrupt:
        print(f"\n\n{CYAN}Interrupted. Stay secure!{RESET}\n")
        sys.exit(0)