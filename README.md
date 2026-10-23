# Password Security & Breach-Risk Checker

> A Python CLI tool that evaluates password strength using entropy analysis, pattern detection, and real-time breach-database lookup via the Have I Been Pwned (HIBP) API — all with **zero third-party dependencies**.

---

## Table of Contents

- [Project Description](#project-description)
- [Features](#features)
- [Technologies Used](#technologies-used)
- [How It Works](#how-it-works)
- [Setup & Run Instructions](#setup--run-instructions)
- [Project Structure](#project-structure)
- [Dataset / API](#dataset--api)
- [Scoring & Grading](#scoring--grading)
- [Privacy & Security](#privacy--security)
- [Author](#author)

---

## Project Description

The **Password Security & Breach-Risk Checker** is a cybersecurity internship project that helps users evaluate the security of their passwords through multiple layers of analysis:

1. **Entropy Calculation** — Measures unpredictability using Shannon entropy (bits).
2. **Strength Analysis** — Checks length, character variety (uppercase, lowercase, digits, specials), and applies penalties for common passwords, keyboard walks, repeated characters, and sequential patterns.
3. **Breach Database Lookup** — Queries the [Have I Been Pwned](https://haveibeenpwned.com) Pwned Passwords API v3 using the **k-Anonymity** model to check if the password has appeared in any known data breach — without ever sending the full password over the network.
4. **Secure Password Generator** — Generates cryptographically strong random passwords using Python's `secrets` module.

The tool outputs a scored report (0–100), a letter grade (A–F), actionable recommendations, and a final verdict on whether the password should be changed immediately.

---

## Features

| Feature | Description |
|---|---|
| Entropy Analysis | Shannon entropy calculation based on character pool size |
| Pattern Detection | Detects keyboard walks, repeated chars, sequential numbers |
| Common Password Check | Flags passwords from the top-50 most-used list |
| HIBP Breach Check | k-Anonymity API call — password never leaves your device |
| Secure Generator | Cryptographically secure passwords via `secrets` module |
| Colour-Coded CLI | ANSI-coloured terminal output with score bar and grades |
| Zero Dependencies | Runs on pure Python 3.8+ standard library only |

---

## Technologies Used

| Technology | Purpose |
|---|---|
| **Python 3.8+** | Core programming language |
| `re` | Regular expression pattern matching |
| `math` | `log2()` for entropy calculation |
| `hashlib` | SHA-1 hashing for HIBP k-Anonymity |
| `secrets` | Cryptographically secure random password generation |
| `urllib` | HTTP requests to HIBP REST API |
| `getpass` | Secure (hidden) password input in terminal |
| `string` | Character set constants for password generation |
| **HIBP API v3** | Real-time breach database lookup |

---

## How It Works

### Entropy Formula
```
H = L × log₂(pool_size)
```
Where `L` = password length and `pool_size` = size of the character set used (lowercase=26, uppercase=26, digits=10, specials=32).

### k-Anonymity (HIBP)
```
SHA-1(password) → XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
                   ↑↑↑↑↑  ← only these 5 chars are sent
```
The API returns all hashes with that prefix; the client checks for the full suffix **locally**. Your password never leaves your machine.

### Scoring System

| Criterion | Points |
|---|---|
| Length ≥ 16 | +30 |
| Length ≥ 12 | +22 |
| Length ≥ 8 | +12 |
| Each character type (×4) | +10 each |
| Entropy ≥ 80 bits | +20 |
| Entropy ≥ 60 bits | +12 |
| Entropy ≥ 40 bits | +5 |
| Common password | −40 |
| Keyboard walk | −20 |
| Repeated chars | −10 |
| Sequential numbers | −10 |

---

## Setup & Run Instructions

### Prerequisites
- Python **3.8 or higher** installed
- Internet connection (for HIBP breach check — optional)

### Installation

No pip installs required. The project uses only Python's standard library.

```bash
# 1. Clone or download the project
git clone <repository-url>
cd password_checker

# 2. Run directly with Python
python RainyKhandelwal_PasswordChecker.py
```

### Usage

```
+======================================================+
|   [*]  PASSWORD SECURITY & BREACH-RISK CHECKER       |
|            Cybersecurity Internship Project           |
|                  Author: Rainy Khandelwal             |
+======================================================+

Options:
  [1] Check a password
  [2] Generate strong passwords
  [3] About this tool
  [Q] Quit
```

- **Option 1** — Enter any password (input is hidden). The tool will analyse strength and optionally check the breach database.
- **Option 2** — Generate 4 cryptographically secure passwords of increasing length.
- **Option 3** — Display tool information and privacy details.

---

## Project Structure

```
password_checker/
├── RainyKhandelwal_PasswordChecker.py   # Main project code
├── requirements.txt                      # Dependencies (stdlib only)
├── README.md                             # This file
└── RainyKhandelwal_ProjectReport.docx   # Full project documentation
```

---

## Dataset / API

This project does **not** use a local dataset. It relies on the live **Have I Been Pwned Pwned Passwords API v3**:

- **API Endpoint:** `https://api.pwnedpasswords.com/range/{first5HashChars}`
- **Documentation:** [https://haveibeenpwned.com/API/v3#PwnedPasswords](https://haveibeenpwned.com/API/v3#PwnedPasswords)
- **Data Source:** Troy Hunt's aggregated breach database containing **over 800 million** compromised passwords
- **Privacy Model:** k-Anonymity — only 5 characters of the SHA-1 hash are transmitted

The internal common-password list is a hardcoded set of the top 50 most frequently used passwords (no external file needed).

---

## Scoring & Grading

| Score Range | Grade | Verdict |
|---|---|---|
| 85 – 100 | **A** | STRONG — Excellent password security |
| 70 – 84 | **B** | GOOD — Reasonably strong |
| 50 – 69 | **C** | MODERATE — Could be stronger |
| 30 – 49 | **D** | WEAK — Needs significant improvement |
| 0 – 29 | **F** | VERY WEAK — Replace immediately |

---

## Privacy & Security

- The **full password never leaves your machine**
- Only the first **5 characters** of its SHA-1 hash are sent to the HIBP API
- The breach check is entirely **optional** (can be skipped per session)
- Password input uses `getpass` to prevent screen display

---

## Author

**Rainy Khandelwal**  
Cybersecurity Internship Project  
Tool Version: 1.0 | Language: Python 3.8+
