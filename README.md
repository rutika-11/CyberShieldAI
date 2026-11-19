# CYBERSHIELD AI — Expert System for Scam and Phishing Detection

A B.Sc. Computer Science project that detects scam and phishing content using a **rule-based expert system**. It does **not** use machine learning, deep learning, paid APIs, OCR, QR scanning, or chatbot features.

## Project Objective

Build a simple, reliable desktop application that:

- Accepts a URL or a suspected scam message
- Extracts features using rules and pattern matching
- Applies IF-THEN expert-system rules
- Produces a risk score, risk level, explanation, and recommendation

## What an Expert System Is

An expert system is a computer program that copies how a human expert makes decisions. It stores domain knowledge as **IF-THEN rules** and uses an **inference engine** to apply those rules to new cases.

In this project:

1. The **knowledge base** holds phishing and scam indicators.
2. The **inference engine** matches extracted features against those rules.
3. The system explains *why* a result was produced, which is important for a viva and for user trust.

This is not a trained model. The logic is explicit, inspectable, and easy to defend in an examination.

## Planned Knowledge Base

The knowledge base will store facts and indicators used by the rules, for example:

- Suspicious URL patterns (IP address in URL, `@` symbol, extra subdomains)
- Known risky keywords in messages (urgent payment, prize, OTP, account blocked)
- Shortened or misspelled domain clues
- Missing HTTPS / unusual response behaviour
- Combined evidence weights for scoring

These items will be represented as structured rules, not as a neural network.

## Planned IF-THEN Rules

Example rule form (to be implemented later):

- **IF** the URL uses an IP address instead of a domain name **THEN** increase phishing risk.
- **IF** the message contains urgency words such as “act now” or “account will be blocked” **THEN** increase scam risk.
- **IF** the URL contains `@` or many hyphens **THEN** flag a suspicious URL structure.
- **IF** several medium-risk indicators appear together **THEN** raise the overall risk level.

Rules will be transparent so each finding can be explained to the user.

## Planned Inference Engine

The inference engine will:

1. Receive features extracted from the URL or message
2. Evaluate matching IF-THEN rules from the knowledge base
3. Accumulate a numeric risk score from fired rules
4. Map the score to a risk level
5. Return an explanation (which rules fired) and a recommendation

Architecture:

```
Knowledge Base
↓
IF-THEN Rules
↓
Feature Extraction
↓
Inference Engine
↓
Risk Score
↓
Risk Level
↓
Explanation + Recommendation
```

## Planned Risk Assessment

Risk will be a simple, explainable scale, for example:

| Score range | Risk level | Meaning |
|-------------|------------|---------|
| Low | Safe / Low | Few or no indicators matched |
| Medium | Suspicious | Some indicators matched |
| High | High risk | Strong phishing or scam evidence |

The exact thresholds will be defined when scoring is implemented.

## Planned URL Scam Detector

The URL detector will:

- Parse the URL with `urllib`
- Apply regular-expression checks (`re`)
- Optionally check basic website response with `requests`
- Extract features (scheme, host, path, query, suspicious tokens)
- Send features to the inference engine

No OCR, QR scanning, or commercial threat-intelligence APIs will be used.

## Planned Scam Message Detector

The message detector will:

- Accept pasted SMS/email-style text
- Detect keywords and patterns with regular expressions
- Extract features (urgency, money requests, fake brands, links)
- Send features to the same inference engine used by URL analysis

## Technologies Used

| Area | Technology |
|------|------------|
| Language | Python 3.11+ |
| GUI | CustomTkinter |
| Database | SQLite |
| URL parsing | `urllib` (standard library) |
| Pattern detection | `re` (standard library) |
| Website response check | `requests` |
| Password storage | Secure hashing (no plain-text passwords) |

**Not used:** machine learning, deep learning, OpenAI or other paid APIs, OCR, QR scanning, chatbots, complex cybersecurity APIs.

## STEP 2 — Authentication

Step 2 adds a simple, secure login system. Detection features are not implemented yet.

### SQLite database

User accounts are stored in `database/cybershield.db`. The file is created automatically on first run by `initialize_database()` in `database/database.py`. SQLite is used through Python’s built-in `sqlite3` module (no extra database package).

### Users table

| Column | Type | Purpose |
|--------|------|---------|
| `id` | INTEGER PRIMARY KEY AUTOINCREMENT | Unique user number |
| `username` | TEXT UNIQUE NOT NULL | Login name (must be unique) |
| `password_hash` | TEXT NOT NULL | Hashed password only |
| `salt` | TEXT NOT NULL | Random salt used for that user |
| `created_at` | TEXT NOT NULL | UTC timestamp of registration |

### Password hashing

Passwords are never stored in plain text. On registration the program:

1. Generates a random 16-byte salt (`os.urandom`)
2. Hashes the password with `hashlib.pbkdf2_hmac` (SHA-256, 120,000 iterations)
3. Saves only the hex-encoded hash and salt

On login, the same salt and algorithm are used to hash the typed password. Access is granted only if the hashes match.

### Registration

The Register screen asks for username, password, and confirm password. A successful registration stores the user in SQLite, shows a friendly success message, and returns to Login.

### Login

The application starts on the Login screen. Correct credentials open a temporary Welcome dashboard (`Welcome, <username>`). Wrong details show a friendly error without revealing whether the username or password was wrong.

### Logout

Logout returns to the Login screen, clears the username and password fields, and does not close the application.

### Validation

Friendly messages (no Python tracebacks) are shown for:

- Empty username
- Empty password
- Password and confirm password not matching
- Duplicate username
- Incorrect login details
- Successful registration
- Successful login (dashboard)
- Logout (back to login)

## STEP 3 — Expert System Core

Step 3 builds the rule-based engine as a separate Python package. It is **not** connected to the GUI yet. There is no machine learning.

Pipeline:

```
Knowledge Base → Feature Extraction → IF-THEN Rules → Inference Engine
→ Risk Score → Risk Level → Explanation → Recommendation
```

### Knowledge Base

`expert_system/knowledge_base.py` stores the facts used by the rules: suspicious URL keywords, risky TLDs, brand names, message patterns (urgent, prize, OTP, password, PIN, banking, card, payment, threat, links), and the point values for each rule.

### Feature Extraction

`expert_system/feature_extractor.py` inspects text only.

- `extract_url_features(url)` uses `urllib.parse` and `re`. It does **not** open or download the website.
- `extract_message_features(message)` uses regular expressions and keyword lists.

Both functions return a dictionary of features (true/false flags and simple counts).

### IF-THEN Rules

`expert_system/rules.py` lists explicit rules, for example:

- IF the URL does not use HTTPS THEN add 20 points.
- IF the URL uses an IP address THEN add 25 points.
- IF the message requests an OTP THEN add 30 points.

Each fired rule also stores a short English explanation.

### Inference Engine

`expert_system/inference_engine.py` is a simple forward-chaining evaluator: it takes features, tests every rule, adds the points of every rule that matches, and collects explanations. The same input always produces the same score.

### Risk Scoring

`expert_system/risk_engine.py` clamps the total to **0–100**.

### Risk Levels

| Score | Level | Decision |
|------:|-------|----------|
| 0–24 | LOW | Likely Safe |
| 25–49 | MEDIUM | Use Caution |
| 50–74 | HIGH | Likely Suspicious |
| 75–100 | CRITICAL | Likely Scam / Phishing |

### Explainable Results

`CyberShieldExpertSystem` in `expert_system/expert_system.py` exposes `analyze_url()` and `analyze_message()`. The result includes score, risk level, decision, triggered rule names, reasons, and a recommendation.

### Safety Recommendations

- **LOW:** No major scam indicators were detected. Continue to use normal online safety practices.
- **MEDIUM:** Proceed with caution. Verify the sender or website before sharing information.
- **HIGH:** Do not provide personal, banking, OTP, or password information. Verify the source independently.
- **CRITICAL:** Do not interact with the message or website. Do not provide credentials, OTPs, payment information, or personal details.

### Test cases

`test_expert_system.py` runs without the GUI. It checks a normal HTTPS URL, HTTP, suspicious keywords, an IP URL, a long URL, a suspicious TLD, a normal message, and prize, banking, OTP, and payment scam messages.

## STEP 4 — Website Scam Detector

Step 4 connects the existing expert system to the CustomTkinter GUI. It does **not** rebuild the rules. The GUI only collects a URL, validates it, calls `CyberShieldExpertSystem.analyze_url(url)`, and displays the returned result.

In Step 4 the Scam Message Detector was a placeholder. Steps 5 and 6 complete that screen and the final dashboard.

### Website Scam Detector GUI

After login, the dashboard shows:

- **Website Scam Detector** — opens the URL analysis screen
- **Scam Message Detector** — opens the message analysis screen (completed in Steps 5–6)
- **Logout** — returns to the login screen (same behaviour as Step 2)

The detector screen includes a title, a short description, a URL field, **Analyze Website**, and **Back to Dashboard**.

### URL input and validation

The user types a website URL (example placeholder: `https://example.com`). Before analysis:

- Empty input → “Please enter a website URL.”
- Clearly invalid input → “Please enter a valid website URL.”

Accepted examples include `https://example.com`, `http://example.com/login`, and `https://www.example.com/account`. Invalid text does not crash the application.

### Connection with the Expert System

`gui/website_detector.py` calls the existing method:

```
CyberShieldExpertSystem.analyze_url(url)
```

The GUI does not duplicate feature extraction, IF-THEN rules, inference, scoring, or recommendations. Those remain in `expert_system/`.

### Result display

The result card shows values returned by the expert system:

- **Risk score** — `score` out of 100
- **Risk level** — LOW / MEDIUM / HIGH / CRITICAL from `risk_level`
- **Decision** — Likely Safe, Use Caution, Likely Suspicious, or Likely Scam / Phishing
- **Triggered rules** — each fired rule name
- **Reasoning** — human-readable explanations
- **Recommendation** — the safety advice for that risk level

Visual emphasis (colour of the risk card) is based on `result["risk_level"]`, not on a hard-coded URL list.

### Safety behaviour

The detector analyses the URL as text only. It does **not** open a browser, download the site, execute page content, or submit credentials.

While analysis runs, the button shows **Analyzing...** and ignores extra clicks. Unexpected errors show “Unable to analyze this URL. Please check the input and try again.” Tracebacks stay in the terminal, not in the GUI.

### Testing performed

| Test | Input / action | Result |
|------|----------------|--------|
| 1 | `https://www.example.com` | LOW / relatively low risk from existing rules |
| 2 | `http://example.com/login` | HTTP and other applicable Step 3 rules trigger |
| 3 | `http://192.168.1.10/login` | IP-address rule and other applicable rules trigger |
| 4 | `http://example.com/verify-account-login` | Suspicious-keyword rules trigger |
| 5 | Empty input | “Please enter a website URL.” |
| 6 | Invalid URL | “Please enter a valid website URL.” |
| 7 | Login → Dashboard → Website Detector → Back | Navigation works |
| 8 | Login → Dashboard → Logout | Returns to Login |
| 9 | Scam Message Detector | Completed in Steps 5–6 (no longer a placeholder) |

## STEP 5 — Scam Message Detector

Step 5 adds a dedicated GUI screen for pasted SMS/email-style text. It does **not** copy the IF-THEN rules into the GUI. Detection remains a **rule-based expert system**.

### Message analysis

The user pastes a message and clicks **Analyze Message**. The GUI:

1. Reads the text
2. Validates it (empty text is rejected)
3. Calls `CyberShieldExpertSystem.analyze_message(message)`
4. Displays the returned result

The message is analysed locally as text only. It is not sent anywhere, not stored, and not added to scan history.

### Message feature extraction

`extract_message_features(message)` in `expert_system/feature_extractor.py` uses regular expressions and keyword lists from the knowledge base. Typical features include:

- Urgent language
- Payment request
- OTP request
- Password request
- PIN request
- Prize / reward language
- Suspicious links
- Threat / fear language
- Banking context
- Card / payment-card details
- Combined “multiple scam indicators”

### IF-THEN rules

`get_message_rules()` in `expert_system/rules.py` maps each feature to points and an English explanation, for example:

- IF the message contains urgent language THEN add risk points.
- IF the message requests an OTP THEN add risk points.
- IF several scam indicators appear together THEN add extra points.

### Inference engine

`evaluate_rules()` in `expert_system/inference_engine.py` is a forward-chaining evaluator. It tests every message rule against the extracted features, adds the points of every rule that matches, and collects the triggered rule names and reasons. The same input always produces the same score.

### Risk scoring

The GUI never calculates a separate score. `risk_engine.py` clamps the expert-system total to **0–100**, maps it to LOW / MEDIUM / HIGH / CRITICAL, and supplies the decision and safety recommendation. Visual colours in the result card come from `result["risk_level"]`.

### Scam Message Detector GUI

`gui/message_detector.py` provides:

- Title: **Scam Message Detector**
- Description: “Analyze a message using rule-based expert system detection.”
- Large text area with “Enter or paste a suspicious message here...”
- **Analyze Message**
- **Back to Dashboard**

Empty input shows “Please enter a message to analyze.” Unexpected errors show a friendly message; Python tracebacks stay in the terminal, not in the window.

Results use the same card layout as the website detector: risk score, risk level, decision, triggered rules, reasoning, and recommendation.

## STEP 6 — Full Integration & Dashboard

Step 6 finishes the application as a single-window desktop program. There is **no** scan history, no extra database tables, and no user-activity tracking. Only the existing `users` table is used.

### Dashboard

After a successful login the user sees:

- **CYBERSHIELD AI**
- **Expert System for Scam and Phishing Detection**
- Two feature cards: **Website Scam Detector** and **Scam Message Detector**
- **Logout**

The dashboard is a simple demonstration screen: two detectors and logout. It does not add extra tools.

### Navigation

All screens share one application window (frames/views are switched; extra windows are not opened):

```
LOGIN
↓
DASHBOARD
├── Website Scam Detector → Analyze URL → Results → Back to Dashboard
├── Scam Message Detector → Analyze Message → Results → Back to Dashboard
└── Logout → LOGIN
```

### Website detector

The Step 4 Website Scam Detector is unchanged in behaviour: URL input, validation, **Analyze Website**, expert-system results, and **Back to Dashboard**. URLs are never opened, downloaded, or executed.

### Message detector

The Step 5 screen is linked from the dashboard and uses the same expert system as Step 3.

### Authentication

Step 2 SQLite authentication is unchanged:

- Register → Login → Dashboard
- Correct login → Dashboard
- Incorrect login → friendly error
- Logout → Login, with session/user fields cleared

### Explainable results

Both detectors display values returned by the expert system only:

- Which IF-THEN rules fired
- Why they fired (reasoning)
- The mapped risk score and risk level
- A safety recommendation for that level

### Safety recommendations

Recommendations still come from `expert_system/risk_engine.py` (LOW through CRITICAL). The GUI does not invent advice.

## Development Steps

1. **Project setup** — complete.
2. **Database and authentication** — complete.
3. **Expert system core** — complete. Knowledge base, feature extraction, IF-THEN rules, inference engine, risk score/level, recommendations, independent tests.
4. **URL scam detector UI** — complete. Website Scam Detector connected to `analyze_url()`.
5. **Scam message detector UI** — complete. Scam Message Detector connected to `analyze_message()`.
6. **Full integration and dashboard** — complete. Login, dashboard, both detectors, logout, single-window navigation.
