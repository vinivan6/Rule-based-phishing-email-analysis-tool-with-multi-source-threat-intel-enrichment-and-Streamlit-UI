# Rule-based Phishing Email Analysis Tool with Multi-Source Threat Intel Enrichment and Streamlit UI

A Python and FastAPI-based cybersecurity application that analyzes suspicious emails and produces a structured phishing risk assessment using rule-based detection, threat-intelligence enrichment, semantic classification, and decision logic.

## Features

- Analyze emails through a FastAPI backend
- Use Streamlit as a simple front-end interface
- Support manual email input
- Support `.eml` email upload
- Extract artifacts such as:
  - URLs
  - domains
  - IP addresses
  - attachment names
  - phone numbers
  - monetary amounts
- Detect phishing indicators such as:
  - urgency
  - credential requests
  - suspicious URLs
  - lookalike domains
  - reply-to mismatch
  - SPF/DKIM failures
  - job scam patterns
  - help desk scam patterns
  - extortion / blackmail patterns
- Enrich results using external reputation sources:
  - VirusTotal
  - URLhaus
  - AbuseIPDB
  - AlienVault OTX
- Classify email semantics into categories such as:
  - newsletter_marketing
  - credential_phishing
  - extortion_blackmail
  - job_scam
  - helpdesk_support_scam
  - uncertain
- Produce:
  - verdict
  - confidence
  - reasons
  - indicators
  - artifacts
  - reputation summary
  - recommended action

## Screenshots

### Home Page
![UI Homepage](docs/images/UI_Homepage.png)

### Manual Entry
![UI Manual Entry](docs/images/UI_Homepage_manualEntry.png)

### Example Results
![UI Analysis Result 1](docs/images/UI_Analysis_result1.png)
![UI Analysis Result 2](docs/images/UI_Analysis_result2.png)
![UI Analysis Result 3](docs/images/UI_Analysis_result3.png)

## Architecture

```text
User Input / .eml Upload
        ↓
Email Parsing
        ↓
Artifact Extraction
        ↓
Rule-Based Analysis
        ↓
Threat-Intelligence Enrichment
        ↓
Semantic Classification
        ↓
Decision Engine
        ↓
Final Verdict + Recommended Action
```
## Known Limitations
- `.msg` not supported yet
- LLM explanation not integrated yet
- Threat-intel feeds can produce occasional noisy results
- IP extraction from complex headers may still include noisy but syntactically valid IP-like values