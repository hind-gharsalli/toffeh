# Team B Source Credibility

A FastAPI-based source credibility analysis service.

The system evaluates a source from a domain or URL and combines multiple signals into a final credibility verdict:
- WHOIS registration analysis
- DNS history and live DNS fallback
- SSL/TLS certificate analysis
- IP geolocation
- HTTP security headers
- Optional username reputation lookup
- Optional stylometric consistency analysis

## What This Project Does

The API returns:
- `trust_score`
- `risk_level`
- `trust_status`
- `recommendation`
- detailed component breakdowns
- consolidated flags and summary text

The goal is not to "prove truth", but to help identify infrastructure red flags, suspicious patterns, and low-confidence cases that deserve further review.

## New Feature Added

This version includes an optional stylometric analysis module.

If you provide:
- `current_text`
- `historical_texts`

the service compares writing-style patterns between the current text and a source's historical writing.

It checks signals such as:
- average sentence length
- average word length
- lexical diversity
- punctuation density
- function-word ratio

A large stylistic shift can be a useful red flag for:
- bot takeover
- ghostwriting
- coordinated inauthentic behavior
- abrupt editorial voice changes

## Tech Stack

- Python 3.12
- FastAPI
- Pydantic
- httpx
- pytest

## Project Structure

```text
.
|-- main.py
|-- models.py
|-- requirements.txt
|-- services/
|   |-- orchestrator.py
|   |-- whois_service.py
|   |-- dns_history_service.py
|   |-- ssl_certificate_service.py
|   |-- ip_geolocation_service.py
|   |-- security_headers_service.py
|   |-- user_reputation_service.py
|   |-- stylometric_service.py
|-- tests/
|   |-- test_team_b.py
```

## Installation

```powershell
cd "xxxxxx\team-b-source-credibility-main"
python -m pip install -r requirements.txt
```

## Run The API

```powershell
python main.py
```

The API starts on:

- `http://127.0.0.1:8002`

Useful endpoints:
- `http://127.0.0.1:8002/`
- `http://127.0.0.1:8002/health`
- `http://127.0.0.1:8002/docs`
- `http://127.0.0.1:8002/api/docs/scoring`

## Example Request

### Basic domain analysis

```json
{
  "domain": "bbc.com"
}
```

### URL-based analysis

```json
{
  "url": "https://example.com/article"
}
```

### Stylometric analysis example

```json
{
  "domain": "example.com",
  "current_text": "BREAKING!!! This shocking event proves the system is collapsing. Everyone must share this immediately before it is deleted. Nobody can wait and nobody can trust official explanations anymore.",
  "historical_texts": [
    "Our newsroom verifies each claim with primary documents and official data before publication. We prioritize accuracy and context in every report.",
    "We cite original studies, interview relevant experts, and compare official statements with independent reporting before drawing conclusions.",
    "Each published piece follows an editorial review process focused on evidence, sourcing quality, and factual consistency."
  ]
}
```

## PowerShell Testing

### Basic test

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8002/api/analyze-source" -ContentType "application/json" -Body '{"domain":"bbc.com"}' | ConvertTo-Json -Depth 10
```

### Stylometric test

```powershell
$body = @'
{
  "domain": "example.com",
  "current_text": "BREAKING!!! This shocking event proves the system is collapsing. Everyone must share this immediately before it is deleted. Nobody can wait and nobody can trust official explanations anymore.",
  "historical_texts": [
    "Our newsroom verifies each claim with primary documents and official data before publication. We prioritize accuracy and context in every report.",
    "We cite original studies, interview relevant experts, and compare official statements with independent reporting before drawing conclusions.",
    "Each published piece follows an editorial review process focused on evidence, sourcing quality, and factual consistency."
  ]
}
'@

Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8002/api/analyze-source" -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 10
```

## Input Validation And Safety

The service now:
- normalizes `domain` values
- accepts URL-like input in `domain`
- rejects invalid hosts
- rejects `localhost`
- rejects internal/private IPs
- rejects mismatched `url` and `domain`

## Scoring Notes

The final verdict is based on:
- component risk scores
- component statuses
- coverage penalties when too many analyses are `UNKNOWN`

This means the system no longer treats missing evidence as proof of trust.

So a source may return:
- `VERIFIED` when multiple checks complete cleanly
- `SUSPICIOUS` when several moderate concerns appear
- `UNKNOWN` when too many external checks fail or data is incomplete

## Testing

```powershell
python -m pytest -q
```

Current result after the latest changes:

- `21 passed`

## Limitations

- Some checks rely on external services and internet access
- A domain can look technically clean and still publish misleading content
- Stylometric analysis is a useful signal, not proof of authorship
- Small text samples reduce stylometric reliability

## Repository Goal

This project is designed as a practical credibility-assessment backend that can be extended with additional signals such as:
- posting pattern analysis
- topical drift detection
- citation graph analysis
- coordinated behavior detection
