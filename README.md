# ECDAT — Enterprise Cryptographic Discovery & Analysis Tool
SIH 2026 · Problem Statement SIH26164 · NTRO

## Pipeline
Scanner Output → Classify Artefacts → Generate CBOM → Calculate Risk → Recommendations → Store in DB

## Team & Structure
- `scanner/` — Part 1: Discovery engine (Vaishnavi) — initial Python/Java/C version built by Snigdha as a starting point; now also includes certificate analysis (via OpenSSL), Dockerfile scanning, and container image scanning
- `cbom/` — Part 2: CBOM generation, classification, dedup, pattern recognition, recommendations (Snigdha) — **complete**
- `risk_engine/` — Part 3: Mosca's theorem, risk scoring (Samridhi) — coming soon
- `backend/` — Part 4: API + MongoDB (Mansi) — coming soon
- `frontend/` — Part 5: Dashboard/GUI (Antriksha & Anisha) — coming soon
- `sample_output/` — Example scanner and CBOM output for reference

## Requirements
- Python 3.x
- OpenSSL CLI must be installed and available on PATH — required for certificate detection (`certificate_detector.py` shells out to it). Without it, certificate scanning will fail with an "OpenSSL CLI was not found on PATH" error.

## CBOM Module (Part 2) — status
- CBOM Generator: done
- Classification: Algorithm, Hash Function, Library, Key, **Certificate, Protocol** (Certificate detections now include subject, issuer, curve/key size, expiry, and serial number via OpenSSL parsing, in addition to file-extension based detection; Protocol detection via TLS/SSL/SSH keywords, even without explicit tagging from the scanner)
- Duplicate Removal: done, preserves full provenance (every file/line an artifact was found at)
- Pattern Recognition: done, includes cross-file and cross-language detection
- Recommendation Database: done (RSA→ML-KEM, ECC/EC→ML-DSA, Ed25519→ML-DSA, SHA-1→SHA-256, DES→AES-256, plus more)
- Fix-it Suggestions: added — guided before/after code examples for detected weak algorithms (currently covers RSA and MD5 in **Python and Java**, more languages/algorithms coming)

## Test status
168 passed, 1 skipped, 0 failed (`python -m pytest tests/ -v`)

## How to run

    cd scanner
    pip install javalang
    python -m scanner.scanner ../samples scanner_output.json

    cd ../cbom
    python cbom_generator.py ../scanner_output.json cbom_output.json

## Output contract
See `sample_output/cbom_output.json` for the exact structure Part 3 (risk engine) and Part 4 (MongoDB) should consume.
