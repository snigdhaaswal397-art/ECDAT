# ECDAT — Enterprise Cryptographic Discovery & Analysis Tool
SIH 2026 · Problem Statement SIH26164 · NTRO

## Pipeline
Scanner Output → Classify Artefacts → Generate CBOM → Calculate Risk → Recommendations → Store in DB

## Team & Structure
- `scanner/` — Part 1: Discovery engine (Vaishnavi) — initial Python/Java/C version built by Snigdha as a starting point
- `cbom/` — Part 2: CBOM generation, classification, dedup, pattern recognition, recommendations (Snigdha) — **complete**
- `risk_engine/` — Part 3: Mosca's theorem, risk scoring (Samridhi) — coming soon
- `backend/` — Part 4: API + MongoDB (Mansi) — coming soon
- `frontend/` — Part 5: Dashboard/GUI (Antriksha & Anisha) — coming soon
- `sample_output/` — Example scanner and CBOM output for reference

## CBOM Module (Part 2) — status
- CBOM Generator: done
- Classification: Algorithm, Hash Function, Library, Key, **Certificate, Protocol** (added — auto-detects certs via file extension and protocols via TLS/SSL/SSH keywords, even without explicit tagging from the scanner)
- Duplicate Removal: done, preserves full provenance (every file/line an artifact was found at)
- Pattern Recognition: done, includes cross-file and cross-language detection
- Recommendation Database: done (RSA→ML-KEM, ECC→ML-DSA, SHA-1→SHA-256, DES→AES-256, plus more)

## How to run
​```bash
cd scanner
pip install javalang
python scanner.py ../sample_code scanner_output.json

cd ../cbom
python cbom_generator.py ../scanner/scanner_output.json cbom_output.json
​```

## Output contract
See `sample_output/cbom_output.json` for the exact structure Part 3
(risk engine) and Part 4 (MongoDB) should consume.
