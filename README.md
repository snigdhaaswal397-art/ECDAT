# ECDAT — Enterprise Cryptographic Discovery & Analysis Tool
SIH 2026 · Problem Statement SIH26164 · NTRO

## Pipeline
Scanner Output → Classify Artefacts → Generate CBOM → Calculate Risk → Recommendations → Store in DB

## Structure
- `scanner/` — Part 1: Discovery engine (Python, Java, C detection)
- `cbom/` — Part 2: CBOM generation, classification, dedup, pattern recognition (Snigdha)
- `risk_engine/` — Part 3: Mosca's theorem, risk scoring (Samridhi) — coming soon
- `backend/` — Part 4: API + database — coming soon
- `frontend/` — Part 5: Dashboard/GUI — coming soon
- `sample_output/` — Example scanner and CBOM output for reference

## How to run
\`\`\`bash
cd scanner
pip install javalang
python scanner.py ../sample_code scanner_output.json

cd ../cbom
python cbom_generator.py ../scanner/scanner_output.json cbom_output.json
\`\`\`

## Output contract
See `sample_output/cbom_output.json` for the exact structure Part 3
(risk engine) should consume.
