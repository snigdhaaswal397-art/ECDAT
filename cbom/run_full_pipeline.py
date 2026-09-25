import json
import sys
sys.path.append("..")  # taaki risk_engine/ import ho sake repo root se

from adapter import cbom_to_risk_input
from risk_engine import RiskEngine
from cbom_generator import generate_cbom

with open("../scanner_output.json") as f:
    raw_artifacts = json.load(f)

cbom_output = generate_cbom(raw_artifacts)
risk_input = cbom_to_risk_input(cbom_output)

engine = RiskEngine(profile="enterprise_default")
enriched = engine.process_findings(risk_input)

with open("risk_output.json", "w") as f:
    json.dump(enriched, f, indent=2)

print(f"\n{len(enriched)} findings scored -> risk_output.json")
print("\n--- band summary ---")
for f in enriched:
    print(f"{f['algorithm']:15s} band={f['risk']['band']:10s} shor_vulnerable={f['risk']['shor_vulnerable']}")
print("\n--- unique locations ---")
for loc in sorted(set(f['location'] for f in risk_input)):
    print(loc)
    
from cyclonedx_export import cbom_to_cyclonedx

bom = cbom_to_cyclonedx(cbom_output)
with open("cbom_cyclonedx.json", "w") as f:
    json.dump(bom, f, indent=2)
print("CycloneDX export written -> cbom_cyclonedx.json")