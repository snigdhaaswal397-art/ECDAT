"""
Compares two scanner_output.json files structurally:
  - ignores artifact_id (random per run, by design)
  - normalizes file_path (fixture dir differs from original ../sample_code path
    only in that both already use "../sample_code/<name>", so no normalization
    needed here beyond exact match)
  - treats each output as a MULTISET of (all fields except artifact_id)
    so ordering differences don't cause false mismatches
"""
import json
import sys
from collections import Counter


def normalize(entry: dict) -> tuple:
    d = {k: v for k, v in entry.items() if k != "artifact_id"}
    # normalize file_path to just the basename so a directory-name
    # difference (e.g. "../sample_code" vs "../sample_code_real") doesn't
    # cause a false mismatch — everything else must still match exactly.
    if "file_path" in d:
        d["file_path"] = d["file_path"].split("/")[-1]
    return tuple(sorted(d.items()))


def load(path, only_langs=None):
    with open(path) as f:
        data = json.load(f)
    if only_langs:
        data = [d for d in data if any(d["file_path"].endswith(ext) for ext in only_langs)]
    return data


if __name__ == "__main__":
    old_path, new_path = sys.argv[1], sys.argv[2]
    # Restrict to Python + C entries only, since Java can't be verified in
    # this sandbox (javalang not installable / no network egress here).
    only = (".py", ".c", ".h", ".cpp", ".cc")

    old = load(old_path, only)
    new = load(new_path, only)

    old_counter = Counter(normalize(e) for e in old)
    new_counter = Counter(normalize(e) for e in new)

    missing = old_counter - new_counter   # present before, missing now
    extra = new_counter - old_counter     # present now, wasn't before

    print(f"Old (Python+C only): {len(old)} entries")
    print(f"New (Python+C only): {len(new)} entries")

    if not missing and not extra:
        print("\n✅ IDENTICAL — every Python and C finding matches exactly (field-for-field, ignoring artifact_id).")
    else:
        if missing:
            print(f"\n❌ MISSING from new output ({sum(missing.values())} entries):")
            for entry, count in missing.items():
                print(f"  x{count}  {dict(entry)}")
        if extra:
            print(f"\n⚠️  EXTRA in new output, not in old ({sum(extra.values())} entries):")
            for entry, count in extra.items():
                print(f"  x{count}  {dict(entry)}")
