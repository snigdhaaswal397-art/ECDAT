"""
Run this LOCALLY (where `pip install javalang` works) to actually execute
the Java verification that could not be run in the sandbox.

Usage:
    cd scanner/
    python verify_java.py path/to/real/LegacyAuthService.java
"""
import sys
from java_detector import scan_java_file

EXPECTED = [
    (9,  "MD5",   None,  "ast_call",  0.95),
    (14, "SHA-1", None,  "ast_call",  0.95),
    (19, "RSA",   1024,  "ast_call",  0.95),
    (25, "AES",   None,  "ast_call",  0.95),
    (30, "ECDSA", None,  "ast_call",  0.95),
]

if __name__ == "__main__":
    path = sys.argv[1]
    results = scan_java_file(path)
    calls = sorted(
        [r for r in results if r["detection_method"] == "ast_call"],
        key=lambda r: r["line_number"],
    )

    print(f"{len(results)} total findings ({len(calls)} confirmed ast_call detections)\n")
    ok = True
    for expected, actual in zip(EXPECTED, calls):
        exp_line, exp_alg, exp_ks, exp_method, exp_conf = expected
        match = (
            actual["line_number"] == exp_line
            and actual["algorithm"] == exp_alg
            and actual["key_size"] == exp_ks
            and actual["detection_method"] == exp_method
            and actual["confidence"] == exp_conf
        )
        status = "OK  " if match else "FAIL"
        print(f"[{status}] line {exp_line}: expected {exp_alg} (key_size={exp_ks}) -> got {actual}")
        ok = ok and match

    if len(calls) != len(EXPECTED):
        print(f"\nFAIL: expected {len(EXPECTED)} ast_call detections, got {len(calls)}")
        ok = False

    print("\n✅ Java detector matches expected output" if ok else "\n❌ MISMATCH — see above")
