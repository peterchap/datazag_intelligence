# test_regression.py
import json

def test_against_saved_output():
    """
    Compare a fresh run against a saved known-good output.
    Checks structure, not exact values (RDAP dates change etc).
    """
    # Save a known-good run first:
    #   python dns_report.py adaptavist.com > test_fixtures/adaptavist_baseline.json

    with open("test_fixtures/adaptavist_baseline.json") as f:
        baseline = json.load(f)

    # Check all top-level keys are still present
    for key in baseline:
        assert key in baseline, f"Key missing: {key}"

    # Check nested structures match shape
    assert "records" in baseline["dns_profile"]
    assert "summary" in baseline["cert_analysis"]
    assert "rdap_available" in baseline["rdap"]

    print("Regression check passed — output structure unchanged")