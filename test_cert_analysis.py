# test_cert_analysis.py
import asyncio
from datetime import date, timedelta
from cert_pipeline import normalise, CertAnalysis

# Synthetic Certspotter records — same shape as the real API response
def make_record(dns_names, not_after_days=90, logged_at_days_ago=10):
    today = date.today()
    return {
        "id": f"test_{dns_names[0]}",
        "dns_names": dns_names,
        "not_before": (today - timedelta(days=60)).isoformat() + "Z",
        "not_after":  (today + timedelta(days=not_after_days)).isoformat() + "Z",
        "logged_at":  (today - timedelta(days=logged_at_days_ago)).isoformat() + "Z",
        "issuer": {
            "organization": "Let's Encrypt",
            "common_name":  "R3",
        },
        "tbs_summary": {"common_names": [dns_names[0]]},
    }

def test_subdomain_corpus():
    records = [
        make_record(["api.example.com"]),
        make_record(["login.example.com"]),
        make_record(["*.example.com"]),          # wildcard — excluded from corpus
        make_record(["example.com"]),            # apex — excluded from corpus
    ]
    rows     = normalise(records, "example.com")
    analysis = CertAnalysis(rows, "example.com")
    corpus   = analysis.subdomain_corpus()

    names = [r["dns_name"] for r in corpus]
    assert "api.example.com"   in names
    assert "login.example.com" in names
    assert "example.com"       not in names     # apex excluded
    assert "*.example.com"     not in names     # wildcards excluded
    print(f"  corpus: {names}")

def test_expiring_soon():
    records = [
        make_record(["soon.example.com"], not_after_days=20),   # expiring
        make_record(["fine.example.com"], not_after_days=120),  # not expiring
    ]
    rows     = normalise(records, "example.com")
    analysis = CertAnalysis(rows, "example.com")
    expiring = analysis.expiring_soon(60)

    assert len(expiring) == 1
    assert expiring[0]["dns_name"] == "soon.example.com"
    print(f"  expiring: {expiring}")

def test_missed_renewals():
    today = date.today()
    records = [
        # Cert expires in 45 days — expected renewal was 15 days ago, hasn't renewed
        make_record(["broken.example.com"], not_after_days=45, logged_at_days_ago=100),
        # Cert expires in 90 days — not yet past expected renewal date
        make_record(["fine.example.com"], not_after_days=90, logged_at_days_ago=10),
    ]
    rows     = normalise(records, "example.com")
    analysis = CertAnalysis(rows, "example.com")
    missed   = analysis.missed_renewals()

    assert any(r["dns_name"] == "broken.example.com" for r in missed)
    print(f"  missed renewals: {[r['dns_name'] for r in missed]}")

def test_cert_churn():
    today = date.today()
    # Same subdomain appearing 10 times in 120 days = churn
    records = [
        {
            "id": f"cert_{i}",
            "dns_names": ["churning.example.com"],
            "not_before": (today - timedelta(days=100)).isoformat() + "Z",
            "not_after":  (today + timedelta(days=30)).isoformat()  + "Z",
            "logged_at":  (today - timedelta(days=i*10)).isoformat() + "Z",
            "issuer":     {"organization": "Let's Encrypt", "common_name": "R3"},
            "tbs_summary": {"common_names": ["churning.example.com"]},
        }
        for i in range(10)
    ]
    rows     = normalise(records, "example.com")
    analysis = CertAnalysis(rows, "example.com")
    churn    = analysis.cert_churn(threshold=8)

    assert len(churn) == 1
    assert churn[0]["dns_name"] == "churning.example.com"
    assert churn[0]["cert_count"] == 10
    print(f"  churn: {churn}")

def test_cross_domain_sans():
    records = [
        make_record(["api.example.com", "status.other-company.com"]),
    ]
    rows     = normalise(records, "example.com")
    analysis = CertAnalysis(rows, "example.com")
    cross    = analysis.cross_domain_sans()

    names = [r["dns_name"] for r in cross]
    assert "status.other-company.com" in names
    assert "api.example.com"          not in names
    print(f"  cross-domain: {names}")

def test_issuer_distribution():
    records = [
        make_record(["a.example.com"]),  # Let's Encrypt
        make_record(["b.example.com"]),  # Let's Encrypt
        {
            "id": "aws_cert",
            "dns_names": ["c.example.com"],
            "not_before": date.today().isoformat() + "Z",
            "not_after":  (date.today() + timedelta(days=365)).isoformat() + "Z",
            "logged_at":  date.today().isoformat() + "Z",
            "issuer":     {"organization": "Amazon", "common_name": "ACM"},
            "tbs_summary": {"common_names": ["c.example.com"]},
        }
    ]
    rows     = normalise(records, "example.com")
    analysis = CertAnalysis(rows, "example.com")
    dist     = analysis.issuer_distribution()

    cats = {r["issuer_category"]: r["subdomain_count"] for r in dist}
    assert cats.get("letsencrypt") == 2
    assert cats.get("amazon_acm")  == 1
    print(f"  distribution: {cats}")

if __name__ == "__main__":
    tests = [
        test_subdomain_corpus,
        test_expiring_soon,
        test_missed_renewals,
        test_cert_churn,
        test_cross_domain_sans,
        test_issuer_distribution,
    ]
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except AssertionError as e:
            print(f"FAIL  {t.__name__}: {e}")