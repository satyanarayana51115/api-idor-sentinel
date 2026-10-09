import json
from scanner_engine import AccessControlScanner
from audit_reporter import AuditReporter

BASE_URL = "http://127.0.0.1:8000"

def run_pipeline():
    print("🚀 Initializing API Access Control Sentinel...")
    scanner = AccessControlScanner(base_url=BASE_URL)
    
    # Alice టోకెన్ ఉపయోగించి Bob కి చెందిన డాక్యుమెంట్ (ID 102) ను పరీక్షించడం
    alice_token = "token_alice"
    bob_resource_id = 102
    
    test_cases = [
        {"path": "/api/v1/documents/{id}", "expect_block": True},
        {"path": "/api/v2/documents/{id}", "expect_block": True}
    ]
    
    findings = []
    for tc in test_cases:
        result = scanner.audit_endpoint(
            path_template=tc["path"],
            target_id=bob_resource_id,
            auth_token=alice_token,
            expected_block=tc["expect_block"]
        )
        findings.append(result)

    # కన్సోల్ అవుట్‌పుట్ మరియు మార్క్‌డౌన్ రిపోర్ట్ జనరేట్ చేయడం
    AuditReporter.print_console_summary(findings)
    AuditReporter.save_markdown_report(findings)
    
    # JSON ఫార్మాట్‌లో కూడా సేవ్ చేయడం
    with open("audit_results.json", "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=4)
        
    print("\n✅ Verification complete. Reports saved to 'SECURITY_AUDIT_REPORT.md' and 'audit_results.json'.")

if __name__ == "__main__":
    run_pipeline()