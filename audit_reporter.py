import json

class AuditReporter:
    @staticmethod
    def print_console_summary(findings: list):
        print("\n" + "=" * 70)
        print("          API OBJECT-LEVEL AUTHORIZATION AUDIT REPORT         ")
        print("=" * 70)
        
        for item in findings:
            status_tag = "[ FAIL / VULNERABLE ]" if item["is_vulnerable"] else "[ PASS / PROTECTED ]"
            print(f"\nTarget: {item['endpoint']}")
            print(f"Result: {status_tag} (HTTP {item['status_code']})")
            print(f"Severity: {item['severity']}")
            print(f"Audit Note: {item['summary']}")
            print("-" * 70)

    @staticmethod
    def save_markdown_report(findings: list, filename: str = "SECURITY_AUDIT_REPORT.md"):
        with open(filename, "w", encoding="utf-8") as f:
            f.write("# 🛡️ API Authorization & Access Control Audit Report\n\n")
            f.write("Automated policy verification report for Object-Level Access Controls (OWASP API Security Top 10).\n\n")
            f.write("| Endpoint | Status Code | Finding | Severity |\n")
            f.write("| :--- | :--- | :--- | :--- |\n")
            
            for f_item in findings:
                status = "❌ High Risk" if f_item["is_vulnerable"] else "✅ Compliant"
                f.write(f"| `{f_item['endpoint']}` | {f_item['status_code']} | {f_item['summary']} | {status} |\n")
            
            f.write("\n\n### Remediation Recommendations\n")
            f.write("1. **Data Access Layers:** Never query records solely by primary key (`id`) from client input.\n")
            f.write("2. **Context Binding:** Always include the authenticated session identity in queries (e.g., `WHERE id = :id AND owner_id = :current_user`).\n")