import httpx
from typing import Dict, Any, List

class AccessControlScanner:
    def __init__(self, base_url: str):
        self.base_url = base_url

    def audit_endpoint(self, path_template: str, target_id: int, auth_token: str, expected_block: bool) -> Dict[str, Any]:
        """
        ఒక నిర్దిష్ట ఎండ్‌పాయింట్‌లో ఆబ్జెక్ట్-లెవెల్ యాక్సెస్ కంట్రోల్స్ పనిచేస్తున్నాయో లేదో పరీక్షిస్తుంది.
        """
        url = f"{self.base_url}{path_template.format(id=target_id)}"
        headers = {"Authorization": auth_token}
        
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(url, headers=headers)
                
            status_code = response.status_code
            
            # ఆడిట్ విశ్లేషణ
            if status_code == 200:
                is_vulnerable = expected_block
                severity = "HIGH" if is_vulnerable else "INFO"
                summary = "BROKEN ACCESS: Resource returned without tenant ownership verification." if is_vulnerable else "Authorized access verified."
            elif status_code == 403:
                is_vulnerable = not expected_block
                severity = "NONE"
                summary = "SECURE: Strict 403 Forbidden enforced on cross-tenant access."
            elif status_code == 401:
                is_vulnerable = False
                severity = "NONE"
                summary = "Unauthenticated access rejected."
            else:
                is_vulnerable = False
                severity = "LOW"
                summary = f"Unexpected status: {status_code}"

            return {
                "endpoint": path_template,
                "tested_id": target_id,
                "status_code": status_code,
                "is_vulnerable": is_vulnerable,
                "severity": severity,
                "summary": summary
            }

        except Exception as e:
            return {
                "endpoint": path_template,
                "tested_id": target_id,
                "status_code": 0,
                "is_vulnerable": False,
                "severity": "ERROR",
                "summary": f"Connection failed: {str(e)}"
            }