from fastapi import FastAPI, Header, HTTPException, status
from typing import Optional, Dict

app = FastAPI(title="Access Control Testbed API", version="1.0.0")

# డమ్మీ యూజర్లు
USERS = {
    "token_alice": {"user_id": "usr_alice", "name": "Alice"},
    "token_bob": {"user_id": "usr_bob", "name": "Bob"}
}

# డమ్మీ రిసోర్స్‌లు (ఒక్కో డాక్యుమెంట్‌కు ఒక ఓనర్ ఉంటారు)
DOCUMENTS: Dict[int, dict] = {
    101: {"doc_id": 101, "owner_id": "usr_alice", "title": "Alice Strategy", "data": "Confidential Q4 Plan"},
    102: {"doc_id": 102, "owner_id": "usr_bob", "title": "Bob Performance Review", "data": "Private Salary Details"}
}

def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or authorization not in USERS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    return USERS[authorization]

# 1. లోపం ఉన్న ఎండ్‌పాయింట్ (ఓనర్ ఎవరో ధృవీకరించకుండా కేవలం ID ఆధారంగా డేటా ఇస్తుంది)
@app.get("/api/v1/documents/{doc_id}")
def get_document_vulnerable(doc_id: int, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    doc = DOCUMENTS.get(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    return doc

# 2. సరిదిద్దబడిన సెక్యూర్ ఎండ్‌పాయింట్ (యూజర్ ఓనర్‌షిప్‌ను ఖచ్చితంగా వెరిఫై చేస్తుంది)
@app.get("/api/v2/documents/{doc_id}")
def get_document_secure(doc_id: int, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    doc = DOCUMENTS.get(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    
    # ఆథరైజేషన్ ఎన్‌ఫోర్స్‌మెంట్: ప్రస్తుత యూజర్ ఈ డాక్యుమెంట్ ఓనర్ కాకపోతే తిరస్కరించడం
    if doc["owner_id"] != user["user_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: Object-level authorization policy violation."
        )
    return doc