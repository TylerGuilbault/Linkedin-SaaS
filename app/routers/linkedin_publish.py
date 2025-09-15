# app/routers/linkedin_publish.py
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from app.deps import get_db
from app.db import crud_tokens
from app.db.token_crypto import decrypt_token
from app.services import linkedin_api

router = APIRouter(prefix="/linkedin", tags=["linkedin"])

class PublishIn(BaseModel):
    user_id: int
    text: str
    member_id: Optional[str] = None  # allow client to pass, else we can look up later

@router.post("/post")
def publish(body: PublishIn, db: Session = Depends(get_db)) -> Dict[str, Any]:
    tok = crud_tokens.get_latest_token(db, user_id=body.user_id)
    if not tok:
        raise HTTPException(400, "No LinkedIn token on file for this user_id. Visit /auth/linkedin/login first.")
    access_token = decrypt_token(tok.access_token_encrypted)

    if not body.member_id:
        raise HTTPException(400, "member_id missing. Pass the OpenID 'sub' you saw in the callback response.")

    # Build the URN as 'member' first (this worked for your first account)
    author_member_urn = f"urn:li:member:{body.member_id}"
    print(f"[publish] Trying author={author_member_urn}", flush=True)

    ok, ref = linkedin_api.post_text(access_token, author_member_urn, body.text)
    if ok:
        return {"status": "posted", "ref": ref}

    # If LinkedIn rejects the member URN, try 'person' shape automatically
    author_person_urn = f"urn:li:person:{body.member_id}"
    print(f"[publish] member URN failed. Retrying author={author_person_urn}", flush=True)
    ok2, ref2 = linkedin_api.post_text(access_token, author_person_urn, body.text)
    if ok2:
        return {"status": "posted", "ref": ref2}

    raise HTTPException(400, f"LinkedIn API error: {ref}")
