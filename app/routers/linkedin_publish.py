# app/routers/linkedin_publish.py
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from app.deps import get_db
from app.db import crud_tokens
from app.db.token_crypto import decrypt_token

import jwt
from app.services import linkedin_api

router = APIRouter(prefix="/linkedin", tags=["linkedin"])

class PublishIn(BaseModel):
    user_id: int
    text: str
    member_id: str | None = None  # explicit type annotation


@router.post("/post")
def publish(body: PublishIn, db: Session = Depends(get_db)) -> Dict[str, Any]:
    tok = crud_tokens.get_latest_token(db, user_id=body.user_id)
    if not tok:
        raise HTTPException(400, "No LinkedIn token on file for this user_id. Visit /auth/linkedin/login first.")
    access_token = decrypt_token(tok.access_token_encrypted)

    member_id = body.member_id
    # Try to derive member_id from stored id_token (OpenID sub) if not provided
    if not member_id:
        id_token = getattr(tok, "id_token", None)
        if id_token:
            # Extract 'sub' from id_token (JWT)
            import jwt
            try:
                payload = jwt.decode(id_token, options={"verify_signature": False})
                member_id = payload.get("sub")
            except Exception:
                pass
        if not member_id:
            raise HTTPException(
                400,
                "member_id missing. Pass the OpenID 'sub' you saw in the callback response, or ensure your token includes an id_token with sub."
            )

    author_member_urn = f"urn:li:member:{member_id}"
    print(f"[publish] Trying author={author_member_urn}", flush=True)

    ok, ref = linkedin_api.post_text(access_token, author_member_urn, body.text)
    if ok:
        return {"status": "posted", "ref": ref}

    # If LinkedIn rejects the member URN, return error with details
    error_status = getattr(ref, "status_code", None)
    error_body = getattr(ref, "text", str(ref))
    if error_status in (403, 422):
        raise HTTPException(
            error_status,
            f"LinkedIn API error ({error_status}): {error_body}"
        )

    raise HTTPException(400, f"LinkedIn API error: {error_body}")
