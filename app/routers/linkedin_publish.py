# Article share endpoint
class LinkShareIn(BaseModel):
    user_id: int
    url: str
    text: str = ""
    member_id: str | None = None

@router.post("/post/link")
def post_link(body: LinkShareIn, db: Session = Depends(get_db)) -> Dict[str, Any]:
    tok = crud_tokens.get_latest_token(db, user_id=body.user_id)
    if not tok:
        raise HTTPException(400, "No LinkedIn token on file for this user_id. Visit /auth/linkedin/login first.")
    access_token = decrypt_token(tok.access_token_encrypted)
    member_id = body.member_id
    if not member_id:
        from app.db.models import User
        user = db.query(User).filter(User.id == body.user_id).first()
        if user and user.member_id:
            member_id = user.member_id
        else:
            raise HTTPException(400, "member_id required; re-auth to capture it")
    author_urn = f"urn:li:member:{member_id}"
    ok, resp = linkedin_api.post_article_share(access_token, author_urn, body.url, body.text)
    if ok:
        return {"status": "posted", "ref": resp.text}
    raise HTTPException(502, f"LinkedIn article share failed: {resp.text}")

# Image share endpoint
class ImageShareIn(BaseModel):
    user_id: int
    image_base64: str | None = None
    image_url: str | None = None
    text: str = ""
    member_id: str | None = None

@router.post("/post/image")
def post_image(body: ImageShareIn, db: Session = Depends(get_db)) -> Dict[str, Any]:
    import base64
    tok = crud_tokens.get_latest_token(db, user_id=body.user_id)
    if not tok:
        raise HTTPException(400, "No LinkedIn token on file for this user_id. Visit /auth/linkedin/login first.")
    access_token = decrypt_token(tok.access_token_encrypted)
    member_id = body.member_id
    if not member_id:
        from app.db.models import User
        user = db.query(User).filter(User.id == body.user_id).first()
        if user and user.member_id:
            member_id = user.member_id
        else:
            raise HTTPException(400, "member_id required; re-auth to capture it")
    author_urn = f"urn:li:member:{member_id}"
    # Register upload
    reg = linkedin_api.register_image_upload(access_token, author_urn)
    upload_url = reg["value"]["uploadMechanism"]["com.linkedin.digitalmedia.uploading.MediaUploadHttpRequest"]["uploadUrl"]
    asset_urn = reg["value"]["asset"]
    # Get image bytes
    if body.image_base64:
        image_bytes = base64.b64decode(body.image_base64)
    elif body.image_url:
        import requests
        r = requests.get(body.image_url)
        image_bytes = r.content
    else:
        raise HTTPException(400, "Provide image_base64 or image_url.")
    # Upload asset
    success = linkedin_api.upload_image_asset(upload_url, image_bytes)
    if not success:
        raise HTTPException(502, "LinkedIn image upload failed.")
    # Create post
    ok, resp = linkedin_api.post_image_share(access_token, author_urn, asset_urn, body.text)
    if ok:
        return {"status": "posted", "ref": resp.text}
    raise HTTPException(502, f"LinkedIn image share failed: {resp.text}")
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

    # If token is expiring and refresh token exists, try to refresh
    if crud_tokens.is_token_expiring(tok):
        refresh_token = crud_tokens.get_latest_refresh_token(db, body.user_id)
        if refresh_token:
            from app.db.token_crypto import decrypt_token as decrypt_refresh
            try:
                plain_refresh = decrypt_refresh(refresh_token)
                resp = linkedin_api.exchange_refresh_for_token(plain_refresh)
                access_token_new = resp.get("access_token")
                expires_in_new = resp.get("expires_in", 3600)
                if access_token_new:
                    crud_tokens.update_access_token_only(db, body.user_id, access_token_new, expires_in_new)
                    tok = crud_tokens.get_latest_token(db, user_id=body.user_id)
                else:
                    raise Exception("No access_token in refresh response")
            except Exception:
                raise HTTPException(401, "LinkedIn token expired and refresh failed; please re-login.")
    access_token = decrypt_token(tok.access_token_encrypted)


    member_id = body.member_id
    # If not provided, use stored user.member_id
    if not member_id:
        from app.db.models import User
        user = db.query(User).filter(User.id == body.user_id).first()
        if user and user.member_id:
            member_id = user.member_id
        else:
            id_token = getattr(tok, "id_token", None)
            if id_token:
                try:
                    payload = jwt.decode(id_token, options={"verify_signature": False})
                    member_id = payload.get("sub")
                except Exception:
                    pass
            if not member_id:
                raise HTTPException(
                    400,
                    "member_id required; re-auth to capture it"
                )

    author_member_urn = f"urn:li:member:{member_id}"
    print(f"[publish] Trying author={author_member_urn}", flush=True)

    # Validate author_urn
    if not author_member_urn.startswith("urn:li:member:") or not member_id:
        raise HTTPException(400, "author_urn must start with 'urn:li:member:' and member_id must be present.")

    ok, ref = linkedin_api.post_text(access_token, author_member_urn, body.text)
    if ok:
        return {"status": "posted", "ref": ref}

    # LinkedIn error handling
    error_status = None
    error_message = None
    service_error_code = None
    if isinstance(ref, dict):
        error_status = ref.get("status")
        error_message = ref.get("message") or ref.get("body")
        service_error_code = ref.get("serviceErrorCode")
    elif hasattr(ref, "status_code"):
        error_status = getattr(ref, "status_code", None)
        error_message = getattr(ref, "text", str(ref))

    if error_status and 400 <= error_status < 500:
        raise HTTPException(
            error_status,
            f"LinkedIn API error ({error_status}) [{service_error_code}]: {error_message}"
        )
    if error_status and error_status >= 500:
        raise HTTPException(
            502,
            f"LinkedIn API error ({error_status}) [{service_error_code}]: {error_message}"
        )
    raise HTTPException(400, f"LinkedIn API error: {ref}")
