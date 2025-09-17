# app/routers/linkedin_publish.py
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.deps import get_db
from app.db import crud_tokens
from app.db.token_crypto import decrypt_token
from app.services import linkedin_api
from app.services.linkedin_api import userinfo_sub, me_id

router = APIRouter(prefix="/linkedin", tags=["linkedin"])

class PublishIn(BaseModel):
    user_id: int
    text: str
    member_id: Optional[str] = None  # optional override

class LinkShareIn(BaseModel):
    user_id: int
    url: str
    text: str = ""
    member_id: Optional[str] = None

class ImageShareIn(BaseModel):
    user_id: int
    image_base64: Optional[str] = None
    image_url: Optional[str] = None
    text: str = ""
    member_id: Optional[str] = None


class DebugPostIn(BaseModel):
    user_id: int
    text: str
    member_id: Optional[str] = None
    person_id: Optional[str] = None


def _resolve_author_from_token(db: Session, user_id: int, access_token: str, provided_member_id: Optional[str], context: str) -> str:
    """
    Always prefer the token identity (userinfo_sub(access_token)).
    If DB/provided member_id differs, we still use token identity because LinkedIn requires /author
    to match the token owner.
    """
    from app.db.models import User

    token_member_id = userinfo_sub(access_token) or None
    db_member_id = None
    body_member_id = provided_member_id

    # read db member_id
    u = db.query(User).filter(User.id == user_id).first()
    if u and u.member_id:
        db_member_id = u.member_id

    # choose in priority order: token -> db -> body
    chosen = token_member_id or db_member_id or body_member_id
    if not chosen:
        raise HTTPException(401, "Couldn't resolve member_id from access token; please re-login.")

    # if we had a token identity but it doesn't match, force token identity
    if token_member_id and chosen != token_member_id:
        print(f"[{context}] WARN mismatch: chosen={chosen} but token.sub={token_member_id}; forcing token.sub", flush=True)
        chosen = token_member_id

    author_urn = f"urn:li:member:{chosen}"
    print(f"[{context}] author={author_urn} (source={'token' if token_member_id else 'db' if db_member_id else 'body'})", flush=True)
    return author_urn


def _get_fresh_access_token(db: Session, user_id: int) -> str:
    tok = crud_tokens.get_latest_token(db, user_id=user_id)
    if not tok:
        raise HTTPException(400, "No LinkedIn token on file for this user_id. Visit /auth/linkedin/login first.")

    # refresh if expiring
    if crud_tokens.is_token_expiring(tok):
        refresh_token_enc = crud_tokens.get_latest_refresh_token(db, user_id)
        if refresh_token_enc:
            try:
                from app.db.token_crypto import decrypt_token as dec
                plain_refresh = dec(refresh_token_enc)
                resp = linkedin_api.exchange_refresh_for_token(plain_refresh)
                access_token_new = resp.get("access_token")
                expires_in_new = resp.get("expires_in", 3600)
                if access_token_new:
                    crud_tokens.update_access_token_only(db, user_id, access_token_new, expires_in_new)
                    tok = crud_tokens.get_latest_token(db, user_id=user_id)
                else:
                    raise Exception("No access_token in refresh response")
            except Exception:
                raise HTTPException(401, "LinkedIn token expired and refresh failed; please re-login.")

    return decrypt_token(tok.access_token_encrypted)


@router.post("/post")
def publish(body: PublishIn, db: Session = Depends(get_db)) -> Dict[str, Any]:
    access_token = _get_fresh_access_token(db, body.user_id)
    from app.db.models import User

    # Resolve member_id: prefer body.member_id, then DB-stored member_id. Do NOT call /v2/me or userinfo.
    member_id = body.member_id
    if not member_id:
        user_db = db.query(User).filter(User.id == body.user_id).first()
        member_id = user_db.member_id if user_db else None
    if not member_id:
        raise HTTPException(400, "member_id missing. Re-login to capture it from OIDC id_token or provide member_id in request.")

    # Build member URN and post
    author_urn = f"urn:li:member:{member_id}"
    print(f"[publish] author(member)={author_urn}", flush=True)
    ok, ref = linkedin_api.post_text(access_token, author_urn, body.text)

    if ok:
        try:
            return {"status": "posted", "ref": ref.text}
        except Exception:
            return {"status": "posted"}

    # bubble up error with good context
    status = getattr(ref, "status_code", None) or (ref.get("status") if isinstance(ref, dict) else None)
    msg = None
    if hasattr(ref, "text"):
        msg = getattr(ref, "text")
    elif isinstance(ref, dict):
        msg = ref.get("message") or ref.get("body")
    code = ref.get("serviceErrorCode") if isinstance(ref, dict) else None
    if status and 400 <= status < 500:
        raise HTTPException(status, f"LinkedIn API error ({status}) [{code}]: {msg}")
    raise HTTPException(502, f"LinkedIn API error: {ref}")


@router.get("/check")
def check(user_id: int, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Dry-run: resolve access token, member_id/person_id and return the author URN the server would use."""
    access_token = _get_fresh_access_token(db, user_id)
    from app.db.models import User

    user_db = db.query(User).filter(User.id == user_id).first()
    db_member_id = user_db.member_id if user_db else None
    db_person_id = user_db.person_id if user_db else None

    token_sub = userinfo_sub(access_token)

    # prefer DB member_id, else token sub
    chosen_member = db_member_id or token_sub

    author_person_urn = None
    author_member_urn = f"urn:li:member:{chosen_member}" if chosen_member else None

    return {
        "status": "ok",
        "user_id": user_id,
        "token_sub": token_sub,
        "db_member_id": db_member_id,
        "db_person_id": db_person_id,
        "author_person_urn": author_person_urn,
        "author_member_urn": author_member_urn,
        "can_post_using_member": bool(chosen_member),
        "note": "If you want to post as numeric person URN (urn:li:person:...), you must have person_id persisted (r_liteprofile required)." 
    }


@router.post("/post/link")
def post_link(body: LinkShareIn, db: Session = Depends(get_db)) -> Dict[str, Any]:
    access_token = _get_fresh_access_token(db, body.user_id)
    author_urn = _resolve_author_from_token(db, body.user_id, access_token, body.member_id, context="post_link")
    ok, resp = linkedin_api.post_article_share(access_token, author_urn, body.url, body.text)
    if ok:
        return {"status": "posted", "ref": resp.text}
    raise HTTPException(502, f"LinkedIn article share failed: {resp.text}")


@router.post("/post/image")
def post_image(body: ImageShareIn, db: Session = Depends(get_db)) -> Dict[str, Any]:
    import base64, httpx
    access_token = _get_fresh_access_token(db, body.user_id)
    author_urn = _resolve_author_from_token(db, body.user_id, access_token, body.member_id, context="post_image")

    reg = linkedin_api.register_image_upload(access_token, author_urn)
    upload_url = reg["value"]["uploadMechanism"]["com.linkedin.digitalmedia.uploading.MediaUploadHttpRequest"]["uploadUrl"]
    asset_urn = reg["value"]["asset"]

    if body.image_base64:
        image_bytes = base64.b64decode(body.image_base64)
    elif body.image_url:
        # fetch remote image via httpx
        with httpx.Client(timeout=60) as c:
            r = c.get(body.image_url)
            r.raise_for_status()
            image_bytes = r.content
    else:
        raise HTTPException(400, "Provide image_base64 or image_url.")

    success = linkedin_api.upload_image_asset(upload_url, image_bytes)
    if not success:
        raise HTTPException(502, "LinkedIn image upload failed.")

    ok, resp = linkedin_api.post_image_share(access_token, author_urn, asset_urn, body.text)
    if ok:
        return {"status": "posted", "ref": resp.text}
    raise HTTPException(502, f"LinkedIn image share failed: {resp.text}")


@router.post("/debug/post")
def debug_post(body: DebugPostIn, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Dev-only: attempt a post using the provided member_id or person_id (no persistence) and return raw response for debugging."""
    access_token = _get_fresh_access_token(db, body.user_id)

    # choose priority: explicit person_id -> explicit member_id -> DB member_id -> token_sub
    from app.db.models import User
    user_db = db.query(User).filter(User.id == body.user_id).first()
    db_member_id = user_db.member_id if user_db else None

    chosen_person = body.person_id
    chosen_member = body.member_id or db_member_id

    if chosen_person:
        # use numeric id as member URN (LinkedIn expects numeric member URNs)
        author = f"urn:li:member:{chosen_person}"
    elif chosen_member:
        author = f"urn:li:member:{chosen_member}"
    else:
        # fallback to token identity
        ts = userinfo_sub(access_token)
        if not ts:
            raise HTTPException(401, "Couldn't resolve any member/person id to test with")
        author = f"urn:li:member:{ts}"

    ok, ref = linkedin_api.post_text(access_token, author, body.text)

    # Return raw LinkedIn response info for debugging
    if ok:
        try:
            return {"status": "posted", "ref": ref.text}
        except Exception:
            return {"status": "posted"}

    if hasattr(ref, 'status_code'):
        return {"status": "error", "status_code": ref.status_code, "body": ref.text}
    if isinstance(ref, dict):
        return {"status": "error", "body": ref}
    return {"status": "error", "body": str(ref)}
