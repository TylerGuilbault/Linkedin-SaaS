# app/routers/auth_linkedin.py
import secrets
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy.orm import Session

from app.deps import get_db
from app.config import settings
import app.services.linkedin_api as linkedin_api
from app.services.linkedin_api import userinfo_sub, me_id
from app.db import crud_tokens
from app.db.token_crypto import decrypt_token as _dec
from app.db.models import User

# Router must be defined after imports
router = APIRouter(prefix="/auth/linkedin", tags=["linkedin-auth"])

# simple in-memory state store (fine for local dev)
STATE_STORE: set[str] = set()

@router.get("/me")
def me():
    # simple health/config sanity
    return {
        "status": "ok",
        "has_client_id": bool(settings.linkedin_client_id),
        "has_secret": bool(settings.linkedin_client_secret),
        "has_fernet": bool(settings.fernet_key),
        "redirect_uri": settings.linkedin_redirect_uri,
    }

@router.get("/login")
def login() -> RedirectResponse:
    if not settings.linkedin_client_id or not settings.linkedin_client_secret or not settings.fernet_key:
        raise HTTPException(500, "Missing LinkedIn or FERNET config in .env")
    state = secrets.token_urlsafe(24)
    STATE_STORE.add(state)
    # Request OpenID 'profile' plus w_member_social only (r_liteprofile removed per app authorization)
    scopes = "openid profile w_member_social"
    url = linkedin_api.auth_url(state, scopes=scopes)
    print("AUTH_URL =>", url, flush=True)
    return RedirectResponse(url)

@router.get("/callback")
def callback(
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
    db: Session = Depends(get_db),
):
    # If LinkedIn sends an error (e.g., unauthorized_scope_error), show it cleanly
    if error:
        if state in STATE_STORE:
            STATE_STORE.discard(state)
        return JSONResponse(
            status_code=400,
            content={"status": "error", "error": error, "error_description": error_description},
        )

    if not code or not state:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "Missing ?code or ?state in callback"},
        )

    if state not in STATE_STORE:
        raise HTTPException(400, "Invalid state")
    STATE_STORE.discard(state)

    token_resp = linkedin_api.exchange_code_for_token(code)
    access_token = token_resp.get("access_token")
    expires_in = token_resp.get("expires_in", 3600)
    id_token = token_resp.get("id_token")

    if not access_token:
        raise HTTPException(400, f"Token exchange failed: {token_resp}")

    # Extract member_id from id_token.sub (OpenID Connect). Do NOT call /v2/me here.
    member_id = linkedin_api.extract_sub_from_id_token(id_token) if id_token else ""

    # If we have an OpenID sub (member_id), try to reuse an existing User with that member_id.
    user = None
    if member_id:
        user = db.query(User).filter(User.member_id == member_id).first()

    # If no matching user, create one
    if not user:
        user = crud_tokens.upsert_user(db, email=None)

    # Save token for the resolved user
    crud_tokens.save_linkedin_token(db, user.id, access_token, expires_in)

    # Persist member_id on the user row if we have one and it's not set
    if member_id:
        try:
            if not user.member_id:
                crud_tokens.set_user_member_id(db, user.id, member_id)
        except Exception:
            # non-fatal: we still return success with the token saved
            print("Failed to persist member_id on user", flush=True)

    return {
        "status": "ok",
        "user_id": user.id,
        "expires_in": expires_in,
        "has_id_token": bool(id_token),
        "member_id": member_id or None,
    }


if settings.enable_dev_endpoints:
    @router.get("/callback_no_state")
    def callback_no_state(
        code: Optional[str] = None,
        db: Session = Depends(get_db),
    ):
        """Dev helper: Exchange a code for tokens without validating state. Disabled by default.
        Returns the same JSON as the normal callback.
        """
        if not code:
            return JSONResponse(status_code=400, content={"status": "error", "message": "Missing code"})

        token_resp = linkedin_api.exchange_code_for_token(code)
        access_token = token_resp.get("access_token")
        expires_in = token_resp.get("expires_in", 3600)
        id_token = token_resp.get("id_token")
        refresh_token = token_resp.get("refresh_token")

        if not access_token:
            raise HTTPException(400, f"Token exchange failed: {token_resp}")

        # Extract member_id from id_token.sub (OpenID Connect). Do NOT call /v2/me here.
        member_id = linkedin_api.extract_sub_from_id_token(id_token) if id_token else ""

        # If we have an OpenID sub (member_id), try to reuse an existing User with that member_id.
        user = None
        if member_id:
            user = db.query(User).filter(User.member_id == member_id).first()

        # If no matching user, create one
        if not user:
            user = crud_tokens.upsert_user(db, email=None)

        # Save token for the resolved user
        crud_tokens.save_linkedin_token(db, user.id, access_token, expires_in, refresh_token)

        # Persist member_id on the user row if we have one and it's not set
        if member_id:
            try:
                if not user.member_id:
                    crud_tokens.set_user_member_id(db, user.id, member_id)
            except Exception:
                print("Failed to persist member_id on user", flush=True)

        return {
            "status": "ok",
            "user_id": user.id,
            "expires_in": expires_in,
            "has_id_token": bool(id_token),
            "member_id": member_id or None,
        }

# Debug helper to compare token owner and stored member_id
@router.get("/debug/whoami")
def whoami(user_id: int = Query(...), db: Session = Depends(get_db)):
    tok = crud_tokens.get_latest_token(db, user_id=user_id)
    if not tok:
        return {"status": "no_token"}

    from app.db import token_crypto
    access_token = token_crypto.decrypt_token(tok.access_token_encrypted)
    token_sub = userinfo_sub(access_token) or None

    user = db.query(User).filter(User.id == user_id).first()
    db_member_id = user.member_id if user else None
    db_person_id = user.person_id if user else None

    return {
        "status": "ok",
        "user_id": user_id,
        "openid_sub": token_sub,
        "person_id": db_person_id,
        "db_member_id": db_member_id,
        "author_person_urn": f"urn:li:person:{db_person_id}" if db_person_id else None,
        "author_member_urn": f"urn:li:member:{token_sub}" if token_sub else None,
        "match": bool(token_sub and db_member_id and token_sub == db_member_id),
    }


@router.post("/save_person_id")
def save_person_id(user_id: int, db: Session = Depends(get_db)):
    """Call /v2/me with the stored access token and persist numeric person id to the User row if available.
    On failure, include LinkedIn's status and response body to aid debugging (e.g., missing scope or error).
    """
    tok = crud_tokens.get_latest_token(db, user_id=user_id)
    if not tok:
        raise HTTPException(400, "No token for user_id")
    access = _dec(tok.access_token_encrypted)
    pid, status, body = linkedin_api.get_person_id_with_response(access)
    if not pid:
        # Return LinkedIn response details in the error so the client (PowerShell) can see why it failed
        msg = "Could not obtain numeric person id from /v2/me; token likely missing profile scope. Re-login via /auth/linkedin/login."
        details = {"linkedin_status": status, "linkedin_body": body}
        raise HTTPException(400, f"{msg} details={details}")
    # persist
    try:
        from app.db import crud_tokens as ct
        ct.set_user_person_id(db, user_id, pid)
    except Exception as e:
        raise HTTPException(500, f"Failed to persist person id: {e}")
    return {"status": "ok", "person_id": pid}


@router.post("/set_person_id")
def set_person_id(user_id: int, person_id: str, db: Session = Depends(get_db)):
    """Admin helper: persist a numeric person id for a user (useful if you already know the digits)."""
    if not str(person_id).isdigit():
        raise HTTPException(400, "person_id must be digits only")
    try:
        from app.db import crud_tokens as ct
        ct.set_user_person_id(db, user_id, person_id)
    except Exception as e:
        raise HTTPException(500, f"Failed to persist person id: {e}")
    return {"status": "ok", "person_id": person_id}


@router.post("/set_member_id")
def set_member_id(user_id: int, member_id: str, db: Session = Depends(get_db)):
    """Admin helper: persist an OpenID member_id (the id_token 'sub') for a user.
    Use this to manually set the member_id that will be used as urn:li:member:{member_id}.
    """
    if not member_id or not isinstance(member_id, str):
        raise HTTPException(400, "member_id must be a non-empty string")
    # basic validation: disallow spaces and control chars
    if any(c.isspace() for c in member_id):
        raise HTTPException(400, "member_id must not contain whitespace")
    try:
        from app.db import crud_tokens as ct
        ct.set_user_member_id(db, user_id, member_id)
    except Exception as e:
        raise HTTPException(500, f"Failed to persist member id: {e}")
    return {"status": "ok", "member_id": member_id}


@router.get("/me_raw")
def me_raw(user_id: int, db: Session = Depends(get_db)):
    """Dev helper: return the raw /v2/me response (status, headers, text, json) using the stored token."""
    tok = crud_tokens.get_latest_token(db, user_id=user_id)
    if not tok:
        raise HTTPException(400, "No token for user_id")
    access = _dec(tok.access_token_encrypted)
    out = linkedin_api.get_me_raw(access)
    return {"status": "ok", "me_raw": out}


@router.post("/refresh")
def refresh(body: dict, db: Session = Depends(get_db)):
    """Use stored refresh token to obtain a new access token and persist it.
    Expects JSON: {"user_id": <int>}.
    """
    user_id = body.get("user_id") if isinstance(body, dict) else None
    if not user_id:
        raise HTTPException(400, "Missing user_id in request body")

    # Get the refresh token plaintext from crud helper (it returns the decrypted token or None)
    plain_refresh = crud_tokens.get_latest_refresh_token(db, user_id)
    if not plain_refresh:
        raise HTTPException(400, "No refresh token available for this user")

    try:
        resp = linkedin_api.exchange_refresh_for_token(plain_refresh)
    except Exception as e:
        raise HTTPException(401, f"LinkedIn refresh failed: {e}")

    new_at = resp.get("access_token")
    new_exp = resp.get("expires_in", 3600)
    if not new_at:
        raise HTTPException(400, f"No access_token in refresh response: {resp}")

    # Persist new access token on the latest token row
    crud_tokens.update_access_token_only(db, user_id, new_at, new_exp)

    return {"status": "ok", "access_token": "updated", "expires_in": new_exp}
