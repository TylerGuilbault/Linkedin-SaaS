# POST /auth/linkedin/refresh { user_id }
from pydantic import BaseModel

class RefreshIn(BaseModel):
    user_id: int

router = APIRouter(prefix="/auth/linkedin", tags=["linkedin-auth"])

@router.post("/refresh")
def refresh_linkedin_token(body: RefreshIn, db: Session = Depends(get_db)):
    refresh_token = crud_tokens.get_latest_refresh_token(db, user_id=body.user_id)
    if not refresh_token:
        return error_response(400, "No refresh_token found for this user_id.")
    try:
        token_resp = linkedin_api.exchange_refresh_for_token(refresh_token)
    except Exception as e:
        return error_response(400, f"LinkedIn refresh failed: {e}")
    access_token = token_resp.get("access_token")
    expires_in = token_resp.get("expires_in", 3600)
    new_refresh_token = token_resp.get("refresh_token", refresh_token)
    if not access_token:
        return error_response(400, "No access_token in LinkedIn response.", token_resp)
    crud_tokens.save_linkedin_token(db, body.user_id, access_token, expires_in, new_refresh_token)
    return {"status": "ok", "access_token": "updated", "expires_in": expires_in}
# Centralized error response helper
def error_response(status_code: int, message: str, details: dict = None):
    # Never include secrets or sensitive config in error details
    safe_details = {k: v for k, v in (details or {}).items() if k != "client_secret"}
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "error",
            "message": message,
            "details": safe_details,
        },
    )
# app/routers/auth_linkedin.py
import secrets
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy.orm import Session

from app.deps import get_db
from app.config import settings
import app.services.linkedin_api as linkedin_api
from app.db import crud_tokens

router = APIRouter(prefix="/auth/linkedin", tags=["linkedin-auth"])
STATE_STORE: set[str] = set()

@router.get("/login")
def login() -> RedirectResponse:
    if not settings.linkedin_client_id or not settings.linkedin_client_secret or not settings.fernet_key:
        raise HTTPException(500, "Missing LinkedIn or FERNET config in .env")
    state = secrets.token_urlsafe(24)
    STATE_STORE.add(state)
    url = linkedin_api.auth_url(state)
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
        return error_response(400, error, {"error_description": error_description})

    if not code or not state:
        return error_response(400, "Missing ?code or ?state in callback")

    if state not in STATE_STORE:
        return error_response(400, "Invalid state")
    STATE_STORE.discard(state)

    token_resp = linkedin_api.exchange_code_for_token(code)
    access_token = token_resp.get("access_token")
    expires_in = token_resp.get("expires_in", 3600)
    id_token = token_resp.get("id_token")  # present because we requested 'openid'

    if not access_token:
        # Never leak secrets in error details
        return error_response(400, "Token exchange failed", {k: v for k, v in token_resp.items() if k != "client_secret"})

    # Create local user + store encrypted access token
    user = crud_tokens.upsert_user(db, email=None)
    crud_tokens.save_linkedin_token(db, user.id, access_token, expires_in)

    # If using OpenID, pull the member id from the id_token's 'sub'
    member_id = linkedin_api.extract_sub_from_id_token(id_token) if id_token else None
    if member_id:
        print("LinkedIn member_id (sub):", member_id, flush=True)

    return {
        "status": "ok",
        "user_id": user.id,
        "expires_in": expires_in,
        "has_id_token": bool(id_token),
        "member_id": member_id,
    }
