# app/services/linkedin_api.py
import httpx
from typing import Tuple, Dict, Any
from urllib.parse import urlencode, quote
from app.config import settings

AUTH_URL  = "https://www.linkedin.com/oauth/v2/authorization"
TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
UGC_URL   = "https://api.linkedin.com/v2/ugcPosts"

def auth_url(state: str) -> str:
    params = {
        "response_type": "code",
        "client_id": settings.linkedin_client_id,
        "redirect_uri": settings.linkedin_redirect_uri,
        "scope": settings.linkedin_scopes,
        "state": state,
    }
    qs = urlencode(params, quote_via=quote, safe=":/")
    return f"{AUTH_URL}?{qs}"

def exchange_code_for_token(code: str) -> Dict[str, Any]:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.linkedin_redirect_uri,
        "client_id": settings.linkedin_client_id,
        "client_secret": settings.linkedin_client_secret,
    }
    with httpx.Client(timeout=60) as c:
        r = c.post(TOKEN_URL, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
        r.raise_for_status()
        return r.json()

def post_text(access_token: str, author_urn: str, text: str) -> Tuple[bool, str]:
    payload = {
        "author": author_urn,
        "lifecycleState": "PUBLISHED",
        "specificContent": {
            "com.linkedin.ugc.ShareContent": {
                "shareCommentary": {"text": text},
                "shareMediaCategory": "NONE",
            }
        },
        "visibility": {"com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"},
    }
    try:
        with httpx.Client(timeout=60) as c:
            r = c.post(
                UGC_URL,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                    "X-Restli-Protocol-Version": "2.0.0",
                },
                json=payload,
            )
            print("[post_text] status:", r.status_code, flush=True)
            print("[post_text] request json:", payload, flush=True)
            print("[post_text] response text:", r.text, flush=True)
            if 200 <= r.status_code < 300:
                return True, r.text
            return False, r.text
    except Exception as e:
        return False, f"exception: {e}"
