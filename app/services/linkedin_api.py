# Create an article share (OG link)
def post_article_share(access_token: str, author_urn: str, url: str, text: str = "") -> tuple:
    payload = {
        "author": author_urn,
        "lifecycleState": "PUBLISHED",
        "specificContent": {
            "com.linkedin.ugc.ShareContent": {
                "shareCommentary": {"text": text},
                "shareMediaCategory": "ARTICLE",
                "media": [{"status": "READY", "originalUrl": url}]
            }
        },
        "visibility": {"com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"},
    }
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
        return r.status_code in (201, 202), r

# Register image upload
def register_image_upload(access_token: str, author_urn: str) -> dict:
    register_url = "https://api.linkedin.com/v2/assets?action=registerUpload"
    payload = {
        "registerUploadRequest": {
            "owner": author_urn,
            "recipes": ["urn:li:digitalmediaRecipe:feedshare-image"],
            "serviceRelationships": [{
                "relationshipType": "OWNER",
                "identifier": "urn:li:userGeneratedContent"
            }]
        }
    }
    with httpx.Client(timeout=60) as c:
        r = c.post(
            register_url,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        r.raise_for_status()
        return r.json()

# Upload image asset
def upload_image_asset(upload_url: str, image_bytes: bytes) -> bool:
    headers = {"Content-Type": "application/octet-stream"}
    with httpx.Client(timeout=60) as c:
        r = c.put(upload_url, headers=headers, content=image_bytes)
        return r.status_code in (201, 202)

# Create image share post
def post_image_share(access_token: str, author_urn: str, asset_urn: str, text: str = "") -> tuple:
    payload = {
        "author": author_urn,
        "lifecycleState": "PUBLISHED",
        "specificContent": {
            "com.linkedin.ugc.ShareContent": {
                "shareCommentary": {"text": text},
                "shareMediaCategory": "IMAGE",
                "media": [{"status": "READY", "media": asset_urn}]
            }
        },
        "visibility": {"com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"},
    }
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
        return r.status_code in (201, 202), r
# Exchange refresh_token for new access token
def exchange_refresh_for_token(refresh_token: str) -> dict:
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": settings.linkedin_client_id,
        "client_secret": settings.linkedin_client_secret,
    }
    with httpx.Client(timeout=httpx.Timeout(30, connect=5)) as c:
        r = c.post(
            TOKEN_URL,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        r.raise_for_status()
        return r.json()
# app/services/linkedin_api.py
import httpx
import time
from typing import Tuple, Dict, Any
from urllib.parse import urlencode, quote
from app.config import settings

AUTH_URL  = "https://www.linkedin.com/oauth/v2/authorization"
TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
UGC_URL   = "https://api.linkedin.com/v2/ugcPosts"

# Helper: log request id if present in LinkedIn response
def log_request_id(resp):
    req_id = resp.headers.get("x-restli-request-id")
    if req_id:
        print(f"[LinkedIn] request id: {req_id}", flush=True)

# Helper: retry logic for LinkedIn API
def linkedin_request_with_retry(method, url, **kwargs):
    max_attempts = 4
    backoff = 2
    for attempt in range(1, max_attempts + 1):
        try:
            with httpx.Client(timeout=httpx.Timeout(30, connect=5)) as c:
                resp = c.request(method, url, **kwargs)
            log_request_id(resp)
            if resp.status_code in (429, 500, 502, 503, 504):
                print(f"[LinkedIn] {url} attempt {attempt} got {resp.status_code}, retrying...", flush=True)
                if attempt < max_attempts:
                    time.sleep(backoff * attempt)
                    continue
            return resp
        except httpx.RequestError as e:
            print(f"[LinkedIn] Request error: {e}", flush=True)
            if attempt < max_attempts:
                time.sleep(backoff * attempt)
                continue
            raise
    raise Exception(f"LinkedIn API failed after {max_attempts} attempts")

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
    # Harden: use retry logic and timeouts
    resp = linkedin_request_with_retry(
        "POST", TOKEN_URL,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    resp.raise_for_status()
    data = resp.json()
    # Capture refresh_token if present
    refresh_token = data.get("refresh_token")
    if refresh_token:
        data["refresh_token"] = refresh_token
    return data

# New: exchange refresh_token for new access token
def exchange_refresh_for_token(refresh_token: str) -> Dict[str, Any]:
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": settings.linkedin_client_id,
        "client_secret": settings.linkedin_client_secret,
    }
    resp = linkedin_request_with_retry(
        "POST", TOKEN_URL,
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    resp.raise_for_status()
    return resp.json()

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
            log_request_id(r)
            if r.status_code in (201, 202):
                return True, r
            # Bubble up error details for 4xx/5xx
            error_info = {
                "status": r.status_code,
                "body": r.text
            }
            try:
                err_json = r.json()
                error_info["serviceErrorCode"] = err_json.get("serviceErrorCode")
                error_info["message"] = err_json.get("message")
            except Exception:
                pass
            return False, error_info
    except Exception as e:
        print("[post_text] error:", e, flush=True)
        return False, {"exception": str(e)}
