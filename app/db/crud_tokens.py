from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from typing import Optional
from app.db import models; from app.db import token_crypto

def upsert_user(db: Session, email: Optional[str] = None) -> models.User:
    if email:
        u = db.query(models.User).filter(models.User.email == email).first()
        if u:
            return u
    u = models.User(email=email)
    db.add(u)
    db.commit()
    db.refresh(u)
    return u

def save_linkedin_token(db: Session, user_id: int, access_token: str, expires_in: Optional[int]) -> models.LinkedInToken:
    enc = token_crypto.encrypt_token(access_token)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in or 3600)
    tok = models.LinkedInToken(user_id=user_id, access_token_encrypted=enc, expires_at=expires_at)
    db.add(tok)
    db.commit()
    db.refresh(tok)
    return tok

def get_latest_token(db: Session, user_id: int) -> Optional[models.LinkedInToken]:
    return (
        db.query(models.LinkedInToken)
        .filter(models.LinkedInToken.user_id == user_id)
        .order_by(models.LinkedInToken.id.desc())
        .first()
    )

