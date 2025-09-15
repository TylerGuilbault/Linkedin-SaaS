import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    hf_api_token: str = os.getenv("HF_API_TOKEN", "")
    summarizer_model: str = os.getenv("SUMMARIZER_MODEL", "sshleifer/distilbart-cnn-12-6")
    rewriter_model: str = os.getenv("REWRITER_MODEL", "")
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./app.db")
    linkedin_client_id: str = os.getenv("LINKEDIN_CLIENT_ID", "")
    linkedin_client_secret: str = os.getenv("LINKEDIN_CLIENT_SECRET", "")
    linkedin_redirect_uri: str = os.getenv("LINKEDIN_REDIRECT_URI", "http://localhost:8000/auth/linkedin/callback")
    linkedin_scopes: str = os.getenv("LINKEDIN_SCOPES", "r_liteprofile r_emailaddress w_member_social")
    fernet_key: str = os.getenv("FERNET_KEY", "")

settings = Settings()
