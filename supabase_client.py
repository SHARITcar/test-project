import os
from supabase import create_client, Client

_url: str = os.getenv("SUPABASE_URL", "")
_anon_key: str = os.getenv("SUPABASE_ANON_KEY", "")

if not _url or not _anon_key:
    raise RuntimeError("SUPABASE_URL and SUPABASE_ANON_KEY must be set in .env")

# Shared anon client — auth operations only (sign_up, sign_in, get_user, reset_password).
# Do NOT use this for table queries — use db_for(token) instead.
supabase: Client = create_client(_url, _anon_key)


def get_user_from_token(access_token: str):
    """Verify a Supabase JWT and return the user object, or None if invalid/expired."""
    try:
        return supabase.auth.get_user(access_token).user
    except Exception:
        return None


def get_token_from_request(request) -> str | None:
    """Extract Bearer JWT from the Authorization header."""
    header = request.headers.get("Authorization", "").strip()
    if header.lower().startswith("bearer "):
        token = header[7:].strip()
        return token or None
    return None


def db_for(access_token: str) -> Client:
    """
    Return a Supabase client with the user's JWT set on the PostgREST layer.
    This ensures RLS policies evaluate auth.uid() correctly for each user.
    Use this for ALL table queries inside request handlers.
    """
    client = create_client(_url, _anon_key)
    client.postgrest.auth(access_token)
    return client
