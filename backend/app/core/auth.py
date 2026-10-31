import os
import secrets
from datetime import datetime, timedelta
from typing import Optional, Union

from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.demo import configure_demo_identity, is_demo_auth, is_demo_client
from app.database import get_db
from app.models.client import Client

import bcrypt

# Password hashing
def hash_password(password: str) -> str:
    pwd_bytes = password.encode('utf-8')[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        pwd_bytes = plain_password.encode('utf-8')[:72]
        hash_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception:
        return False

# Security schemes
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


def generate_api_key() -> str:
    return f"c6_{secrets.token_urlsafe(32)}"


# --- JWT for client-based auth (legacy / programmatic) ---

def create_client_jwt_token(client_id: str, client_name: str) -> str:
    """Create a JWT token for client-based (API key) authentication."""
    payload = {
        "sub": client_id,
        "name": client_name,
        "type": "client",
        "iss": "aegis",
        "exp": datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRE_MINUTES),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, settings.AEGIS_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


# --- JWT for user-based auth (RBAC) ---

def create_user_jwt_token(user_id: str, email: str, role: str, client_id: Optional[str]) -> str:
    """Create a JWT token for user-based (email/password) authentication."""
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "client_id": client_id,
        "type": "user",
        "iss": "aegis",
        "exp": datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRE_MINUTES),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, settings.AEGIS_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_jwt_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            settings.AEGIS_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require_iss": False},  # Don't reject legacy tokens without iss
        )
        # Validate issuer if present (new tokens always have it)
        if "iss" in payload and payload["iss"] != "aegis":
            raise HTTPException(status_code=401, detail="Invalid token issuer")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# --- Unified auth context ---

class AuthContext:
    """Represents the authenticated entity -- either a User or an API-key Client."""

    def __init__(
        self,
        client: Client,
        user=None,
        role: str = "admin",
        user_id: Optional[str] = None,
        email: Optional[str] = None,
    ):
        self.client = client
        self.user = user
        self.role = role
        self.user_id = user_id
        self.email = email

    @property
    def client_id(self) -> str:
        return self.client.id

    @property
    def is_api_key(self) -> bool:
        return self.user is None

    @property
    def is_demo(self) -> bool:
        """True when this request belongs to the public demo tenant."""
        return is_demo_auth(self)


async def get_auth_context(
    request: Request,
    api_key: Optional[str] = Security(api_key_header),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> AuthContext:
    """
    Unified authentication dependency.
    Accepts either X-API-Key header (grants admin role) or Bearer JWT (user or client token).
    """
    # --- Try API key first ---
    if api_key:
        result = await db.execute(select(Client).where(Client.api_key == api_key))
        client = result.scalar_one_or_none()
        if client:
            return AuthContext(client=client, role="admin")

    # --- Try Bearer JWT ---
    if bearer:
        payload = decode_jwt_token(bearer.credentials)
        token_type = payload.get("type", "client")

        if token_type == "user":
            # User JWT -- import here to avoid circular imports
            from app.models.user import User

            user_id = payload.get("sub")
            if not user_id:
                raise HTTPException(status_code=401, detail="Invalid token payload")

            result = await db.execute(select(User).where(User.id == user_id))
            user = result.scalar_one_or_none()
            if not user or not user.is_active:
                raise HTTPException(status_code=401, detail="User not found or inactive")

            # Resolve client
            client = None
            if user.client_id:
                result = await db.execute(select(Client).where(Client.id == user.client_id))
                client = result.scalar_one_or_none()

            if not client:
                raise HTTPException(status_code=403, detail="User is not associated with a valid tenant")

            # A seeded admin may be flagged to rotate a weak/default password.
            # Enforce it (except for the public demo, which must stay usable)
            # but leave read-of-self + change-password reachable so the caller
            # can actually complete the rotation.
            if (
                getattr(user, "must_change_password", False)
                and settings.AEGIS_ENV == "production"
                and not settings.AEGIS_DEMO_MODE
            ):
                path = request.url.path
                allowed = (
                    "/api/v1/auth/change-password",
                    "/api/v1/auth/me",
                    "/api/v1/auth/user/login",
                )
                if not any(path == p or path.startswith(p + "/") for p in allowed):
                    raise HTTPException(
                        status_code=403,
                        detail=(
                            "Password change required before using the API. "
                            "Call POST /api/v1/auth/change-password."
                        ),
                    )

            return AuthContext(
                client=client,
                user=user,
                role=user.role.value if hasattr(user.role, "value") else user.role,
                user_id=user.id,
                email=user.email,
            )

        else:
            # Legacy client JWT
            client_id = payload.get("sub")
            if client_id:
                result = await db.execute(select(Client).where(Client.id == client_id))
                client = result.scalar_one_or_none()
                if client:
                    return AuthContext(client=client, role="admin")

    raise HTTPException(status_code=401, detail="Invalid authentication credentials")


# --- Backward-compatible dependency ---

async def get_current_client(
    auth: AuthContext = Depends(get_auth_context),
) -> Client:
    """Backward-compatible: returns the Client object from auth context."""
    return auth.client


# --- Role-checking dependencies ---

async def require_admin(
    auth: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    """Only admin role (or API key, which is implicitly admin)."""
    if auth.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin access required",
        )
    return auth


async def require_analyst(
    auth: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    """Admin or analyst role."""
    if auth.role not in ("admin", "analyst"):
        raise HTTPException(
            status_code=403,
            detail="Analyst or admin access required",
        )
    return auth


async def require_viewer(
    auth: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    """Any authenticated user (admin, analyst, or viewer)."""
    # If we got here, the user is already authenticated
    return auth


# --- Seed functions ---

async def seed_demo_client(db: AsyncSession) -> Client:
    """Create a demo client if none exist.

    On a deliberate public demo (AEGIS_DEMO_MODE=true) the tenant always owns
    the published demo key, so the advertised credentials keep working on a
    fresh database. A normal self-host gets a random key.
    """
    published_key = (
        (settings.AEGIS_PUBLIC_DEMO_API_KEY or "").strip()
        if settings.AEGIS_DEMO_MODE
        else ""
    )

    result = await db.execute(select(Client).where(Client.slug == "demo"))
    existing = result.scalar_one_or_none()
    if existing:
        if published_key and existing.api_key != published_key:
            existing.api_key = published_key
            await db.commit()
            await db.refresh(existing)
        return existing

    demo_client = Client(
        name="AEGIS Demo",
        slug="demo",
        api_key=published_key or generate_api_key(),
        settings={
            "scan_interval": 3600,
            "auto_response": True,
            "notification_channels": ["webhook"],
            "notify_on_critical": True,
            "notify_on_high": True,
            "notify_on_actions": True,
            "email_enabled": False,
            "email_recipients": [],
        },
        guardrails={
            "block_ip": "auto_approve",
            "isolate_host": "auto_approve",
            "revoke_creds": "auto_approve",
            "shutdown_service": "auto_approve",
            "firewall_rule": "auto_approve",
            "quarantine_file": "auto_approve",
            "kill_process": "auto_approve",
            "disable_account": "auto_approve",
            "network_segment": "auto_approve",
            "counter_attack": "auto_approve",
        },
    )
    db.add(demo_client)
    await db.commit()
    await db.refresh(demo_client)
    return demo_client


async def seed_default_admin(db: AsyncSession, client: Client):
    """Create default admin user if no users exist. Returns the admin user."""
    from app.models.user import User, UserRole

    result = await db.execute(select(User).limit(1))
    existing = result.scalar_one_or_none()
    if existing:
        return existing

    weak_password = (
        settings.AEGIS_ADMIN_PASSWORD == "changeme-on-first-login"
        or settings.AEGIS_ADMIN_PASSWORD == "admin123456"
    )
    admin_user = User(
        email="admin@aegis.local",
        password_hash=hash_password(settings.AEGIS_ADMIN_PASSWORD),
        name="Admin",
        role=UserRole.admin,
        client_id=client.id,
        is_active=True,
        # Only ask for a rotation when the deployment actually booted with a
        # published/default password. The public demo is exempt so the
        # advertised login keeps working.
        must_change_password=bool(weak_password and not settings.AEGIS_DEMO_MODE),
    )
    db.add(admin_user)
    await db.commit()
    await db.refresh(admin_user)
    return admin_user
