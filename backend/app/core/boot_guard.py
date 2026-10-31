"""
Boot-time guard against booting AEGIS in production with default secrets.

`main.py` used to only log a `logger.critical(...)` warning when
`AEGIS_SECRET_KEY` still had its public default value -- boot continued
regardless (P0-9). This module makes that condition fatal in production, and
also refuses to boot with the well-known default admin password unless the
deployment explicitly runs as the public demo.

Kept dependency-free (no FastAPI / SQLAlchemy imports) so it can be unit
tested in isolation and imported early during `lifespan()`.
"""

# Must match app.config.Settings.AEGIS_SECRET_KEY default exactly.
DEFAULT_SECRET = "aegis-dev-secret-key-change-in-production"

# Must match the default used in app.config.Settings.AEGIS_ADMIN_PASSWORD.
DEFAULT_ADMIN_PASSWORD = "changeme-on-first-login"

# Passwords that are published in documentation/the public demo. They are only
# tolerated when AEGIS_DEMO_MODE is explicitly enabled.
DEMO_ADMIN_PASSWORDS = frozenset({DEFAULT_ADMIN_PASSWORD, "admin123456"})


def assert_production_secrets(
    env: str,
    secret_key: str,
    admin_password: str,
    default_admin_password: str = DEFAULT_ADMIN_PASSWORD,
    demo_mode: bool = False,
) -> None:
    """
    Raise RuntimeError if running in production with default/weak secrets.

    No-op for any env other than "production" (e.g. "development", "test").

    Args:
        env: current AEGIS_ENV value.
        secret_key: current AEGIS_SECRET_KEY value.
        admin_password: the admin password that would be seeded.
        default_admin_password: the known default admin password to compare against.
        demo_mode: when true, the published demo admin password is allowed.
            The signing secret is still required to be non-default.

    Raises:
        RuntimeError: listing every offending setting.
    """
    if env != "production":
        return

    bad = []
    if not secret_key or secret_key == DEFAULT_SECRET:
        bad.append("AEGIS_SECRET_KEY (set a strong, unique value)")
    weak_admin = (
        admin_password == default_admin_password
        or admin_password in DEMO_ADMIN_PASSWORDS
    )
    if weak_admin and not demo_mode:
        bad.append(
            "AEGIS_ADMIN_PASSWORD (set a strong, unique value, or enable "
            "AEGIS_DEMO_MODE for a read-only public demo)"
        )

    if bad:
        raise RuntimeError(
            "Refusing to start in production with insecure configuration: "
            + "; ".join(bad)
        )
