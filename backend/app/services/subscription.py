"""
Self-hosted build — Subscription lock removed (All features unlocked, enterprise tier for everyone).
"""

from typing import Any

TIERS: dict[str, dict] = {
    "free": {
        "label": "Enterprise",
        "max_nodes": -1,   # unlimited
        "max_assets": -1,  # unlimited
        "max_users": -1,   # unlimited
        "features": ["*"],
    },
    "enterprise": {
        "label": "Enterprise",
        "max_nodes": -1,   # unlimited
        "max_assets": -1,  # unlimited
        "max_users": -1,   # unlimited
        "features": ["*"],
    },
}

FEATURE_LABELS: dict[str, str] = {}


def get_tier(user_id: str = "") -> str:
    return "enterprise"


def is_feature_enabled(user_id: str = "", feature: str = "") -> bool:
    return True


def get_limits(user_id: str = "") -> dict:
    return {
        "nodes": -1,     # unlimited
        "assets": -1,
        "users": -1,
        "all_features": True,
    }


def get_tier_config(tier_name: str = "") -> dict:
    return TIERS["enterprise"]


def check_feature(client: Any = None, feature: str = "") -> bool:
    """Always return True — all features unlocked in self-hosted mode."""
    return True


def require_feature(client: Any = None, feature: str = "", tier: str = "enterprise") -> None:
    """No-op — never block or raise 403 in self-hosted mode."""
    return


def check_quota(client: Any = None, resource: str = "", current_count: int = 0) -> bool:
    """Always return True — unlimited quotas in self-hosted mode."""
    return True
