from fastapi import APIRouter

router = APIRouter(prefix="/payments", tags=["payments"])

@router.post("/upgrade")
async def upgrade():
    return {
        "status": "payments_disabled",
        "message": "Self-hosted build — sabhi features unlocked hain."
    }

@router.get("/status")
async def payment_status():
    return {"tier": "enterprise", "method": "self_hosted"}

# Backward-compatibility stubs for legacy frontend calls
@router.post("/create-order")
async def create_order():
    return {
        "status": "payments_disabled",
        "message": "Self-hosted build — all features unlocked",
        "order_id": "self_hosted",
        "approval_url": None,
        "tier": "enterprise",
    }

@router.post("/capture-order")
async def capture_order():
    return {
        "status": "completed",
        "tier": "enterprise",
        "transaction_id": "self_hosted",
        "max_nodes": -1,
        "max_assets": -1,
        "max_users": -1,
    }
