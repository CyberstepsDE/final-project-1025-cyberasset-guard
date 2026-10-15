"""REST API for risk: asset risk summary and the scoring model.

Reading needs `findings:read` (all roles), like the findings themselves. The risk of a
single finding is part of the finding (GET /findings, /findings/{id}).
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..assets.models import Asset
from ..auth.dependencies import get_current_user, require
from ..auth.permissions import Permission
from ..database import get_session
from . import engine, service
from .models import AssetRisk
from .schemas import AssetRiskHistoryRead, AssetRiskRead

router = APIRouter(tags=["risk"], dependencies=[Depends(get_current_user)])
can_read = require(Permission.FINDINGS_READ)


def _asset(session: Session, asset_id: str) -> Asset:
    try:
        asset = session.get(Asset, str(uuid.UUID(asset_id)))
    except ValueError:
        asset = None
    if asset is None:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' was not found")
    return asset


@router.get("/risk/assets", response_model=list[AssetRiskRead], dependencies=[Depends(can_read)])
def list_asset_risk(session: Session = Depends(get_session)):
    """Risk summary of every assessed asset (assets without an entry were never assessed)."""
    rows = session.execute(select(AssetRisk, Asset.status).join(Asset, Asset.id == AssetRisk.asset_id)).all()
    result = []
    for row, asset_status in rows:
        item = AssetRiskRead.model_validate(row)
        item.asset_status = asset_status.value
        result.append(item)
    return result


@router.get("/assets/{asset_id}/risk/history", response_model=list[AssetRiskHistoryRead],
            dependencies=[Depends(can_read)], responses={404: {"description": "Asset not found"}})
def get_asset_risk_history(asset_id: str, limit: int = Query(100, ge=1, le=500),
                           session: Session = Depends(get_session)):
    """Changes of the asset's risk, newest first, with what triggered them."""
    return service.history(session, _asset(session, asset_id).id, limit)


@router.get("/assets/{asset_id}/risk", response_model=AssetRiskRead, dependencies=[Depends(can_read)],
            responses={404: {"description": "Asset not found"}})
def get_asset_risk(asset_id: str, session: Session = Depends(get_session)):
    """Highest risk of the asset's open findings. `assessed: false` = never assessed (not: no risk)."""
    asset = _asset(session, asset_id)
    row = session.get(AssetRisk, asset.id)
    result = AssetRiskRead.model_validate(row) if row else AssetRiskRead(asset_id=asset.id, assessed=False)
    result.asset_status = asset.status.value
    return result


@router.get("/risk/model", dependencies=[Depends(can_read)])
def risk_model():
    """The scoring weights and thresholds - every score can be explained."""
    return engine.model()
