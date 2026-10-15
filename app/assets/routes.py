"""REST API for Asset Management.

Reading needs `assets:read` (all roles); changes need `assets:write` (analyst, admin).
Every change is audit-logged by the service in the same transaction.
"""
from __future__ import annotations

import uuid
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ..auth.dependencies import CurrentUser, require
from ..auth.permissions import Permission
from ..database import get_session
from . import service
from .models import AssetType, Criticality, Environment, InternetFacing, LifecycleStatus
from .schemas import AssetCreate, AssetList, AssetOptions, AssetRead, AssetUpdate

router = APIRouter(prefix="/assets", tags=["asset management"])

NOT_FOUND: dict[int | str, dict[str, Any]] = {404: {"description": "Asset not found"}}
can_read = require(Permission.ASSETS_READ)
can_write = require(Permission.ASSETS_WRITE)


def _asset_id(asset_id: str) -> str:
    """Normalize the path id. Malformed ids cannot exist, so they are 'not found' too."""
    try:
        return str(uuid.UUID(asset_id))
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' was not found") from None


def _get(session: Session, asset_id: str):
    try:
        return service.get_asset(session, _asset_id(asset_id))
    except service.AssetNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/options", response_model=AssetOptions, dependencies=[Depends(can_read)])
def asset_options():
    """Allowed values (and display labels) for the controlled fields."""
    return AssetOptions.build()


@router.get("", response_model=AssetList, dependencies=[Depends(can_read)])
def list_assets(
    session: Session = Depends(get_session),
    q: str | None = Query(None, max_length=200, description="Search name, IP address or hostname"),
    environment: Environment | None = None,
    criticality: Criticality | None = None,
    asset_type: AssetType | None = None,
    status_: LifecycleStatus | None = Query(None, alias="status"),
    internet_facing: InternetFacing | None = None,
    tag: str | None = Query(None, max_length=50),
    sort: Literal["updated", "name", "criticality"] = "updated",
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List, search and filter assets. All filters are optional and combined with AND."""
    filters = service.AssetFilter(q=q, environment=environment, criticality=criticality,
                                  asset_type=asset_type, status=status_,
                                  internet_facing=internet_facing, tag=tag)
    items, total = service.list_assets(session, filters, sort, limit, offset)
    return AssetList(items=items, total=total, limit=limit, offset=offset)


@router.post("", response_model=AssetRead, status_code=status.HTTP_201_CREATED)
def create_asset(data: AssetCreate, current: CurrentUser = Depends(can_write),
                 session: Session = Depends(get_session)):
    """Register a new asset. It receives a UUID and starts in lifecycle status 'active'."""
    return service.create_asset(session, data, current.ctx)


@router.get("/{asset_id}", response_model=AssetRead, responses=NOT_FOUND, dependencies=[Depends(can_read)])
def get_asset(asset_id: str, session: Session = Depends(get_session)):
    return _get(session, asset_id)


@router.patch("/{asset_id}", response_model=AssetRead, responses=NOT_FOUND)
def update_asset(asset_id: str, data: AssetUpdate, current: CurrentUser = Depends(can_write),
                 session: Session = Depends(get_session)):
    """Partial update. The id and created_at are preserved; updated_at is refreshed on change."""
    asset = _get(session, asset_id)
    return service.update_asset(session, asset.id, data, current.ctx)


@router.post("/{asset_id}/deactivate", response_model=AssetRead, responses=NOT_FOUND)
def deactivate_asset(asset_id: str, current: CurrentUser = Depends(can_write),
                     session: Session = Depends(get_session)):
    """Safe alternative to deletion: the asset stays stored and identifiable."""
    asset = _get(session, asset_id)
    return service.set_status(session, asset.id, LifecycleStatus.INACTIVE, current.ctx)


@router.post("/{asset_id}/activate", response_model=AssetRead, responses=NOT_FOUND)
def activate_asset(asset_id: str, current: CurrentUser = Depends(can_write),
                   session: Session = Depends(get_session)):
    asset = _get(session, asset_id)
    return service.set_status(session, asset.id, LifecycleStatus.ACTIVE, current.ctx)
