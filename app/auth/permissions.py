"""Role-based access control: roles map to a fixed set of permissions.

Routes check *permissions*, never role names, so roles can be reshaped later
without touching every endpoint.
"""
from __future__ import annotations

import enum


class Role(str, enum.Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"


class Permission(str, enum.Enum):
    ASSETS_READ = "assets:read"
    ASSETS_WRITE = "assets:write"            # create, edit, deactivate / reactivate
    MONITORING_READ = "monitoring:read"
    MONITORING_RUN = "monitoring:run"        # run scans, manage schedules
    FINDINGS_READ = "findings:read"
    FINDINGS_WRITE = "findings:write"        # run correlation, change finding status, accept risk
    USERS_MANAGE = "users:manage"
    AUDIT_READ = "audit:read"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset({Permission.ASSETS_READ, Permission.MONITORING_READ, Permission.FINDINGS_READ}),
    Role.ANALYST: frozenset({Permission.ASSETS_READ, Permission.ASSETS_WRITE,
                             Permission.MONITORING_READ, Permission.MONITORING_RUN,
                             Permission.FINDINGS_READ, Permission.FINDINGS_WRITE}),
    Role.ADMIN: frozenset(Permission),
}

ROLE_LABELS = {Role.VIEWER: "Viewer", Role.ANALYST: "Analyst", Role.ADMIN: "Administrator"}


def permissions_for(role: Role) -> frozenset[Permission]:
    return ROLE_PERMISSIONS[Role(role)]
