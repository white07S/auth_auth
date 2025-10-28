from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Sequence

from fastapi import HTTPException, status

from ..config import AppConfig


@dataclass
class RBACDecision:
    allowed: bool
    missing_roles: list[str]


class RBACService:
    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def groups_to_roles(self, group_ids: Iterable[str]) -> list[str]:
        roles: set[str] = set()
        for group_id in group_ids:
            for role in self._config.rbac.group_role_map.get(group_id, []):
                roles.add(role)
        return sorted(roles)

    def evaluate(self, required_roles: Sequence[str], user_roles: Sequence[str]) -> RBACDecision:
        required_set = set(required_roles)
        user_set = set(user_roles)
        if not required_roles:
            return RBACDecision(True, [])

        if self._config.rbac.evaluation_mode == "any_of":
            allowed = bool(required_set & user_set)
            missing = [] if allowed else list(required_set)
        else:
            missing = sorted(required_set - user_set)
            allowed = not missing

        return RBACDecision(allowed=allowed, missing_roles=missing)

    def guard_route(self, path: str, user_roles: Sequence[str]) -> None:
        required_roles = []
        for pattern, roles in self._config.rbac.route_policies.items():
            if path.startswith(pattern):
                required_roles.extend(roles)
        decision = self.evaluate(required_roles, user_roles)
        if not decision.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"message": "Access denied", "missing_roles": decision.missing_roles},
            )
