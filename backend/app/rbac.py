from __future__ import annotations

from typing import Dict, Iterable, List, Set, Tuple


class RBACResolver:
    def __init__(self, group_to_roles: Dict[str, List[str]], roles_to_permissions: Dict[str, List[str]]) -> None:
        self._group_to_roles = group_to_roles
        self._roles_to_permissions = roles_to_permissions

    def resolve(self, groups: Iterable[str]) -> Tuple[List[str], List[str]]:
        roles: Set[str] = set()
        for group_id in groups:
            roles.update(self._group_to_roles.get(group_id, []))
        permissions: Set[str] = set()
        for role in roles:
            mapped = self._roles_to_permissions.get(role, [])
            if "*" in mapped:
                permissions.add("*")
            else:
                permissions.update(mapped)
        if "*" in permissions:
            permissions = {"*"}
        return sorted(roles), sorted(permissions)

