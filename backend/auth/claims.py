from __future__ import annotations

from typing import Dict, Iterable, List, Mapping, Sequence, Tuple

from ..config import Config
from ..bff.graph import GraphClient


def extract_user(id_token_claims: Mapping[str, object]) -> Dict[str, str | None]:
    name = _as_str(id_token_claims.get("name")) or _as_str(id_token_claims.get("preferred_username"))
    email = _as_str(id_token_claims.get("preferred_username")) or _as_str(id_token_claims.get("email"))
    tenant_id = _as_str(id_token_claims.get("tid"))
    oid = _as_str(id_token_claims.get("oid"))
    return {"name": name or email or "Unknown user", "email": email, "tenant_id": tenant_id, "oid": oid}


async def resolve_roles_and_routes(
    *,
    config: Config,
    id_token_claims: Mapping[str, object],
    access_token: str,
    graph_client: GraphClient,
) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    group_ids = list(_groups_from_claims(id_token_claims))
    if not group_ids and _has_group_overage(id_token_claims):
        group_ids = await graph_client.get_member_groups(access_token)

    roles = _groups_to_roles(group_ids, config)
    allowed_routes = _roles_to_routes(roles, config.route_policies)
    return tuple(sorted(set(roles))), tuple(sorted(set(allowed_routes)))


def _as_str(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def _groups_from_claims(claims: Mapping[str, object]) -> Iterable[str]:
    groups = claims.get("groups")
    if isinstance(groups, list):
        for group in groups:
            if isinstance(group, str):
                yield group


def _has_group_overage(claims: Mapping[str, object]) -> bool:
    claim_names = claims.get("_claim_names")
    if isinstance(claim_names, Mapping):
        return "groups" in claim_names
    return False


def _groups_to_roles(group_ids: Sequence[str], config: Config) -> List[str]:
    roles: List[str] = []
    for role, configured_groups in config.rbac.group_to_role.items():
        if any(group_id in configured_groups for group_id in group_ids):
            roles.append(role)
    return roles


def _roles_to_routes(roles: Sequence[str], route_policies: Mapping[str, Sequence[str]]) -> List[str]:
    allowed: List[str] = []
    for route, permitted_roles in route_policies.items():
        if any(role in permitted_roles for role in roles):
            allowed.append(route)
    return allowed
