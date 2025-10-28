from __future__ import annotations

from fastapi import APIRouter, Depends

from .. import dependencies

router = APIRouter(prefix="/graph", tags=["graph"])


@router.get("/me")
async def graph_me(
    access_token: str = Depends(dependencies.get_graph_access_token),
    container=Depends(dependencies.get_container),
):
    return await container.graph.get_user_profile(access_token)


@router.get("/groups")
async def graph_groups(
    access_token: str = Depends(dependencies.get_graph_access_token),
    container=Depends(dependencies.get_container),
):
    return await container.graph.get_user_groups(access_token)
