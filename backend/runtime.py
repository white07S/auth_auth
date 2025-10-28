from __future__ import annotations

from dataclasses import dataclass

from .config import Config
from .auth.sessions import SessionManager
from .auth.ms_client import MsalClient
from .bff.graph import GraphClient


@dataclass
class RuntimeContext:
    config: Config
    session_manager: SessionManager
    msal_client: MsalClient
    graph_client: GraphClient
