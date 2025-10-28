"""
Core application package for the FastAPI backend.

Modules are organised into config, database, services, routers, and middleware
to keep concerns separated and make the boilerplate easy to extend for new
projects.
"""

from .config import AppConfig, load_config

__all__ = ["AppConfig", "load_config"]
