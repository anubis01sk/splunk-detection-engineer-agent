"""
Splunk Agent API Package
========================

FastAPI-based REST API for the Splunk Detection Engineer Agent.
"""

from src.api.server import app, create_app

__all__ = ["app", "create_app"]
