"""
IRONCLAD Server Route Modules.
"""

from ironclad.server.routes.analysis import router as analysis_router
from ironclad.server.routes.containment import router as containment_router
from ironclad.server.routes.incidents import router as incidents_router
from ironclad.server.routes.loss_control import router as loss_control_router
from ironclad.server.routes.threat_intel import router as threat_intel_router
from ironclad.server.routes.upload import router as upload_router

__all__ = [
    "upload_router",
    "analysis_router",
    "incidents_router",
    "containment_router",
    "threat_intel_router",
    "loss_control_router",
]
