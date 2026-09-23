from fastapi import APIRouter

from app import __creator__, __license__, __project__, __version__
from app.core.config import get_settings
from app.plugins import registry

router = APIRouter(tags=["about"])

# Upstream attribution is project metadata, not configuration: branding changes what the UI calls
# itself, this block keeps the origin of the software discoverable (Apache-2.0 NOTICE, section 4(d)).
UPSTREAM = {
    "name": __project__,
    "full_name": "Agentless Environment-Aware Detection Engineering & Event Intelligence Platform",
    "original_creator": __creator__,
    "license": __license__,
    "version": __version__,
}


@router.get("/about")
def about():
    s = get_settings()
    customized = bool(s.organization_name) or s.project_name != __project__
    return {
        "branding": {
            "project_name": s.project_name,
            "project_description": s.project_description,
            "organization_name": s.organization_name,
            "organization_logo": s.organization_logo,
            "primary_brand_color": s.primary_brand_color,
            "dashboard_title": s.dashboard_title,
            "footer_text": s.footer_text,
            "customized": customized,
        },
        "upstream": UPSTREAM,
        "plugins": registry.loaded_plugins,
        "siem_adapters": sorted(registry.siem_adapters),
        "event_parsers": sorted(registry.event_parsers),
    }
