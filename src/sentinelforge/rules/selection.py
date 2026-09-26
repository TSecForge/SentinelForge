"""Rule selection: does a rule template apply to an environment profile, and why."""

from sentinelforge.schemas.profile import EnvironmentProfile
from sentinelforge.schemas.rule import RuleDefinition

# Rules on these platforms only make sense when the technology exists.
IMPLIED_TECH = {"docker": "Docker", "kubernetes": "Kubernetes"}


def applicability(defn: RuleDefinition, profile: EnvironmentProfile) -> tuple[bool, str]:
    reasons = []
    if defn.platform in ("windows", "linux"):
        if profile.platform != defn.platform:
            return False, f"rule targets {defn.platform}; host platform is {profile.platform}"
        reasons.append(f"host platform is {defn.platform}")
    aw = defn.applies_when
    techs = list(aw.technologies)
    if defn.platform in IMPLIED_TECH and IMPLIED_TECH[defn.platform] not in techs:
        techs.append(IMPLIED_TECH[defn.platform])
    if aw.platforms and profile.platform not in aw.platforms:
        return False, f"requires platform in {aw.platforms}"
    if techs:
        hit = [t for t in techs if t in profile.technologies]
        if not hit:
            return False, f"requires {' or '.join(techs)}; not discovered on this host"
        for t in hit:
            why = "; ".join(profile.evidence.get(t, [])[:2])
            reasons.append(f"{t} discovered ({why})" if why else f"{t} discovered")
    if aw.environment_types:
        hit = [t for t in aw.environment_types if t in profile.environment_type]
        if not hit:
            return False, f"requires environment type {' or '.join(aw.environment_types)}"
        reasons.append(f"environment type {', '.join(hit)}")
    return True, "; ".join(reasons) or "applies to all environments"
