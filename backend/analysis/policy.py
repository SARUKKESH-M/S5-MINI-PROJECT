"""
CodeSentinel — Step 6T-1: Analysis Configuration & Policy Profiles

Defines configurable security analysis profiles (default, strict, ci, developer).
Enforces threshold controls, file limits, and review/block decision thresholds while
preserving baseline security protections.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

VALID_SEVERITY_THRESHOLDS = {"info", "low", "medium", "high", "critical"}
VALID_REVIEW_ACTIONS = {"allow", "review", "block"}


@dataclass
class AnalysisPolicy:
    name: str
    severity_threshold: str = "info"
    max_files: int = 500
    review_action: str = "review"
    block_action: str = "block"
    enabled_categories: List[str] = field(default_factory=lambda: [
        "injection", "broken_auth", "sensitive_data", "xxe", "broken_access",
        "misconfiguration", "xss", "insecure_deserialization", "vulnerable_components"
    ])
    block_on_critical: bool = True
    block_on_high: bool = True

    def validate(self) -> Tuple[bool, List[str]]:
        """Validates policy profile properties."""
        errors: List[str] = []

        if self.severity_threshold.lower() not in VALID_SEVERITY_THRESHOLDS:
            errors.append(f"Invalid severity_threshold '{self.severity_threshold}'")

        if not (1 <= self.max_files <= 10000):
            errors.append(f"max_files must be between 1 and 10000, got {self.max_files}")

        if self.review_action.lower() not in VALID_REVIEW_ACTIONS:
            errors.append(f"Invalid review_action '{self.review_action}'")

        if self.block_action.lower() not in VALID_REVIEW_ACTIONS:
            errors.append(f"Invalid block_action '{self.block_action}'")

        return len(errors) == 0, errors

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "severity_threshold": self.severity_threshold,
            "max_files": self.max_files,
            "review_action": self.review_action,
            "block_action": self.block_action,
            "enabled_categories": self.enabled_categories,
            "block_on_critical": self.block_on_critical,
            "block_on_high": self.block_on_high,
        }


PREDEFINED_POLICIES: Dict[str, AnalysisPolicy] = {
    "default": AnalysisPolicy(
        name="default",
        severity_threshold="info",
        max_files=500,
        review_action="review",
        block_action="block",
        block_on_critical=True,
        block_on_high=True,
    ),
    "strict": AnalysisPolicy(
        name="strict",
        severity_threshold="low",
        max_files=1000,
        review_action="review",
        block_action="block",
        block_on_critical=True,
        block_on_high=True,
    ),
    "ci": AnalysisPolicy(
        name="ci",
        severity_threshold="medium",
        max_files=200,
        review_action="review",
        block_action="block",
        block_on_critical=True,
        block_on_high=True,
    ),
    "developer": AnalysisPolicy(
        name="developer",
        severity_threshold="info",
        max_files=100,
        review_action="review",
        block_action="block",
        block_on_critical=True,
        block_on_high=False,
    ),
}


def get_policy_profile(name: Optional[str] = None) -> AnalysisPolicy:
    """
    Returns an AnalysisPolicy profile by name.
    If name is None, empty, or 'default', returns the default policy.
    Raises ValueError if profile name is unrecognized or invalid.
    """
    if not name or not isinstance(name, str) or not name.strip():
        return PREDEFINED_POLICIES["default"]

    clean_name = name.strip().lower()
    if clean_name not in PREDEFINED_POLICIES:
        raise ValueError(f"Unknown analysis policy profile: '{name}'. Supported: {list(PREDEFINED_POLICIES.keys())}")

    policy = PREDEFINED_POLICIES[clean_name]
    valid, errors = policy.validate()
    if not valid:
        raise ValueError(f"Policy configuration error in profile '{name}': {', '.join(errors)}")

    return policy


def list_available_policies() -> List[Dict[str, object]]:
    """Returns list of available policy profiles."""
    return [pol.to_dict() for pol in PREDEFINED_POLICIES.values()]
