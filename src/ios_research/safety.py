"""Central declaration and enforcement of the authorized-research safety boundary.

The framework performs defensive/authorized research only. Capabilities that
cross into weaponization, surveillance, or persistence are explicitly forbidden
and are documented here in one place so the boundary is auditable.
"""

from __future__ import annotations

from .errors import SafetyError

# Capabilities this framework will never implement.
FORBIDDEN_CAPABILITIES = (
    "covert_surveillance",
    "camera_activation",
    "microphone_activation",
    "permission_bypass",
    "tcc_bypass",
    "sandbox_escape",
    "persistence",
    "credential_theft",
    "spyware",
    "operational_malware",
    "weaponized_exploit_chain",
    "exploit_deployment",
    "shellcode_generation",
    "rop_chain_generation",
)

# Capabilities this framework may implement.
ALLOWED_CAPABILITIES = (
    "fuzzing",
    "crash_discovery",
    "crash_reproduction",
    "crash_minimization",
    "memory_safety_analysis",
    "differential_testing",
    "exploitability_indicators",
    "research_device_instrumentation",
    "responsible_reporting",
    "malware_detection_signatures",
    "known_cve_regression_validation",
)


def assert_allowed(capability: str) -> None:
    """Raise :class:`SafetyError` if ``capability`` is outside the boundary."""
    if capability in FORBIDDEN_CAPABILITIES:
        raise SafetyError(
            f"capability '{capability}' is outside the authorized-research "
            f"safety boundary and will not be performed",
            details={"capability": capability},
        )


def boundary_summary() -> dict:
    return {
        "authorized_research_only": True,
        "allowed": list(ALLOWED_CAPABILITIES),
        "forbidden": list(FORBIDDEN_CAPABILITIES),
    }
