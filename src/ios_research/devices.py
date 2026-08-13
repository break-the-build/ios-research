"""Device abstraction and mock device implementations.

A *device* describes where a target runs (an OS/runtime). Mock devices let the
framework operate deterministically in CI without physical iOS hardware. Real
authorized research devices can be added behind the same interface.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class Device:
    id: str
    kind: str          # "mock" | "simulator" | "research-device"
    model: str
    os_name: str
    os_version: str
    mock: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


_DEVICES: dict[str, Device] = {}


def register(device: Device) -> None:
    _DEVICES[device.id] = device


def get(device_id: str) -> Device:
    from .errors import NotFoundError
    if device_id not in _DEVICES:
        raise NotFoundError(
            f"unknown device '{device_id}'; known: {', '.join(sorted(_DEVICES))}")
    return _DEVICES[device_id]


def list_devices() -> list[dict]:
    return [_DEVICES[d].to_dict() for d in sorted(_DEVICES)]


# Built-in mock devices.
register(Device(id="mock:device", kind="mock", model="MockPhone",
                os_name="MockOS", os_version="17.0", mock=True))
register(Device(id="mock:sim-16", kind="simulator", model="Simulator",
                os_name="iOS-Simulator", os_version="16.4", mock=True))
register(Device(id="mock:sim-17", kind="simulator", model="Simulator",
                os_name="iOS-Simulator", os_version="17.4", mock=True))
