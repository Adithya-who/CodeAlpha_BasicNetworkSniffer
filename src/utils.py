"""System utility functions for permission checks and interface listing."""

import ctypes
import os
import sys
from typing import List, Dict, Any


def is_admin() -> bool:
    """Check if the current process has administrative (Windows) or root (Unix) privileges."""
    try:
        if os.name == "nt":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except AttributeError:
        return False


def get_available_interfaces() -> List[Dict[str, Any]]:
    """List available network interfaces using Scapy's configuration.
    
    Returns:
        List of dictionaries containing interface details.
    """
    from scapy.all import conf

    interfaces = []
    # Scapy's conf.ifaces contains network interfaces mapped to metadata
    for iface_key, iface_obj in conf.ifaces.items():
        name = getattr(iface_obj, "name", str(iface_key))
        description = getattr(iface_obj, "description", "Unknown Adapter")
        ip = getattr(iface_obj, "ip", "No IP")
        mac = getattr(iface_obj, "mac", "No MAC")

        interfaces.append({
            "key": iface_key,
            "name": name,
            "description": description,
            "ip": ip,
            "mac": mac,
            "raw": iface_obj
        })

    return interfaces


def format_bytes(byte_count: int) -> str:
    """Format byte size into human-readable metric string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if byte_count < 1024.0:
            return f"{byte_count:3.1f} {unit}"
        byte_count /= 1024.0
    return f"{byte_count:.1f} TB"

