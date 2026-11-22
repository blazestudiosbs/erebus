"""DNS helpers shared by gather modules. Resolution asks a resolver, not the target."""
from __future__ import annotations

import socket


def resolve_ips(target: str) -> list[str]:
    """IP(s) for ``target``: an IP literal passes through; a hostname is resolved via
    DNS. Returns [] on failure. DNS queries go to a resolver, never to the host itself."""
    try:
        socket.inet_aton(target)
        return [target]
    except OSError:
        pass
    try:
        ips: list[str] = []
        for info in socket.getaddrinfo(target, None):
            ip = str(info[4][0])
            if ip and ip not in ips:
                ips.append(ip)
        return ips
    except OSError:
        return []
