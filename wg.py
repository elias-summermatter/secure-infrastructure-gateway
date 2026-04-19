"""WireGuard key generation and config rendering.

Uses X25519 from the `cryptography` package; WG private keys are 32-byte
Curve25519 scalars (auto-clamped) in base64, public keys are the X25519
public bytes in base64.
"""
import base64
import secrets
from dataclasses import dataclass
from typing import Iterable, Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization


@dataclass
class Keypair:
    private_key_b64: str
    public_key_b64: str


def generate_keypair() -> Keypair:
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return Keypair(
        private_key_b64=base64.b64encode(priv_bytes).decode(),
        public_key_b64=base64.b64encode(pub_bytes).decode(),
    )


def generate_preshared_key() -> str:
    """32 random bytes, base64. Paired with the asymmetric handshake to provide
    post-quantum hedging (WG `PresharedKey`)."""
    return base64.b64encode(secrets.token_bytes(32)).decode()


def public_from_private(private_key_b64: str) -> str:
    raw = base64.b64decode(private_key_b64)
    priv = X25519PrivateKey.from_private_bytes(raw)
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(pub).decode()


def render_client_config(
    *,
    client_private_key_b64: str,
    client_address: str,
    server_public_key_b64: str,
    endpoint: str,
    allowed_ips: Iterable[str],
    preshared_key_b64: Optional[str] = None,
    dns: Optional[str] = None,
    persistent_keepalive: int = 25,
) -> str:
    allowed = ", ".join(allowed_ips)
    lines = [
        "[Interface]",
        f"PrivateKey = {client_private_key_b64}",
        f"Address = {client_address}",
    ]
    if dns:
        lines.append(f"DNS = {dns}")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {server_public_key_b64}",
    ]
    if preshared_key_b64:
        lines.append(f"PresharedKey = {preshared_key_b64}")
    lines += [
        f"Endpoint = {endpoint}",
        f"AllowedIPs = {allowed}",
        f"PersistentKeepalive = {persistent_keepalive}",
        "",
    ]
    return "\n".join(lines)
