"""Venue certificates. The venue key (kept by the operator) signs a certificate for each beacon's own key, in two
formats for the same key pair:

- X.509, for mutual TLS between beacons (and the operator's tools). Subject CN = "beacon-3" / "operator-1".
- Compact, CBOR [body, sig], about 150 bytes, for phones (over BLE later) and the gossiped roster.

All keys are Ed25519. A key file holds the 32-byte seed as unencrypted PKCS#8 PEM.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import ssl
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from beacon.records.keys import KEY_LEN, SIG_LEN, KeyPair, verify

CERT_DOMAIN = b"huddle/v1/beacon-cert"
CERT_KEYS = frozenset({"v", "venue_id", "role", "id", "pub", "not_before", "expires"})


class Role(StrEnum):
    BEACON = "beacon"
    OPERATOR = "operator"


class CertError(Exception):
    pass


# --- key files ---


def write_key(path: Path, seed: bytes) -> None:
    pem = Ed25519PrivateKey.from_private_bytes(seed).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem)
    path.chmod(0o600)


def read_key(path: Path) -> KeyPair:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise CertError(f"{path} is not an Ed25519 key")
    return KeyPair(
        key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    )


# --- compact certificates ---


@dataclass(frozen=True)
class CompactCert:
    venue_id: int
    role: Role
    id: int
    pub: bytes
    not_before: int
    """Unix seconds"""
    expires: int
    """Unix seconds"""
    wire: bytes

    @property
    def name(self) -> str:
        return f"{self.role.value}-{self.id}"


def issue_compact(
    venue: KeyPair, venue_id: int, role: Role, ident: int, pub: bytes, not_before: int, expires: int
) -> bytes:
    body = cbor2.dumps(
        {
            "v": 1,
            "venue_id": venue_id,
            "role": role.value,
            "id": ident,
            "pub": pub,
            "not_before": not_before,
            "expires": expires,
        },
        canonical=True,
    )
    return cbor2.dumps([body, venue.sign(CERT_DOMAIN + body)], canonical=True)


def verify_compact(wire: bytes, venue_pub: bytes, now: int) -> CompactCert:
    """A compact certificate checked against the venue key and the clock (Unix seconds). Raises CertError."""
    try:
        outer = cbor2.loads(wire)
        body, sig = outer
        fields: Any = cbor2.loads(body)
    except Exception as err:
        raise CertError("certificate is not [body, sig] CBOR") from err
    if not (isinstance(body, bytes) and isinstance(sig, bytes) and len(sig) == SIG_LEN and isinstance(fields, dict)):
        raise CertError("certificate is not [body, sig] CBOR")
    if set(fields) != CERT_KEYS or fields["v"] != 1:
        raise CertError("certificate fields")
    if not verify(venue_pub, CERT_DOMAIN + body, sig):
        raise CertError("not signed by the venue key")
    if fields["role"] not in Role._value2member_map_ or not (
        isinstance(fields["pub"], bytes) and len(fields["pub"]) == KEY_LEN
    ):
        raise CertError("certificate fields")
    if not fields["not_before"] <= now < fields["expires"]:
        raise CertError("certificate expired or not yet valid")
    return CompactCert(
        venue_id=fields["venue_id"],
        role=Role(fields["role"]),
        id=fields["id"],
        pub=fields["pub"],
        not_before=fields["not_before"],
        expires=fields["expires"],
        wire=wire,
    )


# --- X.509, for TLS ---


def _utc(seconds: int) -> dt.datetime:
    return dt.datetime.fromtimestamp(seconds, tz=dt.UTC)


def make_ca(venue: KeyPair, venue_id: int, not_before: int, expires: int) -> bytes:
    """The venue's self-signed CA certificate (PEM): what every node trusts."""
    key = Ed25519PrivateKey.from_private_bytes(venue.seed)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"huddle-venue-{venue_id}")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_utc(not_before))
        .not_valid_after(_utc(expires))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, algorithm=None)
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def issue_x509(
    venue: KeyPair,
    ca_pem: bytes,
    role: Role,
    ident: int,
    pub: bytes,
    not_before: int,
    expires: int,
    hosts: list[str],
) -> bytes:
    ca = x509.load_pem_x509_certificate(ca_pem)
    sans: list[x509.GeneralName] = []
    for host in hosts:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            sans.append(x509.DNSName(host))
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{role.value}-{ident}")]))
        .issuer_name(ca.subject)
        .public_key(Ed25519PublicKey.from_public_bytes(pub))
        .serial_number(x509.random_serial_number())
        .not_valid_before(_utc(not_before))
        .not_valid_after(_utc(expires))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    cert = builder.sign(Ed25519PrivateKey.from_private_bytes(venue.seed), algorithm=None)
    return cert.public_bytes(serialization.Encoding.PEM)


@dataclass(frozen=True)
class PeerIdentity:
    """Who is on the other end of a TLS connection, from their (already verified) certificate."""

    name: str
    role: Role
    pub: bytes


def identity_from_der(der: bytes) -> PeerIdentity:
    cert = x509.load_der_x509_certificate(der)
    name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    role_text = str(name).rsplit("-", 1)[0]
    if role_text not in Role._value2member_map_:
        raise CertError(f"unknown role in certificate name {name!r}")
    key = cert.public_key()
    if not isinstance(key, Ed25519PublicKey):
        raise CertError("certificate key is not Ed25519")
    return PeerIdentity(
        str(name), Role(role_text), key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def identity_of(ssl_object: ssl.SSLObject | ssl.SSLSocket | None) -> PeerIdentity | None:
    der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
    return identity_from_der(der) if der else None


def tls_context(server: bool, cert_file: Path, key_file: Path, ca_file: Path) -> ssl.SSLContext:
    """Mutual TLS 1.3: present our certificate, require one signed by the venue CA from the other side. Hostnames are
    not checked (beacons are addressed by IP); identity comes from the certificate itself."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert_file, key_file)
    context.load_verify_locations(ca_file)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    return context
