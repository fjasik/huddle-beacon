import cbor2
import nacl.signing

import beacon


def test_version() -> None:
    assert beacon.__version__ == "0.1.0"


def test_signing_and_cbor_libraries_round_trip() -> None:
    key = nacl.signing.SigningKey.generate()
    signed = key.sign(cbor2.dumps({"v": 1}))
    assert cbor2.loads(key.verify_key.verify(signed)) == {"v": 1}
