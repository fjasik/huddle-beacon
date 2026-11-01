"""The shared test vectors: the beacon must pass every case, and the file must match what the generator produces."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from beacon.records import GroupKeys, KeyPair, Rejected, validate_record
from beacon.records.keys import hkdf_sha256

SPEC = Path(__file__).parent.parent / "spec"
VECTORS: dict[str, Any] = json.loads((SPEC / "vectors.json").read_text(encoding="utf-8"))


def test_file_is_up_to_date_with_the_generator() -> None:
    loaded = importlib.util.spec_from_file_location("gen_vectors", SPEC / "gen_vectors.py")
    assert loaded and loaded.loader
    gen = importlib.util.module_from_spec(loaded)
    loaded.loader.exec_module(gen)
    assert (SPEC / "vectors.json").read_text(encoding="utf-8") == gen.render(), "run: python spec/gen_vectors.py"


@pytest.mark.parametrize("case", VECTORS["hkdf"], ids=lambda c: c["info"])
def test_hkdf(case: dict[str, str]) -> None:
    assert hkdf_sha256(bytes.fromhex(case["ikm"]), case["info"].encode()).hex() == case["okm"]


@pytest.mark.parametrize("case", VECTORS["users"], ids=lambda c: c["name"])
def test_user_key_from_seed(case: dict[str, str]) -> None:
    assert KeyPair(bytes.fromhex(case["seed"])).pub.hex() == case["pub"]


@pytest.mark.parametrize("case", VECTORS["groups"], ids=lambda c: c["name"])
def test_group_keys_from_seed(case: dict[str, str]) -> None:
    group = GroupKeys(bytes.fromhex(case["seed"]))
    assert group.gpub.hex() == case["gpub"]
    assert group.group_id.hex() == case["group_id"]
    assert group.enc_key.hex() == case["enc_key"]


@pytest.mark.parametrize("case", VECTORS["records"], ids=lambda c: c["name"])
def test_valid_record(case: dict[str, Any]) -> None:
    record = validate_record(bytes.fromhex(case["wire"]))
    expected = case["body"]
    body = record.body
    assert record.group_id.hex() == case["group_id"]
    assert (body.v, int(body.type), body.seq, body.ts, body.enc) == (
        expected["v"],
        expected["type"],
        expected["seq"],
        expected["ts"],
        expected["enc"],
    )
    assert (body.gpub.hex(), body.author.hex(), body.payload.hex()) == (
        expected["gpub"],
        expected["author"],
        expected["payload"],
    )


@pytest.mark.parametrize("case", VECTORS["invalid"], ids=lambda c: c["name"])
def test_invalid_record(case: dict[str, str]) -> None:
    with pytest.raises(Rejected) as refused:
        validate_record(bytes.fromhex(case["wire"]))
    assert refused.value.reason.value == case["reason"]
