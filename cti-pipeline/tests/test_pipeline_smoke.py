"""End-to-end checks that need the ATT&CK bundle. Skipped if it has not been downloaded."""

import json
import os

import pytest

from ctilib import analysis, navigator, report, sharing
from ctilib.attack_data import DEFAULT_PATH, AttackKnowledgeBase
from ctilib.indicators import load_feed, process_feed
from ctilib.requirements import IntelRequirement

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ATTACK = os.path.join(ROOT, DEFAULT_PATH)
SAMPLE = os.path.join(ROOT, "samples", "sample_indicator_feed.json")

pytestmark = pytest.mark.skipif(not os.path.exists(ATTACK), reason="run `python cti_pipeline.py --demo` once to download ATT&CK")


@pytest.fixture(scope="module")
def kb():
    return AttackKnowledgeBase(ATTACK)


def test_group_lookup_by_id_name_and_alias(kb):
    assert kb.attack_id(kb.find_group("APT29")) == "G0016"
    assert kb.attack_id(kb.find_group("G0016")) == "G0016"
    assert kb.find_group("Cozy Bear")["name"] == "APT29"
    assert kb.find_group("Not A Real Group") is None


def test_full_pipeline_products(kb, tmp_path):
    req = IntelRequirement("SOC analyst", "q", "d", "test", ["APT29", "APT28", "Bogus Group"])
    processing = process_feed(load_feed(SAMPLE))
    result = analysis.analyze(kb, req.groups, processing.kept, log=lambda *_: None)

    assert result.unresolved_groups == ["Bogus Group"]
    assert len(result.groups) == 2
    assert result.hits, "expected techniques"
    top = result.ranked(1)[0]
    assert top.score >= 2
    assert result.mitigations.most_common(1)

    md = report.write_markdown(tmp_path / "r.md", req, processing, result, kb.version(), "cached")
    text = open(md, encoding="utf-8").read()
    assert "Alerts avoided" in text and "APT29" in text

    layer_path = navigator.write_layer(result, str(tmp_path / "layer.json"), "t", kb.version())
    layer = json.load(open(layer_path, encoding="utf-8"))
    assert layer["domain"] == "enterprise-attack"
    assert {t["techniqueID"] for t in layer["techniques"]} == set(result.hits)

    bundle = sharing.build_share_bundle(req, processing.kept, result, tlp="green")
    types = [o["type"] for o in bundle["objects"]]
    assert types.count("marking-definition") == 1
    assert types.count("report") == 1
    marking_id = sharing.TLP["green"].id
    for obj in bundle["objects"]:
        if obj["type"] in ("indicator", "report", "identity"):
            assert marking_id in obj["object_marking_refs"]
