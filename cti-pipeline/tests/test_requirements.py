from ctilib.requirements import SECTOR_PRESETS, IntelRequirement


def test_requirement_round_trips_through_json(tmp_path):
    req = IntelRequirement(
        stakeholder="SOC analyst",
        question="Which behaviors matter?",
        decision="Which analytics to build",
        sector="nation-states",
        groups=["APT29", "APT28"],
    )
    path = tmp_path / "req.json"
    req.save(path)
    loaded = IntelRequirement.load(path)
    assert loaded == req
    assert "APT29, APT28" in loaded.summary()


def test_presets_have_groups():
    for name, preset in SECTOR_PRESETS.items():
        assert preset["groups"], name
        assert all(isinstance(g, tuple) and len(g) == 2 for g in preset["groups"])
