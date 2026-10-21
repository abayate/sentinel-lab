"""
Dataset-level evaluation test.

Locks the headline metric into CI: on the committed realistic dataset, the engine
must catch every planted attack campaign and raise zero false positives on the
benign baseline. If a rule change ever regresses that, the build fails.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evaluate import score  # noqa: E402


def test_full_detection_no_false_positives():
    r = score()
    assert len(r["missed"]) == 0, f"missed attacks: {[a['id'] for a in r['missed']]}"
    assert len(r["caught"]) == r["planted"], "not every planted attack was caught"
    assert len(r["false_positives"]) == 0, (
        f"false positives on benign traffic: {len(r['false_positives'])}")


def test_dataset_has_realistic_volume():
    # Guards that the committed dataset is the production-style one, not a tiny stub.
    r = score()
    assert r["total_lines"] >= 150, "dataset looks too small to be realistic"
    assert r["benign"] >= 100, "dataset needs a substantial benign baseline"
