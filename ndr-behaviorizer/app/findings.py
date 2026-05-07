from __future__ import annotations

from typing import Any

from app.utils import get_field, isoformat, utc_now


def build_behavior_anomaly_finding(behavior_doc: dict[str, Any], behavior_index_pattern: str) -> dict[str, Any]:
    anomaly_score = float(get_field(behavior_doc, "ml.anomaly_score", 0.0) or 0.0)
    behavior_id = get_field(behavior_doc, "behavior.id")
    return {
        "@timestamp": isoformat(utc_now()),
        "finding": {
            "type": "ml_behavior_anomaly",
            "severity": get_field(behavior_doc, "score.severity", "medium"),
            "confidence": anomaly_score,
            "status": "new",
        },
        "behavior": {
            "id": behavior_id,
            "entity": get_field(behavior_doc, "behavior.entity"),
            "sensor": get_field(behavior_doc, "behavior.sensor"),
            "window_start": get_field(behavior_doc, "behavior.window_start"),
            "window_end": get_field(behavior_doc, "behavior.window_end"),
            "feature_set": get_field(behavior_doc, "behavior.feature_set"),
        },
        "score": {"ml": anomaly_score, "statistical": None, "final": round(anomaly_score * 100, 2)},
        "reasons": get_field(behavior_doc, "score.reasons", []) or ["ml_behavior_anomaly"],
        "evidence": {"behavior_index": behavior_index_pattern, "behavior_id": behavior_id},
        "ml": {"top_features": get_field(behavior_doc, "ml.top_features", [])},
    }
