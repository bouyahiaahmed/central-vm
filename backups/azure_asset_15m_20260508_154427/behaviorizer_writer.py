from __future__ import annotations

import logging
from datetime import datetime
from itertools import islice
from typing import Any, Iterable

from opensearchpy import OpenSearch, helpers

from app.config import Settings
from app.metrics import BEHAVIORS_WRITTEN, FINDINGS_WRITTEN, OPENSEARCH_ERRORS
from app.utils import get_field, parse_ts

logger = logging.getLogger(__name__)


def chunks(items: list[Any], size: int) -> Iterable[list[Any]]:
    iterator = iter(items)
    while True:
        chunk = list(islice(iterator, size))
        if not chunk:
            break
        yield chunk


class BehaviorWriter:
    def __init__(self, client: OpenSearch, settings: Settings):
        self.client = client
        self.settings = settings

    def behavior_index_for_doc(self, doc: dict[str, Any]) -> str:
        window_start = parse_ts(get_field(doc, "behavior.window_start")) or parse_ts(doc.get("@timestamp")) or datetime.utcnow()
        return f"{self.settings.target_index_prefix}-{window_start:%Y.%m.%d}"

    def finding_index_for_doc(self, doc: dict[str, Any]) -> str:
        ts = parse_ts(doc.get("@timestamp")) or datetime.utcnow()
        return f"{self.settings.findings_index_prefix}-{ts:%Y.%m.%d}"

    def bulk_upsert_behaviors(self, docs: list[dict[str, Any]]) -> int:
        if not docs:
            return 0
        actions = []
        for doc in docs:
            doc_id = str(get_field(doc, "behavior.id") or "")
            if not doc_id:
                continue
            actions.append({"_op_type": "index", "_index": self.behavior_index_for_doc(doc), "_id": doc_id, "_source": doc})
        if self.settings.dry_run:
            logger.info("dry_run_behavior_bulk", extra={"behaviors": len(actions)})
            return len(actions)
        try:
            success, errors = helpers.bulk(self.client, actions, chunk_size=self.settings.bulk_size, request_timeout=120, raise_on_error=False)
            if errors:
                OPENSEARCH_ERRORS.inc(len(errors))
                logger.error("behavior_bulk_errors", extra={"error_count": len(errors), "sample": errors[:3]})
            BEHAVIORS_WRITTEN.inc(success)
            return int(success)
        except Exception:
            OPENSEARCH_ERRORS.inc()
            logger.exception("behavior_bulk_failed")
            raise

    def bulk_index_findings(self, docs: list[dict[str, Any]]) -> int:
        if not docs:
            return 0
        actions = []
        for doc in docs:
            behavior_id = get_field(doc, "behavior.id", "unknown")
            doc_id = str(get_field(doc, "finding.dedup_id") or f"{behavior_id}|{get_field(doc, 'finding.type', 'finding')}")
            actions.append({"_op_type": "index", "_index": self.finding_index_for_doc(doc), "_id": doc_id, "_source": doc})
        if self.settings.dry_run:
            logger.info("dry_run_finding_bulk", extra={"findings": len(actions)})
            return len(actions)
        try:
            success, errors = helpers.bulk(self.client, actions, chunk_size=self.settings.bulk_size, request_timeout=120, raise_on_error=False)
            if errors:
                OPENSEARCH_ERRORS.inc(len(errors))
                logger.error("finding_bulk_errors", extra={"error_count": len(errors), "sample": errors[:3]})
            FINDINGS_WRITTEN.inc(success)
            return int(success)
        except Exception:
            OPENSEARCH_ERRORS.inc()
            logger.exception("finding_bulk_failed")
            raise
