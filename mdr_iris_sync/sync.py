"""Bidirectional synchronization engine."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from . import mapping
from .iris_client import (
    IrisApiError,
    IrisClient,
    alert_id_from_response,
    case_id_from_response,
    comment_id_from_response,
)
from .mdr_client import MDRApiError, MDRClient
from .state import StateDB


def _now_ms() -> int:
    return int(time.time() * 1000)


def _iso_from_ms(value: Optional[int]) -> str:
    if not value:
        return "beginning"
    try:
        return datetime.fromtimestamp(value / 1000.0, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except (OverflowError, OSError, ValueError):
        return str(value)


def _comment_body(text: str) -> str:
    """Strip the sync header from a formatted comment."""
    if text.startswith("**") and "\n\n" in text:
        return text.split("\n\n", 1)[1]
    return text


def _case_status_id(case: Dict[str, Any]) -> Optional[int]:
    return mapping.case_status_id(case)


def _iris_timestamp(obj: Dict[str, Any]) -> int:
    """Best-effort update timestamp in milliseconds."""
    for key in (
        "case_update_date",
        "update_date",
        "alert_update_date",
        "modified_at",
        "case_open_date",
    ):
        value = obj.get(key)
        if value is None:
            continue
        if isinstance(value, (int, float)):
            return int(value if value > 10_000_000_000 else value * 1000)
        try:
            text = str(value).replace("Z", "+00:00")
            return int(datetime.fromisoformat(text).timestamp() * 1000)
        except ValueError:
            continue
    return 0


class Syncer:
    def __init__(
        self,
        cfg: Dict[str, Any],
        db: StateDB,
        mdr: MDRClient,
        iris: IrisClient,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.cfg = cfg
        self.db = db
        self.mdr = mdr
        self.iris = iris
        self.log = logger or logging.getLogger(__name__)
        self.mapping_cfg = cfg["mapping"]
        self.iris_cfg = cfg["iris"]
        self.mdr_cfg = cfg["mdr"]
        self._incident_cache: Dict[str, Dict[str, Any]] = {}
        self.stats: Dict[str, int] = {}

    # ------------------------------------------------------------- helpers
    def _reset_stats(self) -> None:
        self.stats = {
            "incidents_seen": 0,
            "alerts_created": 0,
            "cases_created": 0,
            "status_updates_iris": 0,
            "status_updates_mdr": 0,
            "comments_mdr_to_iris": 0,
            "comments_iris_to_mdr": 0,
            "errors": 0,
        }

    def _allow(self, key: str) -> bool:
        """Production safety switches.

        Status and comment writes are disabled by default. Enable them only
        for a lab instance, never for a production tenant.
        """
        return bool(self.cfg.get("safety", {}).get(key, False))

    def _sync_allowed(self, row: Dict[str, Any]) -> bool:
        """Limit status/comment sync to selected MDR incidents or IRIS alerts."""
        sync_cfg = self.cfg.get("sync", {})
        numbers = {str(item) for item in (sync_cfg.get("only_incident_numbers") or [])}
        alert_ids = {str(item) for item in (sync_cfg.get("only_alert_ids") or [])}
        if not numbers and not alert_ids:
            return True
        return (
            str(row.get("incident_number") or "") in numbers
            or str(row.get("alert_id") or "") in alert_ids
        )

    def _merge_target(self, incident: Dict[str, Any]) -> Optional[int]:
        by_tenant = self.mapping_cfg.get("merge_target_by_tenant") or {}
        tenant = str(incident.get("tenant_name") or "")
        if tenant and tenant in by_tenant:
            return mapping.as_int(by_tenant[tenant])
        return mapping.as_int(self.mapping_cfg.get("merge_target_case_id"))

    def _get_incident_data(self, row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        incident_id = str(row["incident_id"])
        if incident_id in self._incident_cache:
            return self._incident_cache[incident_id]
        try:
            incident = self.mdr.incident_details(
                incident_id, fields=self.mdr_cfg.get("incident_fields")
            )
        except Exception:  # noqa: BLE001
            self.log.exception("cannot get MDR incident %s details", incident_id)
            return None
        self._incident_cache[incident_id] = incident
        return incident

    def _is_mdr_closed(self, status: Any) -> bool:
        return mapping.normalize(status) in ("closed", "resolved", "archived")

    def _is_case_closed(self, case: Dict[str, Any], status_id: Optional[int]) -> bool:
        return mapping.case_is_closed(
            case, status_id if status_id is not None else self.iris_cfg.get("closed_case_status_id")
        )

    def _comment_author_ignored(self, author: str, ignore: Any) -> bool:
        ignored = {str(item).strip().lower() for item in (ignore or []) if item}
        return author.strip().lower() in ignored

    def _has_same_comment(
        self,
        comments: List[Dict[str, Any]],
        text: str,
        ignore_authors: Any,
    ) -> bool:
        ignored = {str(item).strip().lower() for item in (ignore_authors or []) if item}
        if not ignored:
            return False
        wanted = mapping.fingerprint(text)
        for comment in comments:
            author = mapping.comment_author(comment).lower()
            if author not in ignored:
                continue
            body = _comment_body(mapping.comment_text(comment))
            if mapping.fingerprint(body) == wanted:
                return True
        return False

    # ---------------------------------------------------------------- cycle
    def run_cycle(self) -> Dict[str, int]:
        self._reset_stats()
        self._incident_cache.clear()
        started = time.monotonic()

        self.log.info("sync cycle started")
        try:
            self._ingest()
        except Exception:  # noqa: BLE001
            self.stats["errors"] += 1
            self.log.exception("incident ingestion failed")

        if self._allow("allow_status_changes"):
            try:
                self._sync_statuses()
            except Exception:  # noqa: BLE001
                self.stats["errors"] += 1
                self.log.exception("status synchronization failed")
        else:
            self.log.info(
                "status sync disabled by safety policy "
                "(safety.allow_status_changes=false)"
            )

        if self._allow("allow_comments"):
            try:
                self._sync_comments()
            except Exception:  # noqa: BLE001
                self.stats["errors"] += 1
                self.log.exception("comment synchronization failed")
        else:
            self.log.info(
                "comment sync disabled by safety policy "
                "(safety.allow_comments=false)"
            )

        self.db.set_kv("last_cycle_at", int(time.time()))
        self.db.set_kv("last_cycle_ok", 1 if not self.stats["errors"] else 0)
        elapsed = time.monotonic() - started
        self.log.info(
            "sync cycle finished in %.1fs: %s",
            elapsed,
            " ".join(f"{key}={value}" for key, value in self.stats.items()),
        )
        return dict(self.stats)

    # --------------------------------------------------------------- ingest
    def _ingest(self) -> None:
        if not self._allow("allow_alert_creation"):
            self.log.info(
                "ingest disabled by safety policy "
                "(safety.allow_alert_creation=false)"
            )
            return

        last_update = self.db.get_kv_int("last_mdr_update_time", 0)
        if last_update:
            # 60 s overlap protects against clock skew and inclusive bounds.
            min_update = max(0, last_update - 60_000)
        else:
            lookback_hours = float(self.mdr_cfg.get("initial_lookback_hours", 24))
            min_update = int((time.time() - lookback_hours * 3600) * 1000)

        self.log.info("ingest: MDR incidents updated since %s", _iso_from_ms(min_update))
        filters: Dict[str, Any] = {}
        include_statuses = self.mdr_cfg.get("include_statuses") or []
        if include_statuses:
            filters["statuses"] = include_statuses
        incidents = self.mdr.list_incidents(
            min_update_time=min_update,
            fields=self.mdr_cfg.get("incident_fields"),
            **filters,
        )
        incidents.sort(key=lambda item: int(item.get("update_time") or 0))
        self.stats["incidents_seen"] = len(incidents)

        if not incidents:
            self.log.info("ingest: no new or updated MDR incidents")
            return

        limit = int(self.mdr_cfg.get("max_incidents_per_cycle", 100))
        batch = incidents[:limit]
        if len(incidents) > limit:
            self.log.warning(
                "ingest: %s incidents received, processing only %s this cycle",
                len(incidents),
                limit,
            )

        max_seen = last_update
        failed_times: List[int] = []

        for incident in batch:
            incident_id = str(incident.get("incident_id") or "")
            update_time = int(incident.get("update_time") or 0)
            if not incident_id:
                self.log.error("ingest: incident without incident_id: %r", incident)
                continue
            try:
                self._ensure_alert(incident)
                max_seen = max(max_seen, update_time)
            except Exception:  # noqa: BLE001
                self.stats["errors"] += 1
                failed_times.append(update_time)
                self.log.exception("ingest: failed to import MDR incident %s", incident_id)

        watermark = max_seen
        if failed_times:
            # Do not move the watermark past a failed incident: it must be
            # retried on the next cycle. Lowering it is safe because already
            # imported incidents are deduplicated by the state DB.
            watermark = min(watermark, min(failed_times) - 1)
        self.db.set_kv("last_mdr_update_time", max(0, watermark))
        self.log.info(
            "ingest: processed=%s watermark=%s",
            len(batch),
            _iso_from_ms(max(0, watermark)),
        )

    def _sync_alert_metadata(
        self, row: Dict[str, Any], incident: Dict[str, Any]
    ) -> None:
        alert_id = row.get("alert_id")
        if not alert_id:
            return
        payload = mapping.build_alert_payload(incident, self.cfg)
        target_severity = int(payload["alert_severity_id"])
        target_classification = int(payload["alert_classification_id"])
        try:
            alert = self.iris.get_alert(int(alert_id))
            changes: Dict[str, int] = {}
            if mapping.as_int(alert.get("alert_severity_id")) != target_severity:
                changes["alert_severity_id"] = target_severity
            if mapping.as_int(alert.get("alert_classification_id")) != target_classification:
                changes["alert_classification_id"] = target_classification
            if not changes:
                return
            self.iris.update_alert(int(alert_id), changes)
            self.log.info(
                "incident %s: IRIS alert #%s metadata updated: %s",
                row.get("incident_id"),
                alert_id,
                changes,
            )
        except Exception:  # noqa: BLE001
            self.stats["errors"] += 1
            self.log.exception(
                "incident %s: cannot update IRIS alert #%s metadata",
                row.get("incident_id"),
                alert_id,
            )

    def _ensure_alert(self, incident: Dict[str, Any]) -> None:
        incident_id = str(incident.get("incident_id"))
        row = self.db.get_incident(incident_id)

        if row:
            self._sync_alert_metadata(row, incident)
            if not row.get("case_id"):
                self._ensure_case(row, incident)
            return

        payload = mapping.build_alert_payload(incident, self.cfg)
        try:
            alert = self.iris.add_alert(payload)
        except IrisApiError as exc:
            if exc.status_code in (400, 422) and "alert_context" in payload:
                self.log.warning(
                    "IRIS rejected alert_context for incident %s; retrying without it",
                    incident_id,
                )
                payload.pop("alert_context", None)
                alert = self.iris.add_alert(payload)
            else:
                raise

        alert_id = alert_id_from_response(alert)
        if alert_id is None:
            raise RuntimeError(f"IRIS did not return alert_id for incident {incident_id}")

        self.db.upsert_incident(
            incident_id,
            incident_number=str(
                incident.get("incident_number") or incident.get("incident_id") or ""
            ),
            alert_id=alert_id,
            mdr_status=str(incident.get("status") or ""),
            mdr_update_time=mapping.as_int(incident.get("update_time")),
            iris_status_id=mapping.as_int(alert.get("alert_status_id"))
            or int(payload["alert_status_id"]),
        )
        self.stats["alerts_created"] += 1
        self.log.info(
            "incident %s imported as IRIS alert #%s", incident_id, alert_id
        )

        row = self.db.get_incident(incident_id)
        if row:
            self._ensure_case(row, incident)

    def _ensure_case(self, row: Dict[str, Any], incident: Dict[str, Any]) -> None:
        if not self._allow("allow_case_creation"):
            self.log.info(
                "case creation disabled by safety policy "
                "(safety.allow_case_creation=false)"
            )
            return

        incident_id = str(row["incident_id"])
        alert_id = row.get("alert_id")
        if not alert_id:
            return

        alert = self.iris.get_alert(int(alert_id))
        existing_case = mapping.as_int(alert.get("alert_case_id"))
        if existing_case:
            self.db.set_case(incident_id, existing_case)
            case = self.iris.get_case(existing_case)
            self.db.update_states(
                incident_id,
                mdr_status=row.get("mdr_status"),
                mdr_update_time=row.get("mdr_update_time"),
                iris_status_id=mapping.as_int(alert.get("alert_status_id")),
                iris_case_status_id=_case_status_id(case),
            )
            return

        mode = str(self.mapping_cfg.get("mode", "escalate")).lower()
        if mode == "merge":
            target_case_id = self._merge_target(incident)
            if not target_case_id:
                raise RuntimeError(
                    f"cannot merge incident {incident_id}: no target case configured"
                )
            self.iris.merge_alert(
                int(alert_id), mapping.build_merge_payload(incident, target_case_id)
            )
            case_id = target_case_id
        else:
            case_data = self.iris.escalate_alert(
                int(alert_id), mapping.build_escalation_payload(incident, self.cfg)
            )
            case_id = case_id_from_response(case_data)
            if case_id is None:
                raise RuntimeError(
                    f"IRIS did not return case_id for alert #{alert_id}"
                )

        self.db.set_case(incident_id, case_id)
        self.stats["cases_created"] += 1
        try:
            case = self.iris.get_case(case_id)
        except Exception:  # noqa: BLE001
            self.log.exception("cannot read IRIS case #%s after creation", case_id)
            case = {}
        self.db.update_states(
            incident_id,
            mdr_status=row.get("mdr_status"),
            mdr_update_time=row.get("mdr_update_time"),
            iris_status_id=row.get("iris_status_id"),
            iris_case_status_id=_case_status_id(case),
        )
        self.log.info("incident %s linked to IRIS case #%s", incident_id, case_id)

    # ------------------------------------------------------------- statuses
    def _sync_statuses(self) -> None:
        rows = self.db.list_incidents()
        if not rows:
            self.log.info("status sync: no mapped incidents yet")
            return

        closed_case_id = int(self.iris_cfg.get("closed_case_status_id", 3))
        closed_alert_id = int(self.iris_cfg.get("closed_alert_status_id", 3))
        status_map = self.mapping_cfg.get("status_to_iris", {})
        default_alert_status = int(
            self.mapping_cfg.get("default_alert_status_id", 1)
        )
        policy = str(self.mapping_cfg.get("conflict_policy", "mdr_wins"))

        for row in rows:
            if not self._sync_allowed(row):
                continue
            incident_id = str(row["incident_id"])
            try:
                incident = self._get_incident_data(row)
                if not incident:
                    self.stats["errors"] += 1
                    continue

                mdr_status = str(incident.get("status") or "")
                mdr_update_time = mapping.as_int(
                    incident.get("update_time"), row.get("mdr_update_time")
                )
                alert = self.iris.get_alert(int(row["alert_id"]))
                iris_alert_status = mapping.as_int(
                    alert.get("alert_status_id"), row.get("iris_status_id")
                )

                case: Dict[str, Any] = {}
                iris_case_status = row.get("iris_case_status_id")
                if row.get("case_id"):
                    case = self.iris.get_case(int(row["case_id"]))
                    iris_case_status = _case_status_id(case) or iris_case_status

                mdr_changed = mapping.normalize(mdr_status) != mapping.normalize(
                    row.get("mdr_status")
                )
                iris_changed = (
                    iris_alert_status != row.get("iris_status_id")
                    or iris_case_status != row.get("iris_case_status_id")
                )

                if not mdr_changed and not iris_changed:
                    continue

                apply_from_iris = False
                if mdr_changed and iris_changed:
                    self.log.warning(
                        "status conflict for incident %s: MDR=%s IRIS alert=%s case=%s "
                        "(policy=%s)",
                        incident_id,
                        mdr_status,
                        iris_alert_status,
                        iris_case_status,
                        policy,
                    )
                    if policy == "iris_wins":
                        apply_from_iris = True
                    elif policy == "last_write":
                        mdr_ts = int(mdr_update_time or 0)
                        iris_ts = _iris_timestamp(case or alert)
                        apply_from_iris = iris_ts > mdr_ts
                elif iris_changed:
                    apply_from_iris = True

                if not apply_from_iris:
                    self._apply_mdr_to_iris(
                        row,
                        incident_id,
                        mdr_status,
                        alert,
                        case,
                        iris_alert_status,
                        iris_case_status,
                        status_map,
                        default_alert_status,
                        closed_case_id,
                    )
                else:
                    self._apply_iris_to_mdr(
                        row,
                        incident_id,
                        mdr_status,
                        alert,
                        case,
                        iris_alert_status,
                        closed_alert_id,
                        closed_case_id,
                    )

                # Re-read the final state so the DB always reflects reality.
                alert = self.iris.get_alert(int(row["alert_id"]))
                iris_alert_status = mapping.as_int(
                    alert.get("alert_status_id"), iris_alert_status
                )
                if row.get("case_id"):
                    case = self.iris.get_case(int(row["case_id"]))
                    iris_case_status = _case_status_id(case) or iris_case_status

                if apply_from_iris and self._is_mdr_closed(mdr_status):
                    mdr_status = "Closed"

                self.db.update_states(
                    incident_id,
                    mdr_status=mdr_status,
                    mdr_update_time=mdr_update_time,
                    iris_status_id=iris_alert_status,
                    iris_case_status_id=iris_case_status,
                )

            except Exception:  # noqa: BLE001
                self.stats["errors"] += 1
                self.log.exception("status sync failed for incident %s", incident_id)

    def _apply_mdr_to_iris(
        self,
        row: Dict[str, Any],
        incident_id: str,
        mdr_status: str,
        alert: Dict[str, Any],
        case: Dict[str, Any],
        iris_alert_status: Optional[int],
        iris_case_status: Optional[int],
        status_map: Dict[str, int],
        default_alert_status: int,
        closed_case_id: int,
    ) -> None:
        target_alert_status = mapping.status_to_alert_status(
            mdr_status, status_map, default_alert_status
        )
        if target_alert_status != iris_alert_status:
            self.iris.update_alert(
                int(row["alert_id"]), {"alert_status_id": target_alert_status}
            )
            self.stats["status_updates_iris"] += 1
            self.log.info(
                "incident %s: IRIS alert #%s status %s -> %s",
                incident_id,
                row["alert_id"],
                iris_alert_status,
                target_alert_status,
            )

        if not row.get("case_id") or not self.mapping_cfg.get("sync_case_status", True):
            return

        if self._is_mdr_closed(mdr_status):
            target_case_status = closed_case_id
        elif self._is_case_closed(case, iris_case_status):
            if not self.mapping_cfg.get("reopen_iris_case", False):
                return
            target_case_status = int(self.iris_cfg.get("case_status_id", 2))
        else:
            target_case_status = int(self.iris_cfg.get("case_status_id", 2))

        if target_case_status != iris_case_status:
            self.iris.update_case_state(
                int(row["case_id"]), target_case_status
            )
            self.stats["status_updates_iris"] += 1
            self.log.info(
                "incident %s: IRIS case #%s status %s -> %s",
                incident_id,
                row["case_id"],
                iris_case_status,
                target_case_status,
            )

    def _close_note(self, alert: Dict[str, Any], case: Dict[str, Any]) -> str:
        """Return the note entered when the IRIS object was closed."""
        if case:
            for key in (
                "case_resolution_note",
                "resolution_note",
                "case_close_note",
                "case_note",
                "note",
            ):
                value = case.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        for key in ("alert_note", "close_note", "note"):
            value = alert.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ""

    def _send_close_note(
        self, incident_id: str, alert: Dict[str, Any], case: Dict[str, Any]
    ) -> None:
        """Copy the IRIS close note to MDR before closing the incident."""
        if not self._allow("allow_comments"):
            return
        note = self._close_note(alert, case)
        if not note:
            return
        source_key = f"close-note:{incident_id}"
        if self.db.comment_seen("iris2mdr", source_key):
            return
        created = str(alert.get("date_update") or case.get("case_close_date") or "")
        formatted = mapping.format_comment(
            self.mapping_cfg.get("comment_prefix_iris", "[IRIS]"),
            "Close note",
            created,
            note,
        )
        try:
            self.mdr.create_comment(incident_id, formatted)
        except MDRApiError:
            self.stats["errors"] += 1
            self.log.exception(
                "incident %s: cannot send IRIS close note to MDR", incident_id
            )
            return
        self.db.mark_comment(
            "iris2mdr", source_key, content_hash=mapping.fingerprint(note)
        )
        self.stats["comments_iris_to_mdr"] += 1
        self.log.info("incident %s: IRIS close note copied to MDR", incident_id)

    def _apply_iris_to_mdr(
        self,
        row: Dict[str, Any],
        incident_id: str,
        mdr_status: str,
        alert: Dict[str, Any],
        case: Dict[str, Any],
        iris_alert_status: Optional[int],
        closed_alert_id: int,
        closed_case_id: int,
    ) -> None:
        iris_closed = (
            self._is_case_closed(case, _case_status_id(case))
            if case
            else iris_alert_status == closed_alert_id
        )
        mdr_closed = self._is_mdr_closed(mdr_status)

        if iris_closed and not mdr_closed:
            self._send_close_note(incident_id, alert, case)
            self.mdr.close_incident(
                incident_id,
                str(self.mapping_cfg.get("close_mdr_resolution", "TRUE_POSITIVE")),
                str(self.mapping_cfg.get("close_mdr_summary", "Closed in DFIR-IRIS")),
            )
            self.stats["status_updates_mdr"] += 1
            self.log.info("incident %s closed in MDR from IRIS", incident_id)
        elif mdr_closed and not iris_closed:
            self.log.warning(
                "incident %s: IRIS case/alert was reopened, but the MDR API has no "
                "reopen operation; MDR stays Closed",
                incident_id,
            )

    # ------------------------------------------------------------- comments
    def _comment_thread(
        self, row: Dict[str, Any]
    ) -> tuple[str, int, List[Dict[str, Any]]]:
        """Return the IRIS object that actually holds comments.

        IRIS v2 stores comments on cases and alerts. IRIS v3.0.0-beta.1 has
        alert comments but no case-comments route, so ``auto`` falls back to
        the alert thread instead of failing the whole sync cycle.
        """
        mode = str(self.iris_cfg.get("comments_object", "auto")).lower()
        case_id = row.get("case_id")
        alert_id = row.get("alert_id")

        candidates: List[tuple[str, Any]] = []
        if mode == "alert":
            candidates = [("alerts", alert_id)]
        elif mode == "case":
            candidates = [("cases", case_id)] if case_id else [("alerts", alert_id)]
        else:
            if case_id:
                candidates.append(("cases", case_id))
            if alert_id:
                candidates.append(("alerts", alert_id))

        last_error: Optional[Exception] = None
        for object_type, object_id in candidates:
            if not object_id:
                continue
            try:
                comments = self.iris.list_comments(object_type, int(object_id))
                return object_type, int(object_id), comments
            except IrisApiError as exc:
                if mode == "auto" and exc.status_code in (404, 405):
                    self.log.info(
                        "comment sync: %s comments unavailable for #%s; trying fallback",
                        object_type,
                        object_id,
                    )
                    last_error = exc
                    continue
                raise

        if last_error:
            raise last_error
        raise RuntimeError(f"incident {row.get('incident_id')} has no comment target")

    def _sync_comments(self) -> None:
        rows = self.db.list_incidents()
        if not rows:
            return

        limit = int(self.mapping_cfg.get("max_comments_per_cycle", 100))
        processed = 0
        mdr_ignore = self.mdr_cfg.get("ignore_comment_authors") or []
        iris_ignore = self.iris_cfg.get("ignore_comment_authors") or []

        for row in rows:
            if not self._sync_allowed(row):
                continue
            if processed >= limit:
                self.log.info("comment sync: cycle limit %s reached", limit)
                break

            incident_id = str(row["incident_id"])
            try:
                mdr_comments = self.mdr.list_comments(incident_id)
                object_type, object_id, iris_comments = self._comment_thread(row)
            except Exception:  # noqa: BLE001
                self.stats["errors"] += 1
                self.log.exception("comment sync: cannot fetch comments for %s", incident_id)
                continue

            # MDR -> IRIS
            for comment in mdr_comments:
                if processed >= limit:
                    break
                comment_key = mapping.comment_id(comment)
                if not comment_key:
                    continue
                source_key = f"mdr:{incident_id}:{comment_key}"
                if self.db.comment_seen("mdr2iris", source_key):
                    continue

                text = mapping.comment_text(comment)
                author = mapping.comment_author(comment)
                if not text:
                    self.db.mark_comment("mdr2iris", source_key)
                    continue
                if self._comment_author_ignored(author, mdr_ignore):
                    self.db.mark_comment("mdr2iris", source_key)
                    continue

                content_hash = mapping.fingerprint(text)
                if self._has_same_comment(iris_comments, text, iris_ignore):
                    self.db.mark_comment(
                        "mdr2iris", source_key, content_hash=content_hash
                    )
                    continue

                formatted = mapping.format_comment(
                    self.mapping_cfg.get("comment_prefix_mdr", "[MDR]"),
                    author,
                    mapping.comment_created(comment),
                    text,
                )
                try:
                    created = self.iris.add_comment(object_type, object_id, formatted)
                except IrisApiError:
                    self.stats["errors"] += 1
                    self.log.exception(
                        "comment sync: MDR comment %s -> IRIS failed", comment_key
                    )
                    continue

                iris_comment_id = comment_id_from_response(created)
                self.db.mark_comment(
                    "mdr2iris",
                    source_key,
                    f"{object_type}:{object_id}:{iris_comment_id}",
                    content_hash,
                )
                self.stats["comments_mdr_to_iris"] += 1
                processed += 1
                self.log.info(
                    "incident %s: MDR comment %s copied to IRIS %s #%s",
                    incident_id,
                    comment_key,
                    object_type,
                    object_id,
                )

            # IRIS -> MDR
            for comment in iris_comments:
                if processed >= limit:
                    break
                comment_key = mapping.comment_id(comment)
                if not comment_key:
                    continue
                source_key = f"{object_type}:{object_id}:{comment_key}"
                if self.db.comment_seen("iris2mdr", source_key):
                    continue
                if self.db.is_our_target("mdr2iris", source_key):
                    continue

                text = mapping.comment_text(comment)
                author = mapping.comment_author(comment)
                login = mapping.comment_login(comment)
                if not text:
                    self.db.mark_comment("iris2mdr", source_key)
                    continue
                if self._comment_author_ignored(author, iris_ignore) or self._comment_author_ignored(login, iris_ignore):
                    self.db.mark_comment("iris2mdr", source_key)
                    continue

                content_hash = mapping.fingerprint(_comment_body(text))
                if self._has_same_comment(mdr_comments, _comment_body(text), mdr_ignore):
                    self.db.mark_comment(
                        "iris2mdr", source_key, content_hash=content_hash
                    )
                    continue

                formatted = mapping.format_comment(
                    self.mapping_cfg.get("comment_prefix_iris", "[IRIS]"),
                    author,
                    mapping.comment_created(comment),
                    _comment_body(text),
                    login=login,
                )
                try:
                    self.mdr.create_comment(incident_id, formatted)
                except MDRApiError:
                    self.stats["errors"] += 1
                    self.log.exception(
                        "comment sync: IRIS comment %s -> MDR failed", comment_key
                    )
                    continue

                self.db.mark_comment(
                    "iris2mdr", source_key, content_hash=content_hash
                )
                self.stats["comments_iris_to_mdr"] += 1
                processed += 1
                self.log.info(
                    "incident %s: IRIS comment %s copied to MDR",
                    incident_id,
                    comment_key,
                )
