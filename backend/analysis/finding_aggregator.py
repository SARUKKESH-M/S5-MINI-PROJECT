"""
CodeSentinel — Step 6N: Security Finding Aggregator

Aggregates, deduplicates, sorts, caps, and recalculates summary statistics for
normalized security findings across repository files.
"""

from typing import Any, Dict, List, Optional, Tuple

MAX_FINDINGS = 20

SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "unknown": 0
}

CONFIDENCE_RANK = {
    "high": 2,
    "medium": 1,
    "low": 0
}


def _evidence_identity(ev: Dict[str, Any]) -> Tuple[str, Optional[int], Optional[int], str, str]:
    """Generates a stable comparison tuple for an evidence item."""
    return (
        str(ev.get("document_id", "")),
        ev.get("line_start"),
        ev.get("line_end"),
        str(ev.get("signal_type", "")),
        str(ev.get("signal_name", ""))
    )


def aggregate_and_deduplicate_findings(
    normalized_findings: List[Dict[str, Any]],
    file_stats: Optional[Dict[str, int]] = None
) -> Dict[str, Any]:
    """
    Deduplicates normalized findings, merges evidence, ranks deterministically,
    reassigns sequential finding IDs (finding_1, finding_2, ...), caps at MAX_FINDINGS,
    and recalculates summary counts.

    Returns dict containing 'summary' and 'findings'.
    """
    if not isinstance(normalized_findings, list) or not normalized_findings:
        stats = file_stats or {}
        return {
            "summary": {
                "total_files": stats.get("total_files", 0),
                "analyzed_files": stats.get("analyzed_files", 0),
                "skipped_files": stats.get("skipped_files", 0),
                "total_findings": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
            },
            "findings": []
        }

    # Group findings by normalized security identity
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}

    for f in normalized_findings:
        cat = str(f.get("category", "")).lower().strip()
        title = str(f.get("title", "")).lower().strip()
        stable_evidence_id = str(f.get("evidence_id", "")).strip()
        
        # Primary evidence signature
        ev_list = f.get("evidence", [])
        if ev_list and isinstance(ev_list, list):
            primary_ev = ev_list[0]
            doc_id = str(primary_ev.get("document_id", ""))
            sig_type = str(primary_ev.get("signal_type", ""))
            sig_name = str(primary_ev.get("signal_name", ""))
            identity_key = ("evidence", stable_evidence_id) if stable_evidence_id else (cat, title, doc_id, sig_type, sig_name)
        else:
            identity_key = ("evidence", stable_evidence_id) if stable_evidence_id else (cat, title, "", "", "")

        if identity_key not in groups:
            groups[identity_key] = []
        groups[identity_key].append(f)

    merged_findings: List[Dict[str, Any]] = []

    for group in groups.values():
        first = group[0]

        # Determine strongest severity and confidence in group
        best_sev = first.get("severity", "unknown")
        best_conf = first.get("confidence", "low")

        for item in group[1:]:
            curr_sev = item.get("severity", "unknown")
            if SEVERITY_RANK.get(curr_sev, 0) > SEVERITY_RANK.get(best_sev, 0):
                best_sev = curr_sev

            curr_conf = item.get("confidence", "low")
            if CONFIDENCE_RANK.get(curr_conf, 0) > CONFIDENCE_RANK.get(best_conf, 0):
                best_conf = curr_conf

        # Merge unique evidence items
        merged_evidence: List[Dict[str, Any]] = []
        seen_ev = set()

        for item in group:
            for ev in item.get("evidence", []):
                ev_id = _evidence_identity(ev)
                if ev_id not in seen_ev:
                    seen_ev.add(ev_id)
                    merged_evidence.append(ev)

        merged_findings.append({
            "finding_id": "",
            "title": first.get("title", "Security Finding"),
            "description": first.get("description", ""),
            "severity": best_sev,
            "confidence": best_conf,
            "category": first.get("category", "General Security"),
            "evidence": merged_evidence,
            "evidence_id": first.get("evidence_id", ""),
            "file_path": first.get("file_path", ""),
            "line": first.get("line"),
            "source": first.get("source", "ast"),
            "enriched_by": first.get("enriched_by", []),
            "recommendation": first.get("recommendation", ""),
        })

    # Sort merged findings deterministically:
    # 1. Severity rank (descending)
    # 2. Confidence rank (descending)
    # 3. Category (ascending)
    # 4. Title (ascending)
    # 5. First evidence document_id (ascending)
    def _sort_key(item: Dict[str, Any]):
        sev_r = SEVERITY_RANK.get(item.get("severity", "unknown"), 0)
        conf_r = CONFIDENCE_RANK.get(item.get("confidence", "low"), 0)
        cat = str(item.get("category", ""))
        title = str(item.get("title", ""))
        ev_doc = ""
        if item.get("evidence"):
            ev_doc = str(item["evidence"][0].get("document_id", ""))
        return (-sev_r, -conf_r, cat, title, ev_doc)

    merged_findings.sort(key=_sort_key)

    # Cap at MAX_FINDINGS (20 max) and assign deterministic finding IDs
    bounded_findings = merged_findings[:MAX_FINDINGS]
    final_findings: List[Dict[str, Any]] = []

    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    for idx, f in enumerate(bounded_findings, start=1):
        f["finding_id"] = f"finding_{idx}"
        final_findings.append(f)

        sev = f["severity"]
        if sev in counts:
            counts[sev] += 1
        else:
            counts["info"] += 1

    stats = file_stats or {}
    summary = {
        "total_files": stats.get("total_files", 0),
        "analyzed_files": stats.get("analyzed_files", 0),
        "skipped_files": stats.get("skipped_files", 0),
        "total_findings": len(final_findings),
        "critical_count": counts["critical"],
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
        "info_count": counts["info"]
    }

    return {
        "summary": summary,
        "findings": final_findings
    }
