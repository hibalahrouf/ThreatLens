"""
Semantic root-cause grouping for findings.

This module intentionally has a deterministic fallback so scan quality does not
depend on an available LLM. The grouping is used before triage to annotate
findings and to let representative findings drive later review workflows.
"""

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable


@dataclass
class DedupGroup:
    group_id: str
    root_cause: str
    finding_ids: list[int]
    representative_title: str


def group_findings_by_root_cause(findings: Iterable) -> list[DedupGroup]:
    """Group ORM findings by likely root cause."""
    findings = list(findings)
    if not findings:
        return []

    llm_groups = _try_llm_grouping(findings)
    if llm_groups:
        return llm_groups
    return _fallback_grouping(findings)


def _try_llm_grouping(findings: list) -> list[DedupGroup]:
    """Use the configured chat LLM when available; return [] on any failure."""
    try:
        from app.engines.llm_triage import LLMClient

        payload = [
            {
                "id": f.id,
                "title": f.title,
                "description": f.description or "",
                "masvs_control": f.masvs_control,
                "affected_file": f.affected_file,
            }
            for f in findings[:80]
        ]
        prompt = (
            "Group these mobile security findings by shared ROOT CAUSE. "
            "Return JSON only as an array of objects with keys: "
            "root_cause, finding_ids, representative_title.\n\n"
            f"{json.dumps(payload, ensure_ascii=True)}"
        )
        response = LLMClient().chat(
            system_prompt="You cluster security findings by root cause for audit triage.",
            user_prompt=prompt,
            json_mode=True,
        )
        raw_groups = json.loads(response)
        groups = []
        valid_ids = {f.id for f in findings}
        for item in raw_groups if isinstance(raw_groups, list) else []:
            ids = [int(i) for i in item.get("finding_ids", []) if int(i) in valid_ids]
            if not ids:
                continue
            root = str(item.get("root_cause") or item.get("representative_title") or "Related findings")
            groups.append(DedupGroup(
                group_id=_stable_group_id(root, ids),
                root_cause=root,
                finding_ids=ids,
                representative_title=str(item.get("representative_title") or root),
            ))
        return groups
    except Exception:
        return []


def _fallback_grouping(findings: list) -> list[DedupGroup]:
    buckets = defaultdict(list)
    for f in findings:
        key = "|".join([
            (f.masvs_control or "MASVS-GENERIC").lower(),
            _normalize_title(f.title),
        ])
        buckets[key].append(f)

    groups = []
    for key, members in buckets.items():
        ids = [m.id for m in members]
        title = members[0].title
        root = f"{members[0].masvs_control or 'Unmapped'}: {_plain_title(title)}"
        groups.append(DedupGroup(
            group_id=_stable_group_id(key, ids),
            root_cause=root,
            finding_ids=ids,
            representative_title=title,
        ))
    return groups


def _normalize_title(title: str) -> str:
    words = []
    for token in (title or "").lower().replace("_", " ").replace("-", " ").split():
        if token.isdigit() or len(token) <= 2:
            continue
        if token in {"the", "and", "for", "with", "from", "this", "that", "file", "line"}:
            continue
        words.append(token)
    return " ".join(words[:8]) or "finding"


def _plain_title(title: str) -> str:
    title = " ".join((title or "Related finding").split())
    return title[:117] + "..." if len(title) > 120 else title


def _stable_group_id(seed: str, ids: list[int]) -> str:
    digest = hashlib.sha1(f"{seed}:{','.join(map(str, sorted(ids)))}".encode("utf-8")).hexdigest()
    return digest[:16]
