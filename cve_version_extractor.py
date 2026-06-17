#!/usr/bin/env python3
"""
Phase 2: CVE 版本提取 — 从 vuln_ruler_filtered.db 的 CVE 描述中提取最后一个有漏洞的版本号

用法:
    python cve_version_extractor.py [--targets-xlsx ...] [--base-url ...] [--api-key ...] [--model ...]
"""

import argparse
import logging
import os
import re
import sqlite3
from typing import Dict, List, Optional, Tuple

import pandas as pd
import requests

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT = 60

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
LOGGER = logging.getLogger("cve_version_extractor")


# ===================================================================
# 版本工具函数
# ===================================================================

def normalize_version(version: str) -> str:
    version = str(version).strip()
    match = re.search(r"(\d+(?:\.\d+){0,4})", version)
    return match.group(1) if match else version


def parse_version_parts(version: str) -> Tuple[int, ...]:
    normalized = normalize_version(version)
    if not normalized:
        return ()
    try:
        return tuple(int(part) for part in normalized.split("."))
    except ValueError:
        return ()


# ===================================================================
# CVE 版本范围提取正则
# ===================================================================

VERSION_TEXT_REGEX = re.compile(r"\d+\.\d+(?:\.\d+){0,3}")
EXPLICIT_RANGE_HINTS = ("before", "prior to", "through", "up to", "upto", "starting in version", "from ")

START_BEFORE_RANGE_REGEX = re.compile(
    r"starting in version\s+(?P<lower>\d+\.\d+(?:\.\d+){0,3})\s+and\s+(?P<mode>prior to|before)\s+version\s+(?P<upper>\d+\.\d+(?:\.\d+){0,3})",
    re.IGNORECASE,
)
GENERIC_BOUNDED_RANGE_REGEX = re.compile(
    r"(?:from\s+)?(?P<lower>\d+\.\d+(?:\.\d+){0,3})\s+through\s+(?P<upper>\d+\.\d+(?:\.\d+){0,3})",
    re.IGNORECASE,
)
BRANCH_BEFORE_REGEX = re.compile(
    r"(?P<branch>\d+(?:\.\d+)*)\.x\s+before\s+(?P<upper>\d+\.\d+(?:\.\d+){0,3})",
    re.IGNORECASE,
)
GENERIC_UPPER_BOUND_REGEX = re.compile(
    r"(?P<mode>before|prior to|through|up to|upto)\s+(?:versions?\s+)?(?P<upper>\d+\.\d+(?:\.\d+){0,3})",
    re.IGNORECASE,
)


# ===================================================================
# 数据库加载
# ===================================================================

def load_cve_records(db_path: str, targets_xlsx: str) -> List[Dict]:
    """读取 CVE 记录：从 xlsx 获取 target→CVE 映射，从 db 获取 content_preview。"""
    # 1. 从 xlsx 读 target_name → cve_list
    xlsx_df = pd.read_excel(targets_xlsx)
    target_cve_map: Dict[str, str] = {}  # cve_id → component_name
    for _, row in xlsx_df.iterrows():
        target_name = str(row["target_name"])
        cve_str = str(row.get("cve_list", "") or "")
        for cve_id in cve_str.split(","):
            cve_id = cve_id.strip()
            if cve_id:
                target_cve_map[cve_id] = target_name
    LOGGER.info("Loaded %d CVE IDs from %d targets in %s", len(target_cve_map), len(xlsx_df), targets_xlsx)

    # 2. 从 db 读 cve_records，只看 xlsx 中的 CVE
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT cve_id, content_preview FROM cve_records").fetchall()
    conn.close()

    records = []
    for r in rows:
        cve_id = r["cve_id"]
        if cve_id in target_cve_map:
            records.append({
                "cve_id": cve_id,
                "component_name": target_cve_map[cve_id],
                "content_preview": r["content_preview"] or "",
            })

    LOGGER.info("Matched %d CVE records from %s", len(records), db_path)
    return records


# ===================================================================
# 版本提取逻辑
# ===================================================================

def extract_last_vulnerable_version(description: str) -> Tuple[Optional[str], str]:
    """
    从 CVE 描述的 content_preview 中提取最后一个有漏洞的版本号。
    返回 (last_vulnerable_version, extraction_method)
    extraction_method: 'regex' | 'llm' | 'none'
    """
    desc = (description or "").lower()
    if not desc:
        return None, "none"

    candidates: List[Tuple[str, bool]] = []

    # 1. "starting in version X and prior to Y"
    for m in START_BEFORE_RANGE_REGEX.finditer(desc):
        candidates.append((m.group("upper"), False))

    # 2. "from X through Y"
    for m in GENERIC_BOUNDED_RANGE_REGEX.finditer(desc):
        candidates.append((m.group("upper"), True))

    # 3. "X.x before Y"
    for m in BRANCH_BEFORE_REGEX.finditer(desc):
        candidates.append((m.group("upper"), False))

    # 4. "before/prior to/through/up to Y"
    for m in GENERIC_UPPER_BOUND_REGEX.finditer(desc):
        mode = m.group("mode").lower()
        is_inclusive = mode in {"through", "up to", "upto"}
        candidates.append((m.group("upper"), is_inclusive))

    # 5. 兜底：有范围提示词时取最大版本号
    if not candidates and any(hint in desc for hint in EXPLICIT_RANGE_HINTS):
        mentioned = [normalize_version(v) for v in VERSION_TEXT_REGEX.findall(desc)]
        mentioned = [v for v in mentioned if v]
        if mentioned:
            highest = max(mentioned, key=lambda v: parse_version_parts(v) or ())
            candidates.append((highest, True))

    if candidates:
        best = max(candidates, key=lambda c: parse_version_parts(c[0]) or ())
        return best[0], "regex"

    return None, "none"


def call_llm_extract_version(base_url: str, api_key: str, model: str,
                             component: str, cve_id: str, description: str) -> Optional[str]:
    """使用 LLM 从 CVE 描述中提取最后有漏洞的版本号"""
    url = base_url.rstrip("/") + "/chat/completions"
    prompt = (
        f"请从以下 CVE 描述中提取最后一个受影响的版本号（即修复版本之前的最高版本）。\n"
        f"只返回版本号，例如 '5.3.13' 或 '2.5.2'。如果无法确定，返回 'N/A'。\n\n"
        f"组件: {component}\n"
        f"CVE: {cve_id}\n"
        f"描述: {description[:2000]}\n"
    )
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a precise CVE version extractor. Reply with version number only."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0,
    }
    req_headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
    try:
        resp = requests.post(url, headers=req_headers, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        content = data["choices"][0]["message"]["content"].strip()
        match = re.search(r"(\d+\.\d+(?:\.\d+){0,3})", content)
        if match:
            return match.group(1)
        if content.upper() == "N/A":
            return None
        return None
    except Exception as exc:
        LOGGER.warning("LLM version extraction failed for %s: %s", cve_id, exc)
        return None


def run(cve_records: List[Dict], base_url: str, api_key: str,
        model: str) -> pd.DataFrame:
    """主入口：从 CVE 描述中提取版本。按 (cve_id, component) 去重。"""
    rows: List[Dict] = []
    seen_keys = set()
    regex_count = 0
    llm_count = 0
    none_count = 0

    total_candidates = sum(1 for _ in cve_records)  # 含重复，仅用于估算
    for i, record in enumerate(cve_records):
        cve_id = record["cve_id"]
        component_name = record["component_name"]
        content_preview = record.get("content_preview") or ""

        dedup_key = (cve_id, component_name.lower())
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        idx = len(seen_keys)
        version, method = extract_last_vulnerable_version(content_preview)

        if version is None and base_url and api_key and model:
            LOGGER.info("[%d] LLM extracting %s / %s ...", idx, component_name, cve_id)
            llm_version = call_llm_extract_version(base_url, api_key, model,
                                                   component_name, cve_id, content_preview)
            if llm_version:
                version = llm_version
                method = "llm"
                LOGGER.info("[%d] LLM hit: %s", idx, llm_version)
            else:
                LOGGER.info("[%d] LLM miss", idx)
        elif version is not None:
            LOGGER.info("[%d] regex hit: %s / %s -> %s", idx, component_name, cve_id, version)

        if method == "regex":
            regex_count += 1
        elif method == "llm":
            llm_count += 1
        else:
            none_count += 1

        rows.append({
            "CVE": cve_id,
            "Component": component_name,
            "LastVulnerableVersion": version if version else "",
            "ExtractionMethod": method,
        })

    LOGGER.info("Done: unique=%d, regex=%d, llm=%d, none=%d", len(rows), regex_count, llm_count, none_count)
    df = pd.DataFrame(rows, columns=["CVE", "Component", "LastVulnerableVersion", "ExtractionMethod"])
    df["LastVulnerableVersion"] = df["LastVulnerableVersion"].fillna("")
    return df


# ===================================================================
# 命令行入口
# ===================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CVE 版本提取 (Phase 2)")
    parser.add_argument("--targets-xlsx", default="data/uncovered_library_cves.xlsx", help="目标组件+CVE列表 Excel")
    parser.add_argument("--vuln-db", default="vuln_ruler_filtered.db", help="CVE 数据库路径（读取 content_preview）")
    parser.add_argument("--output", default="data/cve_version_result.xlsx", help="输出文件路径")
    parser.add_argument("--base-url", default=os.environ.get("LLM_BASE_URL", ""),
                        help="API base URL（也可用 LLM_BASE_URL 环境变量）")
    parser.add_argument("--api-key", default=os.environ.get("LLM_API_KEY", ""),
                        help="API key（也可用 LLM_API_KEY 环境变量）")
    parser.add_argument("--model", default=os.environ.get("LLM_MODEL", ""),
                        help="模型名（也可用 LLM_MODEL 环境变量）")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    cve_records = load_cve_records(args.vuln_db, args.targets_xlsx)
    LOGGER.info("Loaded %d CVE records", len(cve_records))

    LOGGER.info("==== Phase 2: CVE Version Extraction ====")
    cve_df = run(cve_records, args.base_url, args.api_key, args.model)
    cve_df.to_excel(args.output, index=False)
    LOGGER.info("Output written to %s (%d rows)", args.output, len(cve_df))


if __name__ == "__main__":
    main()
