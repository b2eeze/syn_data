#!/usr/bin/env python3
"""
Phase 3: 版本匹配 — 将 Phase 1 的依赖版本与 Phase 2 的 CVE 有漏洞版本进行匹配

用法:
    python cve_matcher.py [--dep-file ...] [--cve-file ...] [--base-url ...] [--api-key ...] [--model ...]
"""

import argparse
import json
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
LLM_JUDGE_CACHE: Dict[Tuple[str, str, str], Optional[bool]] = {}

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
LOGGER = logging.getLogger("cve_matcher")


# ===================================================================
# 版本工具函数
# ===================================================================

def normalize_version(version: str) -> str:
    version = str(version).strip()
    match = re.search(r"(\d+(?:\.\d+){0,4})", version)
    return match.group(1) if match else version


def normalize_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", str(name).strip().lower())


def parse_version_parts(version: str) -> Tuple[int, ...]:
    normalized = normalize_version(version)
    if not normalized:
        return ()
    try:
        return tuple(int(part) for part in normalized.split("."))
    except ValueError:
        return ()


def compare_versions(left: str, right: str) -> int:
    left_parts = parse_version_parts(left)
    right_parts = parse_version_parts(right)
    if not left_parts or not right_parts:
        left_norm = normalize_version(left)
        right_norm = normalize_version(right)
        if left_norm == right_norm:
            return 0
        return -1 if left_norm < right_norm else 1
    max_len = max(len(left_parts), len(right_parts))
    padded_left = left_parts + (0,) * (max_len - len(left_parts))
    padded_right = right_parts + (0,) * (max_len - len(right_parts))
    if padded_left == padded_right:
        return 0
    return -1 if padded_left < padded_right else 1


# ===================================================================
# LLM 兜底判断
# ===================================================================

def _sanitize_version(ver: str) -> str:
    """过滤 NaN → '' """
    ver = str(ver).strip()
    return "" if ver.lower() in ("", "nan", "na", "n/a") else ver


def call_openai_judge(base_url: str, api_key: str, model: str,
                      component: str, version: str, cve: str, description: str) -> Optional[bool]:
    if not (base_url and api_key and model):
        return None
    cache_key = (normalize_package_name(component), normalize_version(version), str(cve).strip())
    if cache_key in LLM_JUDGE_CACHE:
        return LLM_JUDGE_CACHE[cache_key]

    url = base_url.rstrip("/") + "/chat/completions"
    prompt = (
        '你是漏洞分析助手。请只回答 JSON，格式为 {"affected": true/false, "is_direct": true/false, "reason": "..."}。\n'
        f"组件名: {component}\n"
        f"组件版本: {version}\n"
        f"CVE: {cve}\n"
        f"描述: {description}\n"
        "请判断两个问题：\n"
        f"1. affected：该版本的 {component} 本身（作为漏洞直接主体）是否受该 CVE 影响？"
        f"注意：若该 CVE 的受影响软件是使用了 {component} 的上层应用（如 XWiki、Jenkins、OFBiz 等），"
        f"而非 {component} 库本身，则 affected 应为 false。\n"
        f"2. is_direct：该 CVE 的漏洞主体是否就是 {component} 本身（而非依赖它的上层应用）？\n"
        "若描述不足以判断，请保守返回 false。"
    )

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a precise vulnerability triage assistant."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0,
    }
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
    response_text = ""
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
        response_text = response.text or ""
        response.raise_for_status()
        data = response.json()
        content = data["choices"][0]["message"]["content"]
        stripped_content = re.sub(r"^```(?:json)?\s*", "", content.strip(), flags=re.IGNORECASE)
        stripped_content = re.sub(r"\s*```$", "", stripped_content)
        parsed = json.loads(stripped_content)
        is_direct = parsed.get("is_direct", True)
        result = bool(parsed.get("affected")) and bool(is_direct)
        LLM_JUDGE_CACHE[cache_key] = result
        return result
    except Exception as exc:
        details = f" response_text={response_text[:1000]}" if response_text else ""
        LOGGER.warning("LLM judge failed for %s: %s%s", cve, exc, details)
        LLM_JUDGE_CACHE[cache_key] = None
        return None


# ===================================================================
# Phase 3 匹配逻辑
# ===================================================================

def _is_empty_version(ver: str) -> bool:
    return _sanitize_version(ver) == ""


def match_component_to_cves(
    component: str, version: str, cve_with_ver: pd.DataFrame,
    cve_no_ver: pd.DataFrame, base_url: str, api_key: str, model: str,
) -> List[Dict[str, str]]:
    """组件名匹配 + 版本比较 / LLM 兜底"""
    normalized_component = normalize_package_name(component)
    matched: List[Dict[str, str]] = []
    seen_cves: set = set()

    # --- 有版本号的 CVE：版本比对 ---
    for _, row in cve_with_ver.iterrows():
        cve_id = str(row["CVE"])
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)

        cve_component_norm = normalize_package_name(str(row["Component"]))
        if normalized_component not in cve_component_norm and cve_component_norm not in normalized_component:
            continue

        dep_version = normalize_version(version)
        last_vuln_norm = normalize_version(str(row["LastVulnerableVersion"]))

        cmp = compare_versions(dep_version, last_vuln_norm)
        if cmp <= 0:
            determination = f"version_cmp_{row.get('ExtractionMethod', '')}"
        else:
            determination = "version_above_vuln"
        matched.append({
            "CVE": cve_id,
            "LastVulnerableVersion": str(row["LastVulnerableVersion"]),
            "Determination": determination,
        })

    # --- 无版本号的 CVE：LLM 兜底 ---
    for _, row in cve_no_ver.iterrows():
        cve_id = str(row["CVE"])
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)

        cve_component_norm = normalize_package_name(str(row["Component"]))
        if normalized_component not in cve_component_norm and cve_component_norm not in normalized_component:
            continue

        description = str(row.get("description", ""))
        llm_result = call_openai_judge(base_url, api_key, model,
                                       component, version, cve_id, description or "")
        if llm_result is True:
            matched.append({
                "CVE": cve_id,
                "LastVulnerableVersion": "",
                "Determination": "llm",
            })
            LOGGER.info("  LLM hit: %s / %s=%s", cve_id, component, version)

    return matched


def run_phase3(dep_df: pd.DataFrame, cve_df: pd.DataFrame,
               base_url: str, api_key: str, model: str) -> pd.DataFrame:
    """Phase 3 主入口"""
    result_rows: List[Dict] = []

    # 处理版本号
    cve_df = cve_df.copy()
    cve_df["_clean_ver"] = cve_df["LastVulnerableVersion"].apply(_sanitize_version)
    cve_no_ver = cve_df[cve_df["_clean_ver"] == ""].copy()
    cve_with_ver = cve_df[cve_df["_clean_ver"] != ""].copy()

    # 为无版本号的 CVE 加载描述
    if not cve_no_ver.empty and base_url and api_key and model:
        try:
            conn = sqlite3.connect("vuln_ruler_filtered.db")
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT cve_id, content_preview FROM cve_records").fetchall()
            conn.close()
            desc_map = {r["cve_id"]: (r["content_preview"] or "") for r in rows}
            cve_no_ver["description"] = cve_no_ver["CVE"].map(desc_map).fillna("")
            LOGGER.info("Loaded descriptions for %d no-version CVEs", len(cve_no_ver))
        except Exception as exc:
            LOGGER.warning("Failed to load CVE descriptions: %s", exc)
            cve_no_ver["description"] = ""

    LOGGER.info("CVE records: %d with version, %d no-version (LLM fallback)",
                len(cve_with_ver), len(cve_no_ver))

    total = len(dep_df)
    for i, (_, dep_row) in enumerate(dep_df.iterrows()):
        repo_name = str(dep_row["RepoName"])
        tag = str(dep_row["Tag"])
        component = str(dep_row["Component"])
        version = str(dep_row["Version"])
        source_file = str(dep_row.get("SourceFile", ""))

        matched_cves = match_component_to_cves(
            component, version, cve_with_ver, cve_no_ver, base_url, api_key, model,
        )

        if matched_cves:
            for m in matched_cves:
                result_rows.append({
                    "RepoName": repo_name,
                    "Tag": tag,
                    "Component": component,
                    "UsedVersion": version,
                    "SourceFile": source_file,
                    "CVE": m["CVE"],
                    "VulnerableVersion": m["LastVulnerableVersion"],
                    "Determination": m["Determination"],
                })
            LOGGER.info("[%d/%d] %s @ %s / %s %s: %d CVE hits",
                        i + 1, total, repo_name, tag, component, version, len(matched_cves))
        else:
            LOGGER.info("[%d/%d] %s @ %s / %s %s: no CVE hits",
                        i + 1, total, repo_name, tag, component, version)

    if result_rows:
        df = pd.DataFrame(result_rows, columns=[
            "RepoName", "Tag", "Component", "UsedVersion", "SourceFile",
            "CVE", "VulnerableVersion", "Determination",
        ])
    else:
        df = pd.DataFrame(columns=[
            "RepoName", "Tag", "Component", "UsedVersion", "SourceFile",
            "CVE", "VulnerableVersion", "Determination",
        ])

    LOGGER.info("Phase 3 complete: %d total matches", len(df))
    return df


# ===================================================================
# 主入口
# ===================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CVE 匹配 (Phase 3)")
    parser.add_argument("--dep-file", default="data/dep_scan_result.xlsx", help="Phase 1 输出")
    parser.add_argument("--cve-file", default="data/cve_version_result.xlsx", help="Phase 2 输出")
    parser.add_argument("--output", default="data/cve_match_result.xlsx", help="Phase 3 输出")
    parser.add_argument("--base-url", default=os.environ.get("LLM_BASE_URL", ""),
                        help="API base URL（也可用 LLM_BASE_URL 环境变量）")
    parser.add_argument("--api-key", default=os.environ.get("LLM_API_KEY", ""),
                        help="API key（也可用 LLM_API_KEY 环境变量）")
    parser.add_argument("--model", default=os.environ.get("LLM_MODEL", ""),
                        help="模型名（也可用 LLM_MODEL 环境变量）")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    LOGGER.info("Loading dependency data from %s", args.dep_file)
    dep_df = pd.read_excel(args.dep_file)
    LOGGER.info("Loaded %d dependency records", len(dep_df))

    LOGGER.info("Loading CVE version data from %s", args.cve_file)
    cve_df = pd.read_excel(args.cve_file)
    LOGGER.info("Loaded %d CVE version records", len(cve_df))

    LOGGER.info("==== Phase 3: CVE Matching ====")
    result_df = run_phase3(dep_df, cve_df, args.base_url, args.api_key, args.model)
    result_df.to_excel(args.output, index=False)
    LOGGER.info("Phase 3 output written to %s (%d rows)", args.output, len(result_df))

    if not result_df.empty:
        LOGGER.info("=== Summary ===")
        LOGGER.info("Total matches: %d", len(result_df))
        LOGGER.info("Unique repos affected: %d", result_df["RepoName"].nunique())
        LOGGER.info("Unique components affected: %d", result_df["Component"].nunique())
        LOGGER.info("Unique CVEs matched: %d", result_df["CVE"].nunique())
        determ_counts = result_df["Determination"].value_counts().to_dict()
        for k, v in determ_counts.items():
            LOGGER.info("  %s: %d", k, v)


if __name__ == "__main__":
    main()
