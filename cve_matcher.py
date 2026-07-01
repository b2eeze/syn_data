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
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

import pandas as pd
import requests
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT = 60
LLM_JUDGE_CACHE: Dict[Tuple[str, str, str], Optional[bool]] = {}
LLM_JUDGE_LOCK = threading.Lock()

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

def _parse_ranges(ranges_str: str) -> List[List]:
    """解析版本区间 JSON，解析失败返回空列表。"""
    if not ranges_str or not isinstance(ranges_str, str):
        return []
    try:
        parsed = json.loads(ranges_str)
        if isinstance(parsed, list):
            return parsed
    except (json.JSONDecodeError, TypeError):
        pass
    return []


def _version_in_any_range(version: str, ranges: List[List]) -> bool:
    """检查 version 是否在任一区间内。"""
    for r in ranges:
        if len(r) != 3:
            continue
        lower, upper, inclusive = str(r[0]), str(r[1]), int(r[2])
        # 下界比较
        if lower:
            if compare_versions(version, lower) < 0:
                continue  # version < lower, 不在本区间
        # 上界比较
        if inclusive:
            if compare_versions(version, upper) <= 0:
                return True
        else:
            if compare_versions(version, upper) < 0:
                return True
    return False


def call_openai_judge(base_url: str, api_key: str, model: str,
                      component: str, version: str, cve: str, description: str) -> Optional[bool]:
    if not (base_url and api_key and model):
        return None
    cache_key = (normalize_package_name(component), normalize_version(version), str(cve).strip())
    with LLM_JUDGE_LOCK:
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
        with LLM_JUDGE_LOCK:
            LLM_JUDGE_CACHE[cache_key] = result
        return result
    except Exception as exc:
        details = f" response_text={response_text[:1000]}" if response_text else ""
        LOGGER.warning("LLM judge failed for %s: %s%s", cve, exc, details)
        with LLM_JUDGE_LOCK:
            LLM_JUDGE_CACHE[cache_key] = None
        return None


# ===================================================================
# Phase 3 匹配逻辑
# ===================================================================


def _build_cve_index(cve_with_ver: pd.DataFrame) -> Dict[str, List[Tuple[str, str, str]]]:
    """预构建 CVE 索引: {normalized_component: [(cve_id, ranges_str, method), ...]}"""
    index: Dict[str, List[Tuple[str, str, str]]] = defaultdict(list)
    for _, row in cve_with_ver.iterrows():
        comp_norm = normalize_package_name(str(row["Component"]))
        index[comp_norm].append((
            str(row["CVE"]),
            str(row.get("VulnerableVersionRanges", "")),
            str(row.get("ExtractionMethod", "")),
        ))
    return dict(index)


def match_component_to_cves(
    component: str, version: str,
    cve_index: Dict[str, List[Tuple[str, str, str]]],
    cve_no_ver_index: Dict[str, List[Tuple[str, str]]],
    base_url: str, api_key: str, model: str,
) -> List[Dict[str, str]]:
    """组件名匹配 + 版本比较 / LLM 兜底（使用预构建索引）"""
    normalized_component = normalize_package_name(component)
    dep_version = normalize_version(version)
    matched: List[Dict[str, str]] = []
    seen_cves: set = set()

    # --- 有版本区间的 CVE：用索引做 O(1) 查找 ---
    for comp_norm, cve_list in cve_index.items():
        if normalized_component not in comp_norm and comp_norm not in normalized_component:
            continue
        for cve_id, ranges_str, method in cve_list:
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)
            ranges = _parse_ranges(ranges_str)
            if ranges and _version_in_any_range(dep_version, ranges):
                matched.append({
                    "CVE": cve_id,
                    "VulnerableVersionRanges": ranges_str,
                    "Determination": f"version_cmp_{method}",
                })
            elif ranges:
                continue  # 版本在区间外
            else:
                matched.append({
                    "CVE": cve_id,
                    "VulnerableVersionRanges": ranges_str,
                    "Determination": "version_no_range",
                })

    # --- 无版本号的 CVE：LLM 兜底 ---
    for comp_norm, cve_list in cve_no_ver_index.items():
        if normalized_component not in comp_norm and comp_norm not in normalized_component:
            continue
        for cve_id, description in cve_list:
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)
            llm_result = call_openai_judge(base_url, api_key, model,
                                           component, version, cve_id, description or "")
            if llm_result is True:
                matched.append({
                    "CVE": cve_id,
                    "VulnerableVersionRanges": "",
                    "Determination": "llm",
                })
                LOGGER.info("  LLM hit: %s / %s=%s", cve_id, component, version)

    return matched


def _process_one_dep(dep_row: pd.Series, cve_index, cve_no_ver_index,
                     base_url: str, api_key: str, model: str) -> List[Dict]:
    """处理单个依赖记录，返回匹配结果列表。"""
    repo_name = str(dep_row["RepoName"])
    tag = str(dep_row["Tag"])
    component = str(dep_row["Component"])
    version = str(dep_row["Version"])
    source_file = str(dep_row.get("SourceFile", ""))

    matched_cves = match_component_to_cves(
        component, version, cve_index, cve_no_ver_index,
        base_url, api_key, model,
    )
    results = []
    for m in matched_cves:
        results.append({
            "RepoName": repo_name,
            "Tag": tag,
            "Component": component,
            "UsedVersion": version,
            "SourceFile": source_file,
            "CVE": m["CVE"],
            "VulnerableVersionRanges": m.get("VulnerableVersionRanges", ""),
            "Determination": m["Determination"],
        })
    return results


def run_phase3(dep_df: pd.DataFrame, cve_df: pd.DataFrame,
               base_url: str, api_key: str, model: str,
               workers: int = 8) -> pd.DataFrame:
    """Phase 3 主入口（支持并行 LLM 调用）"""
    cve_df = cve_df.copy()

    # 处理版本号
    cve_df["_has_ranges"] = cve_df["VulnerableVersionRanges"].apply(
        lambda v: bool(v) if isinstance(v, str) and v.strip() and v.strip() != "[]" else False
    )
    cve_no_ver = cve_df[~cve_df["_has_ranges"]].copy()
    cve_with_ver = cve_df[cve_df["_has_ranges"]].copy()

    # 预构建 CVE 索引
    cve_index = _build_cve_index(cve_with_ver)

    # 为无版本号的 CVE 构建索引并加载描述
    cve_no_ver_index: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
    if not cve_no_ver.empty and base_url and api_key and model:
        try:
            conn = sqlite3.connect("vuln_ruler_filtered.db")
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT cve_id, content_preview FROM cve_records").fetchall()
            conn.close()
            desc_map = {r["cve_id"]: (r["content_preview"] or "") for r in rows}
            for _, row in cve_no_ver.iterrows():
                comp_norm = normalize_package_name(str(row["Component"]))
                cve_id = str(row["CVE"])
                desc = desc_map.get(cve_id, "")
                cve_no_ver_index[comp_norm].append((cve_id, desc))
            LOGGER.info("Built no-ver index for %d components (%d CVEs)",
                        len(cve_no_ver_index), len(cve_no_ver))
        except Exception as exc:
            LOGGER.warning("Failed to load CVE descriptions: %s", exc)

    LOGGER.info("CVE records: %d with version (%d groups), %d no-version (LLM, %d groups)",
                len(cve_with_ver), len(cve_index), len(cve_no_ver), len(cve_no_ver_index))

    result_rows: List[Dict] = []

    if workers > 1:
        LOGGER.info("Using %d workers for parallel processing", workers)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    _process_one_dep, row, cve_index, cve_no_ver_index,
                    base_url, api_key, model,
                ): i for i, (_, row) in enumerate(dep_df.iterrows())
            }
            for future in as_completed(futures):
                idx = futures[future]
                try:
                    matched = future.result()
                    result_rows.extend(matched)
                    if matched:
                        m = matched[0]
                        LOGGER.info("[%d/%d] %s @ %s / %s %s: %d CVE hits",
                                    idx + 1, len(dep_df), m["RepoName"], m["Tag"],
                                    m["Component"], m["UsedVersion"], len(matched))
                except Exception as exc:
                    LOGGER.warning("Worker failed for dep row %d: %s", idx, exc)
    else:
        total = len(dep_df)
        for i, (_, dep_row) in enumerate(dep_df.iterrows()):
            matched = _process_one_dep(dep_row, cve_index, cve_no_ver_index,
                                       base_url, api_key, model)
            result_rows.extend(matched)
            repo_name = str(dep_row["RepoName"])
            component = str(dep_row["Component"])
            version = str(dep_row["Version"])
            if matched:
                LOGGER.info("[%d/%d] %s / %s %s: %d CVE hits",
                            i + 1, total, repo_name, component, version, len(matched))

    if result_rows:
        df = pd.DataFrame(result_rows, columns=[
            "RepoName", "Tag", "Component", "UsedVersion", "SourceFile",
            "CVE", "VulnerableVersionRanges", "Determination",
        ])
    else:
        df = pd.DataFrame(columns=[
            "RepoName", "Tag", "Component", "UsedVersion", "SourceFile",
            "CVE", "VulnerableVersionRanges", "Determination",
        ])

    before_dedup = len(df)
    df = df.drop_duplicates(subset=["RepoName", "Tag", "Component", "UsedVersion", "CVE"])
    LOGGER.info("Phase 3 complete: %d total matches (%d duplicates removed)", len(df), before_dedup - len(df))
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
    parser.add_argument("--workers", type=int, default=8,
                        help="并行 worker 数（默认 8）")
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
    result_df = run_phase3(dep_df, cve_df, args.base_url, args.api_key, args.model,
                           workers=args.workers)
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
