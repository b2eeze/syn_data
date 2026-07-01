#!/usr/bin/env python3
"""
Phase 2: CVE 版本提取 — 从 vuln_ruler_filtered.db 的 CVE 描述中提取受影响的版本区间

用法:
    python cve_version_extractor.py [--targets-xlsx ...] [--base-url ...] [--api-key ...] [--model ...]

输出格式:
    VulnerableVersionRanges: JSON数组，每个元素为 [lower, upper, inclusive]
    例: [["1.0", "2.5.2", 0]] 表示 1.0 <= ver < 2.5.2 受影响
        [["", "3.0", 1]]      表示 ver <= 3.0 受影响（无下界）
"""

import argparse
import json
import logging
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd
import requests

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT = 60
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD 速率限制：无 API key 5 req/30s，有 API key 50 req/30s
NVD_INTERVAL_NO_KEY = 6.0
NVD_INTERVAL_WITH_KEY = 0.6
NVD_MAX_RETRIES = 3

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
LOGGER = logging.getLogger("cve_version_extractor")


# ===================================================================
# NVD API 客户端
# ===================================================================

_last_nvd_request_time: float = 0.0


def _rate_limit_nvd(api_key: str = ""):
    """确保 NVD API 请求间隔符合速率限制。"""
    global _last_nvd_request_time
    interval = NVD_INTERVAL_WITH_KEY if api_key else NVD_INTERVAL_NO_KEY
    elapsed = time.monotonic() - _last_nvd_request_time
    if elapsed < interval:
        time.sleep(interval - elapsed)
    _last_nvd_request_time = time.monotonic()


def fetch_nvd_json(cve_id: str, cache_dir: str, api_key: str = "") -> Optional[Dict]:
    """调用 NVD API 获取 CVE 原始 JSON，带文件缓存。

    Args:
        cve_id: CVE 编号，如 "CVE-2021-37678"
        cache_dir: 缓存目录路径
        api_key: NVD API key（可选，提升速率限制）

    Returns:
        NVD API 返回的 CVE JSON dict，失败返回 None
    """
    cache_path = Path(cache_dir) / f"{cve_id}.json"

    # 缓存命中
    if cache_path.exists():
        try:
            return json.loads(cache_path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            LOGGER.warning("NVD cache read error for %s: %s", cve_id, exc)

    # 调用 API（带重试）
    params = {"cveId": cve_id}
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    for attempt in range(NVD_MAX_RETRIES):
        _rate_limit_nvd(api_key)
        try:
            resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 404:
                LOGGER.warning("NVD 404 for %s", cve_id)
                return None
            if resp.status_code == 429:
                wait = 30 if not api_key else 6
                LOGGER.warning("NVD 429 for %s (attempt %d/%d), waiting %ds ...",
                               cve_id, attempt + 1, NVD_MAX_RETRIES, wait)
                time.sleep(wait)
                continue
            resp.raise_for_status()
            break  # 成功，跳出重试循环
        except requests.RequestException as exc:
            if attempt < NVD_MAX_RETRIES - 1:
                wait = 5
                LOGGER.warning("NVD request failed for %s (attempt %d/%d): %s, retrying in %ds ...",
                               cve_id, attempt + 1, NVD_MAX_RETRIES, exc, wait)
                time.sleep(wait)
                continue
            LOGGER.warning("NVD API request failed for %s after %d attempts: %s",
                           cve_id, NVD_MAX_RETRIES, exc)
            return None
    else:
        # 429 重试耗尽
        LOGGER.warning("NVD 429 exhausted for %s after %d attempts", cve_id, NVD_MAX_RETRIES)
        return None

    data = resp.json()

    # 写入缓存
    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    try:
        cache_path.write_text(json.dumps(data, ensure_ascii=False, indent=2))
    except OSError as exc:
        LOGGER.warning("NVD cache write error for %s: %s", cve_id, exc)

    return data


def _extract_version_from_cpe(criteria: str) -> str:
    """从 CPE 2.3 criteria 中提取精确版本号。
    cpe:2.3:a:vendor:product:version:... → version 或 ""
    """
    parts = criteria.split(":")
    if len(parts) >= 6 and parts[5] not in ("*", "-", ""):
        return parts[5]
    return ""


def _extract_vendor_product(criteria: str) -> str:
    """从 CPE criteria 提取 vendor:product 标识。
    cpe:2.3:a:vendor:product:... → "vendor:product"
    """
    parts = criteria.split(":")
    if len(parts) >= 5:
        return f"{parts[3]}:{parts[4]}"
    return ""


def _component_matches_vp(component: str, vp: str) -> bool:
    """检查 component 名称是否与 CPE vendor:product 匹配。"""
    if not component or not vp:
        return False
    comp_norm = component.lower().replace(" ", "_").replace("-", "_").lstrip("_")
    vp_parts = vp.lower().split(":")
    if len(vp_parts) != 2:
        return False
    vendor, product = vp_parts
    # 双向包含检查
    return (product in comp_norm or comp_norm in product
            or vendor in comp_norm or comp_norm in vendor)


def extract_ranges_from_nvd(nvd_json: Dict, component: str = "") -> List[List]:
    """从 NVD JSON 的 configurations.cpeMatch 中提取版本区间。

    对每个 vulnerable: true 的 CPE：
      优先取 versionEndIncluding / versionEndExcluding / versionStart*
      若都没有版本区间信息，从 CPE criteria 提取精确版本 → [ver, ver, 1]
      精确版本若 >= 同产品的 versionEndExcluding 上界，则丢弃（已修复版本）
      若指定 component，只保留与该组件匹配的产品的 range

    Returns:
        [[lower, upper, inclusive], ...] 去重后的区间列表
    """
    ranges: List[List] = []
    seen = set()
    vulnerabilities = nvd_json.get("vulnerabilities", [])
    if not vulnerabilities:
        return []

    # 第一遍：收集 range-based CPE 和 exact CPE
    exact_entries: list[tuple[str, str]] = []  # [(version, vendor_product), ...]
    # 按 vendor:product 分组的上界
    upper_bounds_exclusive: dict[str, set[str]] = {}   # vendor_product → {versionEndExcluding}
    upper_bounds_inclusive: dict[str, set[str]] = {}   # vendor_product → {versionEndIncluding}

    for vuln in vulnerabilities:
        cve = vuln.get("cve", {})
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if not cpe_match.get("vulnerable", False):
                        continue
                    vp = _extract_vendor_product(cpe_match.get("criteria", ""))
                    upper = (cpe_match.get("versionEndIncluding")
                             or cpe_match.get("versionEndExcluding")
                             or "")
                    if upper:
                        inclusive = 1 if cpe_match.get("versionEndIncluding") else 0
                        if cpe_match.get("versionStartIncluding"):
                            lower = cpe_match["versionStartIncluding"]
                        elif cpe_match.get("versionStartExcluding"):
                            lower = ""  # 保守：不精确表示
                        else:
                            lower = ""
                        key = (lower, upper, inclusive)
                        if key not in seen:
                            seen.add(key)
                            ranges.append([lower, upper, inclusive])
                            if inclusive:
                                upper_bounds_inclusive.setdefault(vp, set()).add(upper)
                            else:
                                upper_bounds_exclusive.setdefault(vp, set()).add(upper)
                    else:
                        # 无版本区间信息 → 收集精确版本，稍后过滤
                        exact_ver = _extract_version_from_cpe(cpe_match.get("criteria", ""))
                        if exact_ver:
                            exact_entries.append((exact_ver, vp))

    # 第二遍：过滤并添加精确版本
    for exact_ver, vp in exact_entries:
        # 按 component 过滤跨产品范围
        if component and not _component_matches_vp(component, vp):
            continue

        # 过滤非版本号字符串（必须包含数字和点）
        cleaned = normalize_version(exact_ver)
        if not re.search(r'\d+\.\d+', cleaned):
            continue

        parts = parse_version_parts(cleaned)
        if not parts:
            continue

        # 只跟同 vendor:product 的 range 比较
        should_skip = False
        for ub in upper_bounds_exclusive.get(vp, set()):
            ub_parts = parse_version_parts(ub)
            if ub_parts and parts >= ub_parts:
                should_skip = True
                break
        if not should_skip:
            for ub in upper_bounds_inclusive.get(vp, set()):
                ub_parts = parse_version_parts(ub)
                if ub_parts and parts > ub_parts:
                    should_skip = True
                    break

        if should_skip:
            continue

        key = (cleaned, cleaned, 1)
        if key not in seen:
            seen.add(key)
            ranges.append([cleaned, cleaned, 1])

    # 按 component 过滤跨产品 range-based 条目
    if component:
        # 收集所有匹配产品的 range 上界
        matching_upper_bounds: set[str] = set()
        for vp, ubs in upper_bounds_exclusive.items():
            if _component_matches_vp(component, vp):
                matching_upper_bounds.update(ubs)
        for vp, ubs in upper_bounds_inclusive.items():
            if _component_matches_vp(component, vp):
                matching_upper_bounds.update(ubs)
        # 保留：精确版本（第2遍已过滤）或 range 来自匹配产品
        ranges = [r for r in ranges
                  if r[0] == r[1] or not r[1] or r[1] in matching_upper_bounds]

        # 若仅剩精确 CPE（无 proper range），NVD 数据对本品不完整（如
        # CVE-2021-29425 的 apache:commons_io），回退到 regex/LLM 提取
        if ranges and all(r[0] == r[1] for r in ranges):
            return []

    return ranges


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
# CVE 版本区间提取正则
# ===================================================================

VERSION_TEXT_REGEX = re.compile(r"\d+\.\d+(?:\.\d+){0,3}")
EXPLICIT_RANGE_HINTS = ("before", "prior to", "through", "up to", "upto", "starting in version", "from ")

# "starting in version X and before/prior to Y"  → [X, Y, 0]
START_BEFORE_RANGE_REGEX = re.compile(
    r"starting in version\s+(?P<lower>\d+\.\d+(?:\.\d+){0,3})\s+and\s+(?:prior to|before)\s+(?:version\s+)?(?P<upper>\d+\.\d+(?:\.\d+){0,3})",
    re.IGNORECASE,
)
# "from X through Y"  → [X, Y, 1]
GENERIC_BOUNDED_RANGE_REGEX = re.compile(
    r"(?:from\s+)?(?P<lower>\d+\.\d+(?:\.\d+){0,3})\s+through\s+(?P<upper>\d+\.\d+(?:\.\d+){0,3})",
    re.IGNORECASE,
)
# "X.x before Y"  → 下限取 X.0, [X.0, Y, 0]
BRANCH_BEFORE_REGEX = re.compile(
    r"(?P<branch>\d+(?:\.\d+)*)\.x\s+before\s+(?P<upper>\d+\.\d+(?:\.\d+){0,3})",
    re.IGNORECASE,
)
# "before/prior to Y"  → ["", Y, 0]; "through/up to Y"  → ["", Y, 1]
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

def extract_ranges_from_description(description: str) -> Tuple[List[List], str]:
    """从 CVE 描述中用正则提取受影响的版本区间列表（NVD 的 fallback）。

    每个区间为 [lower, upper, inclusive]:
      - lower: 受影响起始版本（含），无下界则为 ""
      - upper: 修复版本/最后受影响版本
      - inclusive: 1=上界包含(<=), 0=上界不包含(<)

    返回 (ranges, extraction_method)
    extraction_method: 'regex' | 'none'
    """
    desc = (description or "").lower()
    if not desc:
        return [], "none"

    ranges: List[List] = []
    seen = set()  # 去重
    captured_uppers = set()  # 已被精准模式捕获的 upper，避免通用正则重复

    def _add(lower: str, upper: str, inclusive: int, mark_upper: bool = False):
        key = (lower, upper, inclusive)
        if key not in seen and upper:
            seen.add(key)
            ranges.append([lower, upper, inclusive])
        if mark_upper and upper:
            captured_uppers.add(upper)

    # 1. "starting in version X and before Y"  → [X, Y, 0]
    for m in START_BEFORE_RANGE_REGEX.finditer(desc):
        _add(normalize_version(m.group("lower")), normalize_version(m.group("upper")), 0, mark_upper=True)

    # 2. "from X through Y"  → [X, Y, 1]
    for m in GENERIC_BOUNDED_RANGE_REGEX.finditer(desc):
        _add(normalize_version(m.group("lower")), normalize_version(m.group("upper")), 1, mark_upper=True)

    # 3. "X.x before Y"  → [X.0, Y, 0]
    for m in BRANCH_BEFORE_REGEX.finditer(desc):
        lower = m.group("branch") + ".0"
        _add(normalize_version(lower), normalize_version(m.group("upper")), 0, mark_upper=True)

    # 4. "before/prior to/through/up to Y"  → 无下界（跳过已被精准模式覆盖的 upper）
    for m in GENERIC_UPPER_BOUND_REGEX.finditer(desc):
        upper = normalize_version(m.group("upper"))
        if upper in captured_uppers:
            continue
        mode = m.group("mode").lower()
        inclusive = 1 if mode in {"through", "up to", "upto"} else 0
        _add("", upper, inclusive)

    if ranges:
        return ranges, "regex"

    # 5. 兜底：有范围提示词但正则全没匹配到 → 提取所有版本号，取最大的作为上界
    if any(hint in desc for hint in EXPLICIT_RANGE_HINTS):
        mentioned = [normalize_version(v) for v in VERSION_TEXT_REGEX.findall(desc)]
        mentioned = [v for v in mentioned if v]
        if len(mentioned) >= 1:
            highest = max(mentioned, key=lambda v: parse_version_parts(v) or ())
            _add("", highest, 1)

    if ranges:
        return ranges, "regex"

    return [], "none"


def call_llm_extract_ranges(base_url: str, api_key: str, model: str,
                            component: str, cve_id: str, description: str) -> Optional[List[List]]:
    """使用 LLM 从 CVE 描述中提取受影响的版本区间。"""
    url = base_url.rstrip("/") + "/chat/completions"
    prompt = (
        f"请从以下 CVE 描述中提取受影响的版本区间。\n"
        f"返回一个 JSON 数组，每个元素为 [lower, upper, inclusive]。\n"
        f"- lower: 受影响起始版本（含），无下界则为空字符串\n"
        f"- upper: 修复版本或最后受影响版本\n"
        f"- inclusive: 1=上界包含(<=), 0=上界不包含(<)\n"
        f"例: [[\"1.0\", \"2.5.2\", 0]] 表示 >=1.0 且 <2.5.2 受影响\n"
        f"例: [[\"\", \"3.0\", 1]]     表示 <=3.0 受影响\n"
        f"无法确定返回空数组 []。只返回 JSON，不要其他内容。\n\n"
        f"组件: {component}\n"
        f"CVE: {cve_id}\n"
        f"描述: {description[:2000]}\n"
    )
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a precise CVE version extractor. Reply JSON only."},
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
        content = re.sub(r"^```(?:json)?\s*", "", content, flags=re.IGNORECASE)
        content = re.sub(r"\s*```$", "", content)
        parsed = json.loads(content)
        if isinstance(parsed, list) and all(isinstance(r, list) and len(r) == 3 for r in parsed):
            return parsed
        return None
    except Exception as exc:
        LOGGER.warning("LLM range extraction failed for %s: %s", cve_id, exc)
        return None


def run(cve_records: List[Dict], base_url: str, api_key: str,
        model: str, nvd_cache_dir: str = "", nvd_api_key: str = "") -> pd.DataFrame:
    """主入口：提取版本区间。优先 NVD API → 正则 fallback → LLM 兜底。"""
    rows: List[Dict] = []
    seen_keys = set()
    nvd_count = 0
    regex_count = 0
    llm_count = 0
    none_count = 0

    for record in cve_records:
        cve_id = record["cve_id"]
        component_name = record["component_name"]
        content_preview = record.get("content_preview") or ""

        dedup_key = (cve_id, component_name.lower())
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        idx = len(seen_keys)
        ranges: List[List] = []
        method = "none"

        # 1. 优先尝试 NVD API
        if nvd_cache_dir:
            nvd_json = fetch_nvd_json(cve_id, nvd_cache_dir, nvd_api_key)
            if nvd_json:
                ranges = extract_ranges_from_nvd(nvd_json, component_name)
                if ranges:
                    method = "nvd"
                    LOGGER.info("[%d] NVD hit: %s / %s -> %d ranges", idx, component_name, cve_id, len(ranges))

        # 2. NVD 无结果 → 正则 fallback
        if not ranges:
            ranges, method = extract_ranges_from_description(content_preview)

        # 3. 正则也无结果 → LLM 兜底
        if not ranges and base_url and api_key and model:
            LOGGER.info("[%d] LLM extracting %s / %s ...", idx, component_name, cve_id)
            llm_ranges = call_llm_extract_ranges(base_url, api_key, model,
                                                 component_name, cve_id, content_preview)
            if llm_ranges:
                ranges = llm_ranges
                method = "llm"
                LOGGER.info("[%d] LLM hit: %d ranges", idx, len(llm_ranges))
            else:
                LOGGER.info("[%d] LLM miss", idx)
        elif not ranges:
            LOGGER.info("[%d] No ranges found: %s / %s", idx, component_name, cve_id)

        if method == "nvd":
            nvd_count += 1
        elif method == "regex":
            regex_count += 1
        elif method == "llm":
            llm_count += 1
        else:
            none_count += 1

        rows.append({
            "CVE": cve_id,
            "Component": component_name,
            "VulnerableVersionRanges": json.dumps(ranges) if ranges else "",
            "ExtractionMethod": method,
        })

    LOGGER.info("Done: unique=%d, nvd=%d, regex=%d, llm=%d, none=%d",
                len(rows), nvd_count, regex_count, llm_count, none_count)
    df = pd.DataFrame(rows, columns=["CVE", "Component", "VulnerableVersionRanges", "ExtractionMethod"])
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
    parser.add_argument("--nvd-cache-dir", default="workflow_cache/nvd",
                        help="NVD API JSON 缓存目录（默认 workflow_cache/nvd）")
    parser.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY", ""),
                        help="NVD API key（也可用 NVD_API_KEY 环境变量，可选）")
    parser.add_argument("--no-nvd", action="store_true",
                        help="禁用 NVD API，仅用正则+LLM")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    cve_records = load_cve_records(args.vuln_db, args.targets_xlsx)
    LOGGER.info("Loaded %d CVE records", len(cve_records))

    nvd_cache_dir = "" if args.no_nvd else args.nvd_cache_dir

    LOGGER.info("==== Phase 2: CVE Version Extraction ====")
    cve_df = run(cve_records, args.base_url, args.api_key, args.model,
                 nvd_cache_dir=nvd_cache_dir, nvd_api_key=args.nvd_api_key)
    cve_df.to_excel(args.output, index=False)
    LOGGER.info("Output written to %s (%d rows)", args.output, len(cve_df))


if __name__ == "__main__":
    main()
