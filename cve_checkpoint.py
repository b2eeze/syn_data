#!/usr/bin/env python3
"""
CVE 结构化 Checkpoint 提取 + 多粒度描述生成

从 CVE content_preview 中提取结构化 checkpoints（单次 LLM 调用），
并支持通过模板渲染生成多粒度描述。

用法:
    # 初始化 DB 表
    python cve_checkpoint.py --init-db

    # 批量提取所有 CVE 的 checkpoints（默认行为）
    python cve_checkpoint.py --workers 10

    # 查看单个 CVE 的完整描述
    python cve_checkpoint.py --cve CVE-2020-14343
"""

import argparse
import json
import logging
import os
import re
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional

import requests
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT = 90
MAX_RETRIES = 3
RETRY_BACKOFF = 5  # 秒，指数退避: 5/10/20
DEFAULT_DB = "vuln_ruler_filtered.db"

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
LOGGER = logging.getLogger("cve_checkpoint")

# ---------------------------------------------------------------------------
# Pydantic 模型 — 定义结构化 Checkpoint 的 schema
# ---------------------------------------------------------------------------


class VersionConstraint(BaseModel):
    ecosystem: str = Field(
        default="",
        description="包管理器/生态系统，如 Maven/PyPI/npm/Go，无法确定则为空字符串",
    )
    introduced: str = Field(
        default="",
        description="受影响的起始版本（含），未知则为空字符串",
    )
    fixed: str = Field(
        default="",
        description="修复版本（不含），即第一个不受影响的版本，未知则为空字符串",
    )


class CheckPoint(BaseModel):
    id: str = Field(description="检查点标识: version_check / export_presence / precondition_check")
    priority: str = Field(description="优先级: critical / high / medium")
    question: str = Field(description="该检查点要回答的问题")
    how_to_check: str = Field(description="具体的检查方法")
    pass_condition: str = Field(description="通过该检查点的条件")


class MatchTerms(BaseModel):
    modules: List[str] = Field(
        default_factory=list,
        description="漏洞直接相关的类名/函数名/API 名称，如 RegExPatternMatcher、full_load",
    )
    config_keys: List[str] = Field(
        default_factory=list,
        description="相关的配置项名称，如 pathMatcher、filterChainDefinitions",
    )
    concepts: List[str] = Field(
        default_factory=list,
        description="核心漏洞概念关键词，用于语义搜索，如 'regex bypass', 'deserialization'",
    )


class CVECheckpoint(BaseModel):
    """CVE 结构化 Checkpoint — LLM 直接输出此 schema"""

    version_constraint: VersionConstraint = Field(
        default_factory=VersionConstraint,
        description="受影响版本范围",
    )
    safe_condition: str = Field(
        default="",
        description="一行中文总结：什么条件下项目不受该漏洞影响",
    )
    preconditions: List[str] = Field(
        default_factory=list,
        description="漏洞利用需要满足的前置条件，每条用中文描述",
    )
    check_points: List[CheckPoint] = Field(
        default_factory=list,
        description="结构化检查点，必须包含 version_check / export_presence / precondition_check 三类",
    )
    match_terms: MatchTerms = Field(
        default_factory=MatchTerms,
        description="用于代码搜索的关键词",
    )


# ---------------------------------------------------------------------------
# LLM Prompt
# ---------------------------------------------------------------------------

EXTRACTION_SYSTEM_PROMPT = (
    "You are a precise CVE security analyst. Extract structured vulnerability "
    "checkpoints from CVE descriptions."
)

EXTRACTION_USER_PROMPT = """请从以下 CVE 描述中提取结构化的漏洞检查点信息。所有字段若无法确定则用空字符串/空数组。**只输出 JSON，不要 markdown 代码围栏。**

**CVE 描述**:
{content_preview}

**输出格式**（字段名不可改）:
{{
  "version_constraint": {{
    "ecosystem": "Maven/PyPI/npm/Go 或空字符串",
    "introduced": "受影响起始版本（含），未知则为空字符串",
    "fixed": "修复版本（不含），未知则为空字符串"
  }},
  "safe_condition": "一行中文：什么条件下项目不受影响",
  "preconditions": ["前置条件1", "前置条件2"],
  "check_points": [
    {{
      "id": "version_check",
      "priority": "critical",
      "question": "版本是否在受影响范围内？",
      "how_to_check": "检查依赖配置中的版本号",
      "pass_condition": "版本 >= fixed 版本则不受影响"
    }},
    {{
      "id": "export_presence",
      "priority": "high",
      "question": "项目中是否存在受影响模块/类/函数？",
      "how_to_check": "搜索 import 或 API 调用",
      "pass_condition": "未使用受影响模块则不受影响"
    }},
    {{
      "id": "precondition_check",
      "priority": "medium",
      "question": "前置条件是否满足？",
      "how_to_check": "检查代码中的前置条件",
      "pass_condition": "任一前置条件不满足则不受影响"
    }}
  ],
  "match_terms": {{
    "modules": ["类名/函数名/API名"],
    "config_keys": ["配置项名"],
    "concepts": ["漏洞概念关键词"]
  }}
}}"""


# ---------------------------------------------------------------------------
# 多粒度描述模板
# ---------------------------------------------------------------------------

def _fmt_version(vc: dict) -> str:
    """格式化版本约束为可读字符串。"""
    if not vc or not vc.get("ecosystem"):
        return "版本范围未知"
    parts = [vc["ecosystem"]]
    if vc.get("introduced"):
        parts.append(f">= {vc['introduced']}")
    if vc.get("fixed"):
        parts.append(f"< {vc['fixed']}")
    else:
        parts.append("(修复版本未知)")
    return " ".join(parts)


def generate_description(checkpoints: dict) -> str:
    """从 checkpoints 结构渲染完整描述。"""
    cve_id = checkpoints.get("cve_id", "Unknown")
    safe_condition = checkpoints.get("safe_condition", "")
    preconditions = checkpoints.get("preconditions", [])
    check_points = checkpoints.get("check_points", [])
    match_terms = checkpoints.get("match_terms", {})
    version_constraint = checkpoints.get("version_constraint", {})

    lines = [f"{cve_id}: {safe_condition}" if safe_condition else cve_id]

    # 版本范围
    vc_text = _fmt_version(version_constraint)
    lines.append(f"受影响版本: {vc_text}")

    # 前置条件
    if preconditions:
        lines.append(f"前提条件: {'; '.join(preconditions)}")

    # 检查要点（按 priority 排序）
    if check_points:
        priority_order = {"critical": 0, "high": 1, "medium": 2}
        sorted_cps = sorted(check_points, key=lambda cp: priority_order.get(cp.get("priority", ""), 99))
        cp_lines = []
        for cp in sorted_cps:
            priority = cp.get("priority", "")
            q = cp.get("question", "")
            pc = cp.get("pass_condition", "")
            if q and pc:
                cp_lines.append(f"  [{priority}] {q} → {pc}")
        if cp_lines:
            lines.append("检查要点:")
            lines.extend(cp_lines)

    # 匹配关键词
    mt_parts = []
    concepts = match_terms.get("concepts", [])
    modules = match_terms.get("modules", [])
    config_keys = match_terms.get("config_keys", [])
    if concepts:
        mt_parts.append(f"漏洞概念: {' | '.join(concepts)}")
    if modules:
        mt_parts.append(f"相关模块: {' | '.join(modules)}")
    if config_keys:
        mt_parts.append(f"配置项: {' | '.join(config_keys)}")
    if mt_parts:
        lines.append("匹配关键词: " + " / ".join(mt_parts))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# DB 操作
# ---------------------------------------------------------------------------

def init_db(db_path: str = DEFAULT_DB) -> None:
    """创建 cve_checkpoints 表（如果不存在）。"""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cve_checkpoints (
            cve_id TEXT PRIMARY KEY,
            checkpoints_json TEXT NOT NULL,
            extracted_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()
    LOGGER.info("cve_checkpoints table ready in %s", db_path)


def load_checkpoints(db_path: str, cve_id: str) -> Optional[dict]:
    """从 DB 加载指定 CVE 的 checkpoints。"""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT checkpoints_json FROM cve_checkpoints WHERE cve_id = ?", (cve_id,)
    ).fetchone()
    conn.close()
    if row:
        return json.loads(row["checkpoints_json"])
    return None


def load_all_checkpoints(db_path: str) -> Dict[str, dict]:
    """从 DB 加载所有 checkpoints，返回 {cve_id: checkpoints_dict}。"""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT cve_id, checkpoints_json FROM cve_checkpoints").fetchall()
    conn.close()
    return {r["cve_id"]: json.loads(r["checkpoints_json"]) for r in rows}


def store_checkpoint(db_path: str, cve_id: str, checkpoints: dict, extracted_at: str) -> None:
    """将 checkpoints 写入 DB（UPSERT）。"""
    conn = sqlite3.connect(db_path)
    conn.execute(
        """INSERT OR REPLACE INTO cve_checkpoints (cve_id, checkpoints_json, extracted_at)
           VALUES (?, ?, ?)""",
        (cve_id, json.dumps(checkpoints, ensure_ascii=False), extracted_at),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# LLM 调用（requests + Pydantic 校验）
# ---------------------------------------------------------------------------

def _call_llm(base_url: str, api_key: str, model: str,
              system_prompt: str, user_prompt: str) -> Optional[str]:
    """调用 OpenAI 兼容 API，带重试，返回原始响应文本。"""
    url = base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0,
    }
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}

    last_error = None
    for attempt in range(MAX_RETRIES):
        response_text = ""
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
            response_text = response.text or ""
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
        except Exception as exc:
            last_error = exc
            if attempt < MAX_RETRIES - 1:
                wait = RETRY_BACKOFF * (2 ** attempt)
                LOGGER.warning("LLM call failed (attempt %d/%d), retrying in %ds: %s",
                              attempt + 1, MAX_RETRIES, wait, exc)
                time.sleep(wait)
            else:
                details = f" response_text={response_text[:300]}" if response_text else ""
                LOGGER.warning("LLM call failed after %d attempts: %s%s", MAX_RETRIES, exc, details)

    return None


def _parse_json_safe(text: str) -> Optional[dict]:
    """安全解析 JSON：先尝试直接解析，失败则清洗控制字符后重试。"""
    stripped = re.sub(r"^```(?:json)?\s*", "", text.strip(), flags=re.IGNORECASE)
    stripped = re.sub(r"\s*```$", "", stripped)

    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    # 清洗非法的控制字符（除了 \n \t \r 在 JSON 中需要转义，这里直接移除未转义的）
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", stripped)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return None


def extract_checkpoints_with_llm(cve_id: str, content_preview: str,
                                 base_url: str, api_key: str, model: str) -> Optional[dict]:
    """调用 LLM 从 content_preview 提取结构化 checkpoints。

    prompt 中内嵌 JSON 格式 → requests 调用 → json.loads → Pydantic 校验。

    Returns:
        dict 含 cve_id + 所有 checkpoint 字段，或 None
    """
    if not (base_url and api_key and model):
        LOGGER.warning("LLM config incomplete, cannot extract checkpoints for %s", cve_id)
        return None

    if not content_preview or not content_preview.strip():
        LOGGER.warning("Empty content_preview for %s", cve_id)
        return None

    prompt = EXTRACTION_USER_PROMPT.format(content_preview=content_preview[:2000])
    content = _call_llm(base_url, api_key, model, EXTRACTION_SYSTEM_PROMPT, prompt)

    if content is None:
        return None

    raw = _parse_json_safe(content)
    if raw is None:
        LOGGER.warning("JSON parse failed for %s", cve_id)
        return None

    # Pydantic 校验
    try:
        checkpoint = CVECheckpoint(**raw)
    except Exception as exc:
        LOGGER.warning("Pydantic validation failed for %s: %s", cve_id, exc)
        return None

    d = checkpoint.model_dump()
    d["cve_id"] = cve_id
    return d


# ---------------------------------------------------------------------------
# 批量提取
# ---------------------------------------------------------------------------

def _extract_one(args: tuple) -> tuple:
    """单个 CVE 提取任务（用于线程池）。返回 (cve_id, checkpoints_dict_or_None, error_msg)。"""
    cve_id, content_preview, base_url, api_key, model, db_path = args
    try:
        checkpoints = extract_checkpoints_with_llm(
            cve_id, content_preview, base_url, api_key, model
        )
        if checkpoints:
            store_checkpoint(db_path, cve_id, checkpoints,
                           datetime.now().isoformat())
            return (cve_id, True, None)
        else:
            return (cve_id, False, "LLM returned None")
    except Exception as exc:
        return (cve_id, False, str(exc))


def batch_extract(db_path: str = DEFAULT_DB,
                  base_url: str = "", api_key: str = "", model: str = "",
                  workers: int = 5) -> None:
    """遍历 cve_records 表，并发调用 LLM 提取 checkpoints 并写入 DB。

    跳过已存在于 cve_checkpoints 表中的 CVE。
    """
    init_db(db_path)

    # 获取 LLM 配置
    base_url = base_url or os.environ.get("LLM_BASE_URL", "")
    api_key = api_key or os.environ.get("LLM_API_KEY", "")
    model = model or os.environ.get("LLM_MODEL", "")

    if not (base_url and api_key and model):
        LOGGER.error("LLM config missing. Set LLM_BASE_URL, LLM_API_KEY, LLM_MODEL env vars or pass via args.")
        sys.exit(1)

    # 读取 cve_records
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cve_rows = conn.execute(
        "SELECT cve_id, content_preview FROM cve_records WHERE content_preview IS NOT NULL AND content_preview != ''"
    ).fetchall()
    conn.close()
    LOGGER.info("Found %d CVE records with content_preview", len(cve_rows))

    # 读取已提取的 CVE
    existing = set()
    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT cve_id FROM cve_checkpoints").fetchall()
    existing = {r[0] for r in rows}
    conn.close()
    LOGGER.info("Already extracted: %d CVE checkpoints", len(existing))

    # 过滤已处理的
    pending = [(r["cve_id"], r["content_preview"]) for r in cve_rows if r["cve_id"] not in existing]
    LOGGER.info("Pending extraction: %d CVEs", len(pending))

    if not pending:
        LOGGER.info("All CVEs already extracted, nothing to do.")
        return

    # 构建任务参数
    tasks = [(cve_id, cp, base_url, api_key, model, db_path) for cve_id, cp in pending]

    success = 0
    failed = 0

    max_workers = min(len(tasks), workers) if workers > 0 else min(len(tasks), 5)
    LOGGER.info("Starting batch extraction with %d workers...", max_workers)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_extract_one, t): t[0] for t in tasks}
        for i, future in enumerate(as_completed(futures), 1):
            cve_id, ok, error = future.result()
            if ok:
                success += 1
            else:
                failed += 1
                if error:
                    LOGGER.debug("  Failed %s: %s", cve_id, error)
            if i % 10 == 0 or i == len(tasks):
                LOGGER.info("  Progress: %d/%d (success=%d, failed=%d)", i, len(tasks), success, failed)

    LOGGER.info("Batch extraction complete: %d success, %d failed", success, failed)


# ---------------------------------------------------------------------------
# 便捷函数：获取描述
# ---------------------------------------------------------------------------

def get_description(db_path: str, cve_id: str,
                    fallback_base_url: str = "", fallback_api_key: str = "",
                    fallback_model: str = "") -> str:
    """获取 CVE 的完整描述。

    先查 cve_checkpoints 表，若有则用模板生成；
    若无则实时调 LLM 提取并缓存，然后用模板生成。
    """
    checkpoints = load_checkpoints(db_path, cve_id)

    if checkpoints is None:
        # 尝试实时提取
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT content_preview FROM cve_records WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        conn.close()

        if not row or not row["content_preview"]:
            return f"{cve_id}: 无 CVE 描述数据"

        base_url = fallback_base_url or os.environ.get("LLM_BASE_URL", "")
        api_key = fallback_api_key or os.environ.get("LLM_API_KEY", "")
        model = fallback_model or os.environ.get("LLM_MODEL", "")

        if not (base_url and api_key and model):
            # 无 LLM 可用，返回原始描述截断
            return f"{cve_id}: {row['content_preview'][:200]}"

        LOGGER.info("Checkpoint not cached for %s, extracting on-the-fly...", cve_id)
        checkpoints = extract_checkpoints_with_llm(
            cve_id, row["content_preview"], base_url, api_key, model
        )
        if checkpoints is None:
            return f"{cve_id}: LLM 提取失败 - {row['content_preview'][:200]}"
        # 缓存
        store_checkpoint(db_path, cve_id, checkpoints, datetime.now().isoformat())

    return generate_description(checkpoints)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CVE 结构化 Checkpoint 提取 + 多粒度描述生成")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite 数据库路径")
    parser.add_argument("--init-db", action="store_true", help="初始化 cve_checkpoints 表")
    parser.add_argument("--cve", type=str, help="查看单个 CVE 的描述（不指定则执行批量提取）")
    parser.add_argument("--base-url", default=os.environ.get("LLM_BASE_URL", ""),
                        help="API base URL")
    parser.add_argument("--api-key", default=os.environ.get("LLM_API_KEY", ""),
                        help="API key")
    parser.add_argument("--model", default=os.environ.get("LLM_MODEL", ""),
                        help="模型名")
    parser.add_argument("--workers", type=int, default=5, help="批量提取并发数（默认 5）")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.init_db:
        init_db(args.db)
        print(f"cve_checkpoints table initialized in {args.db}")
        return

    if args.cve:
        desc = get_description(
            args.db, args.cve,
            fallback_base_url=args.base_url,
            fallback_api_key=args.api_key,
            fallback_model=args.model,
        )
        print(desc)
        return

    # 默认：批量提取
    batch_extract(args.db, args.base_url, args.api_key, args.model, args.workers)


if __name__ == "__main__":
    main()
