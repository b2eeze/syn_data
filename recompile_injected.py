#!/usr/bin/env python3
"""
重新编译已注入的 repo，覆写 Compilable/CompileError 结果。

用法:
    python recompile_injected.py
    python recompile_injected.py --input result/xxx_injected.json
"""

import argparse
import json
import logging
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

from vuln_injector import check_compilability, clone_repo, _ensure_clean_repo

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
LOGGER = logging.getLogger("recompile")

DEFAULT_INPUT = "repos_cache/_vuln_injection_progress_injected.json"
CACHE_DIR = Path("repos_cache")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="重新编译已注入的 repo")
    parser.add_argument("--input", default=DEFAULT_INPUT,
                        help=f"注入结果 JSON（默认 {DEFAULT_INPUT}）")
    parser.add_argument("--cache-dir", default=str(CACHE_DIR),
                        help="仓库克隆缓存目录")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    cache_dir = Path(args.cache_dir)

    if not input_path.exists():
        LOGGER.error("Input file not found: %s", input_path)
        return

    data = json.loads(input_path.read_text(encoding="utf-8"))
    LOGGER.info("Loaded %d injected entries from %s", len(data), input_path)

    # 按 (RepoName, Tag) 分组
    groups: Dict[str, List[dict]] = defaultdict(list)
    for entry in data:
        key = (entry["RepoName"], entry["Tag"])
        groups[key].append(entry)

    updated = 0
    for (repo_name, tag), entries in groups.items():
        LOGGER.info("Processing: %s @ %s (%d entries)", repo_name, tag, len(entries))

        # 1. 克隆
        repo_path = clone_repo(repo_name, tag, cache_dir)
        if (repo_path / "CLONE_FAILED").exists():
            LOGGER.warning("  Clone failed, skip")
            continue

        # 2. 确保干净
        _ensure_clean_repo(repo_path, tag)

        # 3. 收集所有修改文件（去重）
        all_modified: set = set()
        for e in entries:
            mf = e.get("ModifiedFiles", "")
            if mf:
                for f in mf.split(", "):
                    f = f.strip()
                    if f:
                        all_modified.add(f)

        # 4. 应用所有 patch（去重）
        applied_patches: set = set()
        for e in entries:
            patch_file = e.get("PatchFile", "")
            if not patch_file or patch_file in applied_patches:
                continue
            applied_patches.add(patch_file)
            patch_path = Path(patch_file)
            if not patch_path.is_absolute():
                patch_path = Path.cwd() / patch_path
            if not patch_path.exists():
                LOGGER.warning("  Patch not found: %s", patch_path)
                continue
            try:
                proc = subprocess.run(
                    ["git", "apply", str(patch_path)],
                    cwd=str(repo_path), capture_output=True, text=True, timeout=30
                )
                if proc.returncode != 0:
                    LOGGER.warning("  git apply failed for %s: %s", patch_path.name, proc.stderr[:200])
            except Exception as exc:
                LOGGER.warning("  git apply error: %s", exc)

        # 5. 编译
        modified_list = sorted(all_modified)
        if not modified_list:
            LOGGER.warning("  No modified files, skip compile")
            continue

        compilable, compile_error = check_compilability(repo_path, modified_list)
        LOGGER.info("  Compile result: %s", compilable)
        if compile_error:
            LOGGER.info("  Error: %s", compile_error[:500])

        # 6. 覆写结果
        for e in entries:
            e["Compilable"] = compilable
            e["CompileError"] = compile_error
            updated += 1

    # 保存
    input_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    LOGGER.info("Done: %d entries updated, saved to %s", updated, input_path)


if __name__ == "__main__":
    main()
