#!/usr/bin/env python3
"""离线修复 dep_scan_result.xlsx 中的占位符版本号。

读取缓存文件重新解析属性，将 ${xxx} / $xxx 占位符替换为实际版本。
不需要 GitHub API，只用本地缓存。
"""

import argparse
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import pandas as pd

from dep_analyzer import (
    DEFAULT_CACHE_DIR,
    get_raw_cache_path,
    parse_maven_properties,
    parse_gradle_properties,
    parse_gradle_ext_properties,
    parse_pom_dependencies,
    parse_gradle_dependencies,
    sanitize_filename,
    normalize_version,
    _JAVA_MAVEN_MAP,
    match_java_component,
)

WORKSPACE = Path(__file__).resolve().parent


def load_targets(targets_xlsx: str) -> Dict:
    from dep_analyzer import load_targets_from_xlsx
    return load_targets_from_xlsx(targets_xlsx)


def find_cache_dir(owner: str, repo: str, tag: str, cache_base: Path) -> Optional[Path]:
    """找到缓存目录。"""
    safe_owner = sanitize_filename(owner)
    safe_repo = sanitize_filename(repo)
    safe_tag = sanitize_filename(tag)
    cache_dir = cache_base / safe_owner / safe_repo / safe_tag
    if cache_dir.exists():
        return cache_dir
    return None


def resolve_all_placeholders_pom(versions: Dict[str, str],
                                 collected_properties: Dict[str, str]) -> Dict[str, str]:
    """对 POM 提取的版本号做多轮属性解析。"""
    resolved: Dict[str, str] = {}
    for component, ver in versions.items():
        if ver.startswith("${"):
            seen = set()
            current = ver
            while current.startswith("${") and current not in seen:
                seen.add(current)
                if current in collected_properties:
                    current = collected_properties[current]
                else:
                    break
            if not current.startswith("${"):
                resolved[component] = normalize_version(current)
            # 无法解析的保持原样（不加入 resolved）
        else:
            resolved[component] = ver
    return resolved


def resolve_all_placeholders_gradle(versions: Dict[str, str],
                                    properties: Dict[str, str]) -> Dict[str, str]:
    """对 Gradle 提取的版本号做多轮属性解析。"""
    from dep_analyzer import resolve_gradle_placeholders
    resolved: Dict[str, str] = {}
    for component, ver in versions.items():
        result = resolve_gradle_placeholders(ver, properties)
        if result and result != ver:
            resolved[component] = normalize_version(result)
        elif re.search(r'\$[\{A-Za-z]', ver):
            # 占位符无法解析，跳过
            pass
        else:
            resolved[component] = ver
    return resolved


def build_full_properties(owner: str, repo: str, tag: str,
                          java_targets: Dict, cache_base: Path) -> Dict[str, str]:
    """收集仓库 tag 下所有属性定义（完整版，比 dep_analyzer 原版更全面）。"""
    properties: Dict[str, str] = {}
    cache_dir = find_cache_dir(owner, repo, tag, cache_base)
    if not cache_dir:
        return properties

    for fpath in cache_dir.rglob("*"):
        if not fpath.is_file():
            continue
        fname = fpath.name.lower()
        try:
            content = fpath.read_text(encoding="utf-8")
        except Exception:
            continue

        if fname == "pom.xml" or fname.endswith(".pom"):
            properties.update(parse_maven_properties(content))
        elif fname == "gradle.properties":
            properties.update(parse_gradle_properties(content))
        elif fname in ("build.gradle", "build.gradle.kts"):
            properties.update(parse_gradle_properties(content))
            properties.update(parse_gradle_ext_properties(content))

    return properties


def fix_placeholders(dep_df: pd.DataFrame, targets_xlsx: str,
                     cache_base: Path) -> pd.DataFrame:
    """离线修复占位符。"""
    comp_lookup = load_targets(targets_xlsx)
    java_targets = comp_lookup["java_targets"]

    # 按 (RepoName, Tag) 分组
    groups: Dict[Tuple[str, str], pd.DataFrame] = {}
    for key, group_df in dep_df.groupby(["RepoName", "Tag"]):
        groups[(str(key[0]), str(key[1]))] = group_df

    fixed_rows: List[Dict] = []
    placeholder_rows_fixed = 0
    placeholder_rows_unfixable = 0

    for (repo_name, tag_name), group_df in groups.items():
        if "/" not in repo_name:
            # 无法解析 owner/repo，保留原数据
            for _, row in group_df.iterrows():
                fixed_rows.append(row.to_dict())
            continue

        owner, repo = repo_name.split("/", 1)
        properties = build_full_properties(owner, repo, tag_name, java_targets, cache_base)

        for _, row in group_df.iterrows():
            ver = str(row["Version"])
            component = str(row["Component"])
            source_file = str(row.get("SourceFile", ""))

            # 检查是否是占位符
            is_ph = bool(re.search(r'[\$@]\{', ver)) \
                or (ver.startswith("$") and bool(re.match(r'\$[A-Za-z_]', ver)))

            if not is_ph:
                fixed_rows.append(row.to_dict())
                continue

            # 尝试解析
            resolved = None

            # Maven 占位符 ${xxx}
            if ver.startswith("${"):
                seen = set()
                current = ver
                while current.startswith("${") and current not in seen:
                    seen.add(current)
                    if current in properties:
                        current = properties[current]
                    else:
                        break
                if not current.startswith("${") and re.search(r'\d', current):
                    resolved = normalize_version(current)
            elif ver.startswith("$") and re.match(r'\$[A-Za-z_]', ver):
                # Gradle $variable
                key = ver.lstrip("$")
                if key in properties:
                    resolved = normalize_version(properties[key])

            # @project.version@ 风格
            if resolved is None and ver.startswith("@") and ver.endswith("@"):
                key = ver.strip("@")
                if key in properties:
                    resolved = normalize_version(properties[key])

            if resolved:
                new_row = row.to_dict()
                new_row["Version"] = resolved
                fixed_rows.append(new_row)
                placeholder_rows_fixed += 1
                print(f"  FIXED: {repo_name}@{tag_name} / {component}: {ver} -> {resolved}")
            else:
                fixed_rows.append(row.to_dict())
                placeholder_rows_unfixable += 1
                print(f"  SKIP:  {repo_name}@{tag_name} / {component}: {ver} (unable to resolve)")

    print(f"\nResults: {placeholder_rows_fixed} fixed, {placeholder_rows_unfixable} unable to resolve")

    result_df = pd.DataFrame(fixed_rows, columns=dep_df.columns.tolist())
    return result_df


def main():
    parser = argparse.ArgumentParser(description="离线修复 dep_scan_result.xlsx 占位符")
    parser.add_argument("--input", default="data/dep_scan_result.xlsx")
    parser.add_argument("--output", default="data/dep_scan_result.xlsx")
    parser.add_argument("--targets-xlsx", default="data/uncovered_library_cves.xlsx")
    parser.add_argument("--cache-dir", default=str(DEFAULT_CACHE_DIR))
    parser.add_argument("--dry-run", action="store_true", help="只检查不写文件")
    args = parser.parse_args()

    dep_df = pd.read_excel(args.input)
    print(f"Loaded {len(dep_df)} rows from {args.input}")

    # 统计占位符
    def is_placeholder(v: str) -> bool:
        s = str(v)
        return bool(re.search(r'[\$@]\{', s)) \
            or (s.startswith("$") and bool(re.match(r'\$[A-Za-z_]', s)))
    placeholder_mask = dep_df["Version"].apply(is_placeholder)
    placeholder_count = placeholder_mask.sum()
    print(f"Rows with placeholders: {placeholder_count}")
    if placeholder_count > 0:
        print("Examples:")
        for v in dep_df[placeholder_mask]["Version"].drop_duplicates().head(10):
            print(f"  {v}")

    result_df = fix_placeholders(dep_df, args.targets_xlsx, Path(args.cache_dir))

    if not args.dry_run:
        result_df.to_excel(args.output, index=False)
        print(f"Written to {args.output} ({len(result_df)} rows)")
    else:
        print(f"Dry-run: would write {len(result_df)} rows to {args.output}")


if __name__ == "__main__":
    main()
