#!/usr/bin/env python3
"""
爬取 GitHub Top N Java + Python 开源项目，输出 RepoName、Tag 两列。

用法:
    export GITHUB_TOKEN=ghp_xxx   # 必须，无 token 限速 60 次/小时
    python crawl_top_repos.py                     # 默认 500 Java + 500 Python
    python crawl_top_repos.py --count 100          # 每语言 100 个
    python crawl_top_repos.py --java-only          # 只要 Java

输出格式（兼容 vuln_injector.py）:
    RepoName             Tag
    iluwatar/java-design-patterns   master
    donnemartin/system-design-primer   master
"""

import argparse
import logging
import os
import sys
import time

import pandas as pd
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
LOGGER = logging.getLogger("crawler")

GITHUB_API = "https://api.github.com"
REQUEST_TIMEOUT = 30


def _github_headers() -> dict:
    token = os.environ.get("GITHUB_TOKEN", "") or os.environ.get("GH_TOKEN", "")
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def search_repos(language: str, page: int = 1, per_page: int = 100) -> list:
    """按 star 降序搜索指定语言仓库。"""
    headers = _github_headers()
    query = f"language:{language} stars:>50"
    params = {
        "q": query, "sort": "stars", "order": "desc",
        "per_page": per_page, "page": page,
    }
    resp = requests.get(
        f"{GITHUB_API}/search/repositories",
        headers=headers, params=params, timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code != 200:
        LOGGER.error("Search error %d: %s", resp.status_code, resp.text[:200])
        if resp.status_code == 403:
            LOGGER.warning("Rate limited, sleeping 60s...")
            time.sleep(60)
            return search_repos(language, page, per_page)
        return []
    return resp.json().get("items", [])


def crawl_language(language: str, count: int) -> list:
    """爬取指定语言的 top repos，只返回 RepoName + Tag。"""
    per_page = 100
    max_pages = min(count // per_page + 2, 10)  # GitHub 最多 1000 条

    rows = []
    seen = set()

    LOGGER.info("=== Crawling Top %d %s repos ===", count, language)

    for page in range(1, max_pages + 1):
        items = search_repos(language, page=page, per_page=per_page)
        if not items:
            break

        for item in items:
            full_name = item["full_name"]
            if full_name in seen:
                continue
            seen.add(full_name)

            rows.append({
                "RepoName": full_name,
                "Tag": item.get("default_branch", "main"),
            })

        LOGGER.info("  Page %d: +%d repos (total %d)", page, len(items), len(rows))

        if len(rows) >= count:
            break

        time.sleep(1.0)  # 有 token 5000/h = 83/min，1s 间隔足够

    rows = rows[:count]
    LOGGER.info("%s: %d repos collected", language, len(rows))
    return rows


def main():
    parser = argparse.ArgumentParser(description="爬取 GitHub Top 开源项目")
    parser.add_argument("--count", type=int, default=500, help="每种语言爬取数量（默认 500）")
    parser.add_argument("--output", default="data/github_top_repos.xlsx", help="输出文件")
    parser.add_argument("--java-only", action="store_true", help="只爬 Java")
    parser.add_argument("--python-only", action="store_true", help="只爬 Python")
    args = parser.parse_args()

    if args.java_only:
        langs = ["Java"]
    elif args.python_only:
        langs = ["Python"]
    else:
        langs = ["Java", "Python"]

    all_rows = []
    for lang in langs:
        repos = crawl_language(lang, args.count)
        all_rows.extend(repos)

    if not all_rows:
        LOGGER.error("No repos collected. Set GITHUB_TOKEN environment variable.")
        sys.exit(1)

    df = pd.DataFrame(all_rows)
    df.to_excel(args.output, index=False)
    LOGGER.info("=== Done: %s (%d rows) ===", args.output, len(df))


if __name__ == "__main__":
    main()
