#!/usr/bin/env python3
"""查看 vuln_ruler.db 数据库内容的工具脚本。"""

import sqlite3
import sys
import pandas as pd
from collections import defaultdict

DB_PATH = "/data1/czc/projects/huawei/syn_data/vuln_ruler.db"


def query(sql, params=()):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(sql, params)
    rows = cur.fetchall()
    conn.close()
    return rows


def overview():
    """打印数据库概览"""
    print("=" * 60)
    print("  vuln_ruler.db 概览")
    print("=" * 60)
    for table in ("targets", "cve_records", "security_advisories"):
        count = query(f"SELECT COUNT(*) AS cnt FROM {table}")[0]["cnt"]
        print(f"  {table:<25s}  {count} 行")
    print()


def list_targets():
    """列出所有监控目标"""
    rows = query(
        "SELECT id, name, language, github_owner, github_repo, osv_package FROM targets ORDER BY id"
    )
    print(f"{'ID':<4} {'Name':<30} {'Lang':<12} {'GitHub':<30} {'OSV Package'}")
    print("-" * 100)
    for r in rows:
        github = f"{r['github_owner']}/{r['github_repo']}" if r["github_owner"] else ""
        print(
            f"{r['id']:<4} {r['name']:<30} {(r['language'] or ''):<12} {github:<30} {r['osv_package'] or ''}"
        )


def target_detail(target_id: int):
    """查看单个target详情"""
    t = query("SELECT * FROM targets WHERE id = ?", (target_id,))
    if not t:
        print(f"Target ID={target_id} 不存在")
        return
    t = t[0]
    print("=" * 60)
    print(f"  Target #{t['id']}: {t['name']}")
    print("=" * 60)
    for key in t.keys():
        if t[key]:
            print(f"  {key:<18}: {t[key]}")

    cve_count = query(
        "SELECT COUNT(*) AS cnt FROM cve_records WHERE target_id = ?", (target_id,)
    )[0]["cnt"]
    adv_count = query(
        "SELECT COUNT(*) AS cnt FROM security_advisories WHERE target_id = ?",
        (target_id,),
    )[0]["cnt"]
    print(f"\n  关联 CVE: {cve_count}  安全公告: {adv_count}")


def list_cves(target_id: int = None, limit: int = 50):
    """列出 CVE 记录"""
    if target_id:
        rows = query(
            "SELECT id, cve_id, title, product_tags FROM cve_records WHERE target_id = ? ORDER BY id DESC LIMIT ?",
            (target_id, limit),
        )
    else:
        rows = query(
            "SELECT id, cve_id, title, product_tags FROM cve_records ORDER BY id DESC LIMIT ?",
            (limit,),
        )
    print(f"{'ID':<6} {'CVE ID':<18} {'Product Tags':<30} {'Title'}")
    print("-" * 100)
    for r in rows:
        print(f"{r['id']:<6} {r['cve_id']:<18} {(r['product_tags'] or '')[:28]:<30} {(r['title'] or '')[:50]}")


def cve_detail(cve_id: str):
    """查看单个 CVE 详情"""
    row = query(
        "SELECT c.*, t.name AS target_name FROM cve_records c JOIN targets t ON c.target_id = t.id WHERE c.cve_id = ?",
        (cve_id,),
    )
    if not row:
        print(f"CVE {cve_id} 不存在")
        return
    r = row[0]
    print("=" * 60)
    print(f"  {r['cve_id']}")
    print("=" * 60)
    fields = [
        "id",
        "target_name",
        "source",
        "title",
        "trickest_path",
        "poc_urls",
        "product_tags",
        "matched_keywords",
        "content_preview",
        "fetched_at",
    ]
    for key in fields:
        val = r[key]
        if val:
            if len(str(val)) > 200:
                val = str(val)[:200] + "..."
            print(f"  {key:<18}: {val}")


def search_cves(keyword: str, limit: int = 50):
    """按关键词搜索 CVE"""
    kw = f"%{keyword}%"
    rows = query(
        "SELECT id, cve_id, title, matched_keywords FROM cve_records WHERE title LIKE ? OR matched_keywords LIKE ? OR cve_id LIKE ? ORDER BY id DESC LIMIT ?",
        (kw, kw, kw, limit),
    )
    print(f"搜索 '{keyword}' 结果 ({len(rows)} 条):")
    print(f"{'ID':<6} {'CVE ID':<18} {'Matched Keywords':<30} {'Title'}")
    print("-" * 100)
    for r in rows:
        print(f"{r['id']:<6} {r['cve_id']:<18} {(r['matched_keywords'] or '')[:28]:<30} {(r['title'] or '')[:50]}")


def list_advisories(target_id: int = None, limit: int = 50):
    """列出安全公告"""
    if target_id:
        rows = query(
            "SELECT id, advisory_id, source, title, severity FROM security_advisories WHERE target_id = ? ORDER BY id DESC LIMIT ?",
            (target_id, limit),
        )
    else:
        rows = query(
            "SELECT id, advisory_id, source, title, severity FROM security_advisories ORDER BY id DESC LIMIT ?",
            (limit,),
        )
    print(f"{'ID':<6} {'Advisory ID':<25} {'Source':<12} {'Severity':<10} {'Title'}")
    print("-" * 110)
    for r in rows:
        print(
            f"{r['id']:<6} {(r['advisory_id'] or '')[:23]:<25} {r['source']:<12} {(r['severity'] or ''):<10} {(r['title'] or '')[:55]}"
        )


def severity_stats():
    """统计信息"""
    # CVE 按产品标签统计
    rows = query(
        "SELECT product_tags, COUNT(*) AS cnt FROM cve_records WHERE product_tags IS NOT NULL AND product_tags != '' GROUP BY product_tags ORDER BY cnt DESC LIMIT 20"
    )
    print("CVE 产品标签分布 (Top 20):")
    for r in rows:
        print(f"  {(r['product_tags'] or 'N/A'):<40} {r['cnt']}")

    # 安全公告按严重程度统计
    rows2 = query(
        "SELECT severity, COUNT(*) AS cnt FROM security_advisories GROUP BY severity ORDER BY cnt DESC"
    )
    print("\n安全公告严重程度分布:")
    for r in rows2:
        print(f"  {(r['severity'] or 'N/A'):<12} {r['cnt']}")

    # CVE 按匹配关键词统计
    rows3 = query(
        "SELECT matched_keywords, COUNT(*) AS cnt FROM cve_records WHERE matched_keywords IS NOT NULL AND matched_keywords != '' GROUP BY matched_keywords ORDER BY cnt DESC LIMIT 20"
    )
    print("\nCVE 匹配关键词分布 (Top 20):")
    for r in rows3:
        print(f"  {(r['matched_keywords'] or 'N/A'):<40} {r['cnt']}")


def source_stats():
    """按数据源统计"""
    rows = query(
        "SELECT source, COUNT(*) AS cnt FROM cve_records GROUP BY source ORDER BY cnt DESC"
    )
    print("CVE 数据源分布:")
    for r in rows:
        print(f"  {r['source']:<20} {r['cnt']}")

    rows2 = query(
        "SELECT source, COUNT(*) AS cnt FROM security_advisories GROUP BY source ORDER BY cnt DESC"
    )
    print("\n安全公告数据源分布:")
    for r in rows2:
        print(f"  {r['source']:<20} {r['cnt']}")


def export_excel(output_path: str = None):
    """将数据库所有表导出为一个 Excel 文件（每个表一个 sheet）"""
    if output_path is None:
        output_path = "data/vuln_ruler.xlsx"
    conn = sqlite3.connect(DB_PATH)
    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        for table in ("targets", "cve_records", "security_advisories"):
            df = pd.read_sql_query(f"SELECT * FROM {table}", conn)
            df.to_excel(writer, sheet_name=table, index=False)
            print(f"  已导出 {table}: {len(df)} 行")
    conn.close()
    print(f"\nExcel 文件已保存到: {output_path}")


def help_text():
    print(
        """
用法: python view_vuln_db.py <命令> [参数]

命令:
  overview          数据库概览（表、行数）
  targets           列出所有监控目标
  target <id>       查看某个target的详情
  cves [target_id]  列出 CVE 记录（可指定 target_id）
  cve <cve_id>      查看某个 CVE 的详情（如 CVE-2024-1234）
  search <kw>       按关键词搜索 CVE
  advisories [tid]  列出安全公告
  stats             严重程度和数据源统计
  export [path]     导出为 Excel 文件（默认 vuln_ruler.xlsx）
  help              显示此帮助
"""
    )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        overview()
        list_targets()
        print("\n使用 'python view_vuln_db.py help' 查看更多命令")
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd == "overview":
        overview()
    elif cmd == "targets":
        list_targets()
    elif cmd == "target" and len(sys.argv) >= 3:
        target_detail(int(sys.argv[2]))
    elif cmd == "cves":
        tid = int(sys.argv[2]) if len(sys.argv) >= 3 else None
        list_cves(tid)
    elif cmd == "cve" and len(sys.argv) >= 3:
        cve_detail(sys.argv[2])
    elif cmd == "search" and len(sys.argv) >= 3:
        search_cves(sys.argv[2])
    elif cmd == "advisories":
        tid = int(sys.argv[2]) if len(sys.argv) >= 3 else None
        list_advisories(tid)
    elif cmd == "stats":
        severity_stats()
        source_stats()
    elif cmd == "export":
        path = sys.argv[2] if len(sys.argv) >= 3 else None
        export_excel(path)
    elif cmd == "help":
        help_text()
    else:
        help_text()
