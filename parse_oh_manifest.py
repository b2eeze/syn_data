"""解析 OpenHarmony manifest XML，提取所有仓库信息，导出 Excel。"""
import xml.etree.ElementTree as ET
import os
from pathlib import Path

MANIFEST_DIR = "/tmp/openharmony_manifest"
OUTPUT = "data/openharmony_repos.xlsx"


def parse_manifest(xml_path: str, remotes: dict, default_remote: str,
                   default_revision: str, projects: list):
    """递归解析 manifest XML，收集所有 <project> 信息。"""
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # 更新 remote 映射
    for remote in root.findall('remote'):
        remotes[remote.get('name')] = remote.get('fetch')

    # 更新默认值
    default_elem = root.find('default')
    if default_elem is not None:
        if default_elem.get('remote'):
            default_remote = default_elem.get('remote')
        if default_elem.get('revision'):
            default_revision = default_elem.get('revision')

    # 提取所有 project
    for proj in root.findall('project'):
        name = proj.get('name')
        remote_name = proj.get('remote', default_remote)
        revision = proj.get('revision', default_revision)
        fetch_base = remotes.get(remote_name, '')
        # 构造完整 git URL
        if name.startswith("https://") or name.startswith("git@"):
            repo_url = name
        else:
            repo_url = f"{fetch_base}/{name}"

        projects.append({
            "name": name,
            "git_url": repo_url,
            "local_path": proj.get('path', name),
            "groups": proj.get('groups', ''),
            "revision": revision,
            "remote": remote_name,
            "upstream": proj.get('upstream', ''),
        })

    # 递归处理 include
    base_dir = os.path.dirname(xml_path)
    for inc in root.findall('include'):
        inc_path = os.path.join(base_dir, inc.get('name'))
        if os.path.exists(inc_path):
            parse_manifest(inc_path, remotes, default_remote, default_revision, projects)


def main():
    projects = []
    parse_manifest(
        os.path.join(MANIFEST_DIR, "default.xml"),
        remotes={},
        default_remote="gitcode",
        default_revision="master",
        projects=projects,
    )

    print(f"共找到 {len(projects)} 个仓库")

    # 统计各分组数量
    from collections import Counter
    group_counts = Counter()
    for p in projects:
        for g in p['groups'].split(','):
            g = g.strip()
            if g:
                group_counts[g] += 1
    print("\n分组统计:")
    for g, c in group_counts.most_common():
        print(f"  {g}: {c}")

    # 统计各 remote 数量
    remote_counts = Counter(p['remote'] for p in projects)
    print("\nRemote 统计:")
    for r, c in remote_counts.most_common():
        print(f"  {r}: {c}")

    # 导出 Excel
    try:
        import openpyxl
    except ImportError:
        os.system("pip install openpyxl -q")
        import openpyxl

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "OpenHarmony Repos"

    # 表头
    headers = ["序号", "仓库名", "Git Clone URL", "平台 URL", "本地路径", "分支", "分组", "Remote"]
    ws.append(headers)

    for i, p in enumerate(projects, 1):
        name = p['name']
        git_clone_url = f"https://gitcode.com/openharmony/{name}.git"
        platform_url = f"https://gitcode.com/openharmony/{name}"

        ws.append([
            i,
            name,
            git_clone_url,
            platform_url,
            p['local_path'],
            p['revision'],
            p['groups'],
            p['remote'],
        ])

    # 调整列宽
    ws.column_dimensions['A'].width = 8
    ws.column_dimensions['B'].width = 45
    ws.column_dimensions['C'].width = 60
    ws.column_dimensions['D'].width = 55
    ws.column_dimensions['E'].width = 50
    ws.column_dimensions['F'].width = 12
    ws.column_dimensions['G'].width = 40
    ws.column_dimensions['H'].width = 12

    # 冻结首行
    ws.freeze_panes = 'A2'

    # 添加筛选
    ws.auto_filter.ref = f"A1:H{len(projects) + 1}"

    wb.save(OUTPUT)
    print(f"\n已导出到: {OUTPUT}")


if __name__ == "__main__":
    main()
