#!/usr/bin/env python3
"""
Phase 1: 依赖提取 — 从 GitHub 仓库中扫描依赖文件，提取目标组件版本

用法:
    python dep_analyzer.py --github-token ghp_xxx [--top-tags 3] [--repo-limit 5]
"""

import argparse
import json
import logging
import os
import re

import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Sequence, Tuple

import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# 配置常量
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT = 60
RAW_BASE = "https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
TAGS_API = "https://api.github.com/repos/{owner}/{repo}/tags"
TREE_API = "https://api.github.com/repos/{owner}/{repo}/git/trees/{ref}?recursive=1"
HEADERS = {
    "Accept": "application/vnd.github+json, text/plain",
    "User-Agent": "dep-analyzer",
}
MAVEN_NAMESPACE = "http://maven.apache.org/POM/4.0.0"
SLEEP_BETWEEN_REQUESTS = 0.2
RETRY_STATUS_CODES = [429, 500, 502, 503, 504]
BACKOFF_FACTOR = 1
RETRY_TOTAL = 5

WORKSPACE_DIR = Path(__file__).resolve().parent
DEFAULT_CACHE_DIR = WORKSPACE_DIR / "workflow_cache"
DEFAULT_CACHE_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
LOGGER = logging.getLogger("dep_analyzer")

# ---------------------------------------------------------------------------
# HTTP Session
# ---------------------------------------------------------------------------
SESSION = requests.Session()
SESSION.mount(
    "https://",
    HTTPAdapter(
        max_retries=Retry(
            total=RETRY_TOTAL,
            backoff_factor=BACKOFF_FACTOR,
            status_forcelist=RETRY_STATUS_CODES,
            allowed_methods=frozenset(["GET"]),
        )
    ),
)


# ===================================================================
# 正则表达式（从 workflow_unified.py 复用）
# ===================================================================

REQ_LINE_REGEXES = [
    re.compile(r"^(?P<pkg>[A-Za-z0-9_.\-]+)(?:\[.*\])?\s*(?P<op>==|>=|<=|~=|>|<)\s*(?P<ver>[A-Za-z0-9_.\-+]+)"),
]

TOML_DEP_SECTION_REGEXES = [
    re.compile(r'^\s*([A-Za-z0-9_.\-]+)\s*=\s*"(?P<spec>[^"]+)"'),
    re.compile(r'^\s*([A-Za-z0-9_.\-]+)\s*=\s*\{[^}]*version\s*=\s*"(?P<spec>[^"]+)"[^}]*\}'),
]

GRADLE_DEP_REGEX = re.compile(
    r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|classpath)?\s*[\(\s\"]*([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-$\{\}]+)"
)

SETUP_PY_REGEX = re.compile(
    r"([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?\s*(?:==|>=|<=|~=|>|<)\s*([A-Za-z0-9_.\-+]+)"
)

PIPFILE_REGEX = re.compile(
    r'^\s*"?([A-Za-z0-9_.\-]+)"?\s*=\s*(?:\{[^}]*version\s*=\s*"([^"]+)"[^}]*\}|"([^"]+)")'
)

POETRY_LOCK_NAME_REGEX = re.compile(r'^name\s*=\s*"([^"]+)"\s*$')
POETRY_LOCK_VERSION_REGEX = re.compile(r'^version\s*=\s*"([^"]+)"\s*$')
PDM_LOCK_NAME_REGEX = re.compile(r'^name\s*=\s*"([^"]+)"\s*$')
PDM_LOCK_VERSION_REGEX = re.compile(r'^version\s*=\s*"([^"]+)"\s*$')

MAVEN_COORD_REGEX = re.compile(
    r"<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>",
    re.DOTALL,
)

ANT_IVY_REGEX = re.compile(
    r'(?:org|group)\s*=\s*"([^"]+)"[^\n>]*(?:name)\s*=\s*"([^"]+)"[^\n>]*(?:rev|version)\s*=\s*"([^"]+)"',
    re.IGNORECASE,
)

# 依赖候选文件 patterns
PYTHON_FILE_PATTERNS = (
    "requirements", "pyproject.toml", "setup.py", "setup.cfg",
    "environment.yml", "environment.yaml", "pdm.lock", "poetry.lock",
    "Pipfile", "Pipfile.lock", "tox.ini",
)

JAVA_FILE_PATTERNS = (
    "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
    "settings.gradle.kts", "gradle.properties", "build.xml", "ivy.xml",
)

JS_FILE_PATTERNS = ("package.json",)

RUST_FILE_PATTERNS = ("Cargo.toml",)


# ===================================================================
# 工具函数
# ===================================================================

def normalize_version(version: str) -> str:
    version = str(version).strip()
    match = re.search(r"(\d+(?:\.\d+){0,4})", version)
    return match.group(1) if match else version


def normalize_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", str(name).strip().lower())


def sanitize_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_") or "unknown"


def http_get(url: str, headers: Optional[Dict[str, str]] = None) -> Tuple[int, str]:
    merged_headers = dict(HEADERS)
    if headers:
        merged_headers.update(headers)
    try:
        resp = SESSION.get(url, headers=merged_headers, timeout=REQUEST_TIMEOUT)
        return resp.status_code, resp.text
    except requests.RequestException as exc:
        LOGGER.warning("HTTP GET failed %s: %s", url, exc)
        return 0, str(exc)


def build_headers(github_token: str = "") -> Dict[str, str]:
    h = dict(HEADERS)
    if github_token:
        h["Authorization"] = f"Bearer {github_token}"
    return h


# ===================================================================
# 数据库加载
# ===================================================================

# Java 组件 Maven 坐标映射表（target_name → osv_package）
_JAVA_MAVEN_MAP: Dict[str, str] = {
    "Spring Boot": "org.springframework.boot:spring-boot",
    "Apache Tomcat": "org.apache.tomcat:tomcat",
    "Apache Kafka": "org.apache.kafka:kafka-clients",
    "Log4j": "org.apache.logging.log4j:log4j-core",
    "Fastjson2": "com.alibaba.fastjson2:fastjson2",
    "Apache Solr": "org.apache.solr:solr-core",
    "Apache Struts2": "org.apache.struts:struts2-core",
    "Apache Shiro": "org.apache.shiro:shiro-core",
    "MyBatis": "org.mybatis:mybatis",
    "Apache Commons IO": "commons-io:commons-io",
    "Apache Commons Text": "org.apache.commons:commons-text",
    "Apache XMLBeans": "org.apache.xmlbeans:xmlbeans",
    "Apache Commons Collections": "org.apache.commons:commons-collections4",
    "Groovy": "org.apache.groovy:groovy",
    "Jetty": "org.eclipse.jetty:jetty-server",
}


def load_targets_from_xlsx(xlsx_path: str) -> Dict:
    """从 uncovered_library_cves.xlsx 读取 target_name + language，构建组件查找表。

    返回:
        {"java_targets": {name: [(group_id, artifact_id)]},
         "python_targets": {name: [package_name]}}
    """
    df = pd.read_excel(xlsx_path)
    java_targets: Dict[str, List[Tuple[str, str]]] = {}
    python_targets: Dict[str, List[str]] = {}

    for _, row in df.iterrows():
        name = str(row["target_name"])
        lang = str(row.get("language", "")).lower()

        if lang == "java":
            osv_pkg = _JAVA_MAVEN_MAP.get(name, "")
            if osv_pkg and ":" in osv_pkg:
                group_id, artifact_id = osv_pkg.split(":", 1)
                java_targets.setdefault(name, []).append((group_id, artifact_id))
            else:
                LOGGER.warning("No Maven coordinate mapping for %s, skipping", name)
        elif lang == "python":
            python_targets.setdefault(name, []).append(name.lower())

    return {
        "java_targets": java_targets,
        "python_targets": python_targets,
    }


# ===================================================================
# GitHub API 操作
# ===================================================================

def list_recent_tags(owner: str, repo: str, top_n: int, headers: Dict[str, str]) -> List[str]:
    """拉取仓库 tag 列表。top_n=0 表示拉取全部 tag。"""
    tags: List[str] = []
    page = 1
    while True:
        api = TAGS_API.format(owner=owner, repo=repo)
        url = f"{api}?per_page=100&page={page}"
        code, text = http_get(url, headers=headers)
        if code != 200:
            LOGGER.warning("Failed to get tags for %s/%s: %s", owner, repo, text[:200])
            break
        data = json.loads(text)
        if not data:
            break
        for item in data:
            name = item.get("name") if isinstance(item, dict) else None
            if name and re.search(r"\d", name):
                tags.append(name)
                if top_n > 0 and len(tags) >= top_n:
                    break
        if top_n > 0 and len(tags) >= top_n:
            break
        page += 1
        time.sleep(SLEEP_BETWEEN_REQUESTS)
    LOGGER.info("Repo %s/%s: got %d tags: %s", owner, repo, len(tags), tags)
    return tags


def list_repository_files(owner: str, repo: str, ref: str, headers: Dict[str, str]) -> List[str]:
    url = TREE_API.format(owner=owner, repo=repo, ref=ref)
    code, text = http_get(url, headers=headers)
    if code != 200:
        LOGGER.warning("Failed to get file tree for %s/%s@%s: %s", owner, repo, ref, text[:200])
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    paths = [item["path"] for item in data.get("tree", []) if item.get("type") == "blob" and item.get("path")]
    LOGGER.info("Repo %s/%s@%s: %d files in tree", owner, repo, ref, len(paths))
    return paths


def get_raw_cache_path(owner: str, repo: str, tag: str, path: str) -> Path:
    path_obj = PurePosixPath(path)
    safe_parts = [sanitize_filename(owner), sanitize_filename(repo), sanitize_filename(tag)]
    for part in path_obj.parts:
        safe_parts.append(sanitize_filename(part))
    return DEFAULT_CACHE_DIR.joinpath(*safe_parts)


def fetch_raw_file(owner: str, repo: str, tag: str, path: str, headers: Dict[str, str]) -> Optional[str]:
    cache_path = get_raw_cache_path(owner, repo, tag, path)
    if cache_path.exists():
        try:
            return cache_path.read_text(encoding="utf-8")
        except Exception:
            pass

    raw_url = RAW_BASE.format(owner=owner, repo=repo, ref=tag, path=path)
    code, content = http_get(raw_url, headers=headers)
    if code == 200 and content:
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(content, encoding="utf-8")
        except Exception as exc:
            LOGGER.warning("Cache write failed %s: %s", cache_path, exc)
        return content
    return None


def filter_candidate_files(paths: List[str], patterns: Sequence[str]) -> List[str]:
    result: List[str] = []
    for path in paths:
        lower_path = path.lower()
        filename = os.path.basename(lower_path)
        if any(token.lower() in lower_path or token.lower() == filename for token in patterns):
            result.append(path)
    return result


# ===================================================================
# 依赖解析函数
# ===================================================================

def match_java_component(group: str, artifact: str, java_targets: Dict[str, List[Tuple[str, str]]]) -> Optional[str]:
    """返回匹配到的 DB 组件名称（如 'Spring Framework'）"""
    for name, patterns in java_targets.items():
        for target_group, artifact_keyword in patterns:
            group_match = group == target_group or group.startswith(target_group + ".") or target_group in group
            if group_match and artifact_keyword in artifact:
                return name
    return None


def parse_maven_properties(content: str) -> Dict[str, str]:
    properties: Dict[str, str] = {}
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return properties
    ns = {"pom": MAVEN_NAMESPACE}
    props_element = root.find("pom:properties", ns)
    if props_element is not None:
        for prop in props_element:
            tag = prop.tag.replace("{" + MAVEN_NAMESPACE + "}", "")
            text = prop.text.strip() if prop.text else ""
            if text:
                properties[f"${{{tag}}}"] = text
    return properties


def parse_pom_dependencies(content: str, java_targets: Dict, inherited_properties: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    versions: Dict[str, str] = {}
    properties = dict(inherited_properties or {})
    properties.update(parse_maven_properties(content))
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return versions
    ns = {"pom": MAVEN_NAMESPACE}
    for dep in root.findall(".//pom:dependency", ns):
        gid = dep.findtext("pom:groupId", default="", namespaces=ns).strip()
        aid = dep.findtext("pom:artifactId", default="", namespaces=ns).strip()
        ver = dep.findtext("pom:version", default="", namespaces=ns).strip()
        if not gid or not aid or not ver:
            continue
        if ver.startswith("${"):
            ver = properties.get(ver, ver)
        component = match_java_component(gid, aid, java_targets)
        if component:
            versions.setdefault(component, normalize_version(ver))
    return versions


def parse_gradle_properties(content: str) -> Dict[str, str]:
    properties: Dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        properties[key.strip()] = value.strip()
    return properties


def resolve_gradle_placeholders(version: str, properties: Dict[str, str]) -> str:
    version = version.strip().strip("\"'")
    placeholder_match = re.fullmatch(r"\$\{?([A-Za-z0-9_.\-]+)\}?", version)
    if placeholder_match:
        key = placeholder_match.group(1)
        return properties.get(key, version)
    return version


def parse_gradle_dependencies(content: str, java_targets: Dict, properties: Dict[str, str]) -> Dict[str, str]:
    versions: Dict[str, str] = {}
    for group, artifact, version in GRADLE_DEP_REGEX.findall(content):
        component = match_java_component(group, artifact, java_targets)
        if component:
            resolved = resolve_gradle_placeholders(version, properties)
            versions.setdefault(component, normalize_version(resolved))
    return versions


def parse_ant_or_ivy_dependencies(content: str, java_targets: Dict) -> Dict[str, str]:
    versions: Dict[str, str] = {}
    for group, artifact, version in ANT_IVY_REGEX.findall(content):
        component = match_java_component(group, artifact, java_targets)
        if component:
            versions.setdefault(component, normalize_version(version))
    return versions


def parse_maven_coordinates_from_text(content: str, java_targets: Dict) -> Dict[str, str]:
    versions: Dict[str, str] = {}
    for group, artifact, version in MAVEN_COORD_REGEX.findall(content):
        component = match_java_component(group.strip(), artifact.strip(), java_targets)
        if component:
            versions.setdefault(component, normalize_version(version.strip()))
    return versions


# ---- Python 解析 ----

def parse_python_versions_from_content(pkg: str, content: str) -> List[str]:
    results: List[str] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for rgx in REQ_LINE_REGEXES:
            matched = rgx.match(line)
            if matched and matched.group("pkg").lower() == pkg.lower():
                results.append(normalize_version(matched.group("ver")))
                break
    for line in content.splitlines():
        line = line.strip()
        for rgx in TOML_DEP_SECTION_REGEXES:
            matched = rgx.match(line)
            if matched and matched.group(1).lower() == pkg.lower():
                results.append(normalize_version(matched.group("spec")))
    return list(dict.fromkeys(results))


def parse_setup_py_versions(pkg: str, content: str) -> List[str]:
    target = normalize_package_name(pkg)
    versions: List[str] = []
    for dep_name, dep_version in SETUP_PY_REGEX.findall(content):
        if normalize_package_name(dep_name) == target:
            versions.append(normalize_version(dep_version))
    return list(dict.fromkeys(versions))


def parse_pipfile_versions(pkg: str, content: str) -> List[str]:
    target = normalize_package_name(pkg)
    versions: List[str] = []
    for name, version1, version2 in PIPFILE_REGEX.findall(content):
        if normalize_package_name(name) == target:
            versions.append(normalize_version(version1 or version2))
    return list(dict.fromkeys(versions))


def parse_poetry_or_pdm_lock_versions(pkg: str, content: str) -> List[str]:
    target = normalize_package_name(pkg)
    current_name = ""
    versions: List[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        name_match = POETRY_LOCK_NAME_REGEX.match(stripped) or PDM_LOCK_NAME_REGEX.match(stripped)
        if name_match:
            current_name = name_match.group(1)
            continue
        version_match = POETRY_LOCK_VERSION_REGEX.match(stripped) or PDM_LOCK_VERSION_REGEX.match(stripped)
        if version_match and normalize_package_name(current_name) == target:
            versions.append(normalize_version(version_match.group(1)))
            current_name = ""
    return list(dict.fromkeys(versions))


def parse_python_file_for_package(path: str, pkg_name: str, content: str) -> List[str]:
    lower_path = path.lower()
    versions: List[str] = []
    versions.extend(parse_python_versions_from_content(pkg_name, content))
    if lower_path.endswith("setup.py"):
        versions.extend(parse_setup_py_versions(pkg_name, content))
    if lower_path.endswith("pipfile") or lower_path.endswith("pipfile.lock"):
        versions.extend(parse_pipfile_versions(pkg_name, content))
    if lower_path.endswith("poetry.lock") or lower_path.endswith("pdm.lock"):
        versions.extend(parse_poetry_or_pdm_lock_versions(pkg_name, content))
    return list(dict.fromkeys([v for v in versions if v]))


# ---- JavaScript / Rust 解析 ----

def parse_package_json(content: str, python_targets: Dict[str, List[str]]) -> Dict[str, str]:
    versions: Dict[str, str] = {}
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return versions
    all_deps = {}
    all_deps.update(data.get("dependencies", {}))
    all_deps.update(data.get("devDependencies", {}))
    pkg_map: Dict[str, str] = {}
    for target_name, pkg_names in python_targets.items():
        for pn in pkg_names:
            pkg_map[pn] = target_name
    for pkg, ver in all_deps.items():
        pkg_lower = pkg.lower()
        if pkg_lower in pkg_map:
            raw_ver = str(ver).lstrip("^~>=< ")
            versions.setdefault(pkg_map[pkg_lower], normalize_version(raw_ver))
    return versions


def parse_cargo_toml(content: str, python_targets: Dict[str, List[str]]) -> Dict[str, str]:
    versions: Dict[str, str] = {}
    in_deps = False
    pkg_map: Dict[str, str] = {}
    for target_name, pkg_names in python_targets.items():
        for pn in pkg_names:
            pkg_map[pn] = target_name
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("[dependencies"):
            in_deps = True
            continue
        if line.startswith("[") and in_deps:
            in_deps = False
            continue
        if in_deps and "=" in line:
            parts = line.split("=", 1)
            pkg = parts[0].strip().strip('"').lower()
            ver_str = parts[1].strip().strip('"').lstrip("^~>=< ")
            if pkg in pkg_map:
                versions.setdefault(pkg_map[pkg], normalize_version(ver_str))
    return versions


# ===================================================================
# 主流程
# ===================================================================

def scan_repo_for_deps(owner: str, repo: str, tag: str, headers: Dict[str, str],
                       comp_lookup: Dict) -> List[Dict[str, str]]:
    """扫描一个仓库的某个 tag，提取目标组件版本"""
    rows: List[Dict[str, str]] = []
    repo_files = list_repository_files(owner, repo, tag, headers)
    if not repo_files:
        return rows

    java_targets = comp_lookup["java_targets"]
    python_targets = comp_lookup["python_targets"]

    py_candidates = filter_candidate_files(repo_files, PYTHON_FILE_PATTERNS)
    java_candidates = filter_candidate_files(repo_files, JAVA_FILE_PATTERNS)
    js_candidates = filter_candidate_files(repo_files, JS_FILE_PATTERNS)
    rust_candidates = filter_candidate_files(repo_files, RUST_FILE_PATTERNS)

    LOGGER.info("[%s] %s candidate files: py=%d, java=%d, js=%d, rust=%d",
                tag, repo, len(py_candidates), len(java_candidates), len(js_candidates), len(rust_candidates))

    # Java 解析
    collected_properties: Dict[str, str] = {}
    java_contents: Dict[str, str] = {}
    for path in java_candidates:
        content = fetch_raw_file(owner, repo, tag, path, headers)
        if content is None:
            continue
        java_contents[path] = content
        if path.endswith("gradle.properties"):
            collected_properties.update(parse_gradle_properties(content))
        elif path.endswith("pom.xml"):
            collected_properties.update(parse_maven_properties(content))

    for path, content in java_contents.items():
        if path.endswith("pom.xml"):
            versions = parse_pom_dependencies(content, java_targets, collected_properties)
        elif path.endswith("build.gradle") or path.endswith("build.gradle.kts"):
            versions = parse_gradle_dependencies(content, java_targets, collected_properties)
        elif path.endswith("build.xml") or path.endswith("ivy.xml"):
            versions = parse_ant_or_ivy_dependencies(content, java_targets)
        else:
            versions = parse_maven_coordinates_from_text(content, java_targets)
        for component, version in versions.items():
            rows.append({"Tag": tag, "Component": component, "Version": version, "SourceFile": path})
            LOGGER.info("[Java] Hit: repo=%s/%s tag=%s file=%s component=%s version=%s",
                        owner, repo, tag, path, component, version)
        time.sleep(SLEEP_BETWEEN_REQUESTS)

    # Python 解析
    for path in py_candidates:
        content = fetch_raw_file(owner, repo, tag, path, headers)
        if content is None:
            continue
        for target_name, pkg_names in python_targets.items():
            for pkg_name in pkg_names:
                versions = parse_python_file_for_package(path, pkg_name, content)
                for version in versions:
                    rows.append({"Tag": tag, "Component": target_name, "Version": version, "SourceFile": path})
                    LOGGER.info("[Python] Hit: repo=%s/%s tag=%s file=%s component=%s version=%s",
                                owner, repo, tag, path, target_name, version)
        time.sleep(SLEEP_BETWEEN_REQUESTS)

    # JS 解析 (package.json)
    for path in js_candidates:
        content = fetch_raw_file(owner, repo, tag, path, headers)
        if content is None:
            continue
        versions = parse_package_json(content, python_targets)
        for component, version in versions.items():
            rows.append({"Tag": tag, "Component": component, "Version": version, "SourceFile": path})
            LOGGER.info("[JS] Hit: repo=%s/%s tag=%s file=%s component=%s version=%s",
                        owner, repo, tag, path, component, version)
        time.sleep(SLEEP_BETWEEN_REQUESTS)

    # Rust 解析 (Cargo.toml)
    for path in rust_candidates:
        content = fetch_raw_file(owner, repo, tag, path, headers)
        if content is None:
            continue
        versions = parse_cargo_toml(content, python_targets)
        for component, version in versions.items():
            rows.append({"Tag": tag, "Component": component, "Version": version, "SourceFile": path})
            LOGGER.info("[Rust] Hit: repo=%s/%s tag=%s file=%s component=%s version=%s",
                        owner, repo, tag, path, component, version)
        time.sleep(SLEEP_BETWEEN_REQUESTS)

    return deduplicate_rows(rows)


def deduplicate_rows(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    seen = set()
    result = []
    for row in rows:
        key = (row.get("Tag"), row.get("Component"), row.get("Version"), row.get("SourceFile"))
        if key in seen:
            continue
        seen.add(key)
        result.append(dict(row))
    return result


def load_repos_from_excel(excel_path: str) -> List[Dict[str, str]]:
    """从 Excel 读取仓库列表，格式: RepoName (owner/repo)"""
    df = pd.read_excel(excel_path)
    repos = []
    for _, row in df.iterrows():
        repo_name = str(row["RepoName"]).strip()
        if not repo_name or repo_name.lower() == "nan":
            continue
        if "/" in repo_name:
            owner, parsed_repo = repo_name.split("/", 1)
        else:
            owner, parsed_repo = "", repo_name
        repos.append({"repo_name": repo_name, "owner": owner, "repo": parsed_repo, "url": f"https://github.com/{repo_name}"})
    LOGGER.info("Loaded %d repos from %s", len(repos), excel_path)
    return repos


def _process_repo(repo_info: Dict[str, str], comp_lookup: Dict, headers: Dict[str, str],
                  top_tags: int, idx: int, total: int, lock: threading.Lock) -> List[Dict[str, str]]:
    """处理单个仓库（线程安全）"""
    owner, repo, repo_name = repo_info["owner"], repo_info["repo"], repo_info["repo_name"]
    with lock:
        LOGGER.info("[%d/%d] Processing repo: %s/%s", idx, total, owner, repo)

    rows: List[Dict[str, str]] = []
    tags = list_recent_tags(owner, repo, top_tags, headers)
    if not tags:
        with lock:
            LOGGER.warning("[%d/%d] No tags found for %s/%s", idx, total, owner, repo)
        return rows

    for tag in tags:
        try:
            hits = scan_repo_for_deps(owner, repo, tag, headers, comp_lookup)
            for row in hits:
                row["RepoName"] = repo_name
            rows.extend(hits)
            with lock:
                LOGGER.info("[%d/%d] Repo %s tag %s: %d hits", idx, total, repo_name, tag, len(hits))
        except Exception as exc:
            with lock:
                LOGGER.warning("[%d/%d] Failed to scan %s tag %s: %s", idx, total, repo_name, tag, exc)
    return rows


def run(repos: List[Dict[str, str]], comp_lookup: Dict, headers: Dict[str, str],
        top_tags: int, repo_limit: int, workers: int = 5) -> pd.DataFrame:
    """主入口：并发扫描所有仓库，提取依赖"""
    repos_to_scan = repos[:repo_limit] if repo_limit and repo_limit > 0 else repos
    total = len(repos_to_scan)
    all_rows: List[Dict[str, str]] = []
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {}
        for i, repo_info in enumerate(repos_to_scan, 1):
            future = executor.submit(_process_repo, repo_info, comp_lookup, headers, top_tags, i, total, lock)
            futures[future] = repo_info["repo_name"]

        for future in as_completed(futures):
            repo_name = futures[future]
            try:
                rows = future.result()
                all_rows.extend(rows)
            except Exception as exc:
                LOGGER.error("Repo %s failed with error: %s", repo_name, exc)

    if all_rows:
        df = pd.DataFrame(all_rows, columns=["RepoName", "Tag", "Component", "Version", "SourceFile"])
    else:
        df = pd.DataFrame(columns=["RepoName", "Tag", "Component", "Version", "SourceFile"])
    LOGGER.info("Phase 1 complete: %d total hits from %d repos (workers=%d)", len(df), total, workers)
    return df


# ===================================================================
# 命令行入口
# ===================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GitHub 仓库依赖提取 (Phase 1)")
    parser.add_argument("--github-token", default="", help="GitHub API Token（必需）")
    parser.add_argument("--top-tags", type=int, default=0, help="每个仓库分析的 tag 数量 (0=全部)")
    parser.add_argument("--repo-limit", type=int, default=0, help="限制分析的仓库数量 (0=全部)")
    parser.add_argument("--workers", type=int, default=5, help="并发 worker 数 (默认 5)")
    parser.add_argument("--cache-dir", default=str(DEFAULT_CACHE_DIR), help="本地缓存目录")
    parser.add_argument("--repos-excel", default="data/github_top_repos.xlsx", help="仓库列表 Excel")
    parser.add_argument("--targets-xlsx", default="data/uncovered_library_cves.xlsx", help="目标组件列表 Excel")
    parser.add_argument("--output", default="data/dep_scan_result.xlsx", help="输出文件路径")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    global DEFAULT_CACHE_DIR
    DEFAULT_CACHE_DIR = Path(args.cache_dir)
    DEFAULT_CACHE_DIR.mkdir(parents=True, exist_ok=True)

    headers = build_headers(args.github_token)

    LOGGER.info("Loading targets from %s", args.targets_xlsx)
    comp_lookup = load_targets_from_xlsx(args.targets_xlsx)
    total = len(comp_lookup["java_targets"]) + len(comp_lookup["python_targets"])
    LOGGER.info("Loaded %d targets: java=%d, python=%d",
                total, len(comp_lookup["java_targets"]), len(comp_lookup["python_targets"]))

    LOGGER.info("==== Phase 1: Dependency Extraction ====")
    repos = load_repos_from_excel(args.repos_excel)
    dep_df = run(repos, comp_lookup, headers, args.top_tags, args.repo_limit, args.workers)
    dep_df.to_excel(args.output, index=False)
    LOGGER.info("Output written to %s (%d rows)", args.output, len(dep_df))


if __name__ == "__main__":
    main()
