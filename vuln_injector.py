#!/usr/bin/env python3
"""
Phase 4: 漏洞注入点预测 — 找到仓库中漏洞组件的调用位置，修改为有漏洞版本的调用模式，检查可编译性

用法:
    python vuln_injector.py [--match-file data/cve_match_result.xlsx] [--dry-run] [--repo-limit 3]
"""

import argparse
import ast
import json
import logging
import os
import re
import sqlite3
import subprocess
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd
import requests

import cve_checkpoint

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT = 120

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
LOGGER = logging.getLogger("vuln_injector")


# ===================================================================
# 组件名 → import/grep 模式映射
# ===================================================================

COMPONENT_IMPORT_PATTERNS: Dict[str, Dict[str, List[str]]] = {
    "Jackson": {
        "java": ["com.fasterxml.jackson", "org.codehaus.jackson"],
    },
    "Log4j": {
        "java": ["org.apache.logging.log4j", "org.apache.log4j"],
    },
    "Apache Commons IO": {
        "java": ["org.apache.commons.io"],
    },
    "Apache Commons FileUpload": {
        "java": ["org.apache.commons.fileupload"],
    },
    "Apache Commons BeanUtils": {
        "java": ["org.apache.commons.beanutils"],
    },
    "urllib3": {
        "python": ["import urllib3", "from urllib3"],
    },
    "NumPy": {
        "python": ["import numpy", "from numpy"],
    },
    "SciPy": {
        "python": ["import scipy", "from scipy"],
    },
    "Pillow": {
        "python": ["import PIL", "from PIL", "import Pillow", "from Pillow"],
    },
    "PyYAML": {
        "python": ["import yaml", "from yaml"],
    },
    "joblib": {
        "python": ["import joblib", "from joblib"],
    },
}

import javalang

# ===================================================================
# Step 1: Repo 克隆
# ===================================================================

def clone_repo(repo_name: str, tag: str, cache_dir: Path) -> Path:
    """浅克隆仓库到缓存目录，返回 repo 路径。支持从 GitHub 和 gitee 克隆。"""
    cache_dir.mkdir(parents=True, exist_ok=True)
    repo_path = cache_dir / repo_name / tag

    if (repo_path / ".git").exists():
        LOGGER.info("Repo cache hit: %s", repo_path)
        return repo_path

    # 清理不完整的克隆
    if repo_path.exists():
        shutil.rmtree(repo_path)

    # repo 格式：owner/repo
    if "/" in repo_name:
        remotes = [f"https://github.com/{repo_name}.git"]
    else:
        LOGGER.warning("Invalid repo name format (expected owner/repo): %s", repo_name)
        return None

    for remote in remotes:
        cmd = ["git", "clone", "--depth", "1", "--branch", tag, remote, str(repo_path)]
        LOGGER.info("Cloning: %s", " ".join(cmd))
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0 and (repo_path / ".git").exists():
                LOGGER.info("Clone success from %s", remote)
                return repo_path
            else:
                LOGGER.warning("Clone failed from %s: %s", remote, result.stderr[-200:])
                if repo_path.exists():
                    shutil.rmtree(repo_path)
        except subprocess.TimeoutExpired:
            LOGGER.warning("Clone timeout from %s", remote)
            if repo_path.exists():
                shutil.rmtree(repo_path)

    # 全部失败，创建标记文件
    LOGGER.error("All clone attempts failed for %s @ %s", repo_name, tag)
    repo_path.mkdir(parents=True, exist_ok=True)
    (repo_path / "CLONE_FAILED").touch()
    return repo_path


# ===================================================================
# Step 2: 调用点发现
# ===================================================================

def _get_import_patterns(component: str, language: str) -> List[str]:
    """获取组件的 grep 搜索模式。"""
    if component in COMPONENT_IMPORT_PATTERNS:
        extra = COMPONENT_IMPORT_PATTERNS[component].get(language, [])
    else:
        extra = []
    # 追加基于组件名的推断模式
    if language == "java":
        # 尝试从组件名推断包名: "Jackson" -> "jackson"
        inferred = component.lower().replace(" ", "")
        extra.append(inferred)
    elif language == "python":
        inferred = component.lower().replace(" ", "_").replace("-", "_")
        extra.append(f"import {inferred}")
        extra.append(f"from {inferred}")
    return list(set(extra))


def _detect_language(source_file: str) -> str:
    """根据依赖文件类型判断语言。"""
    ext = os.path.splitext(source_file)[1].lower()
    java_indicators = [".xml", ".gradle", ".kts", ".properties"]
    python_indicators = [".txt", ".py", ".cfg", ".toml", ".lock"]
    if source_file.endswith("pom.xml") or ext in java_indicators:
        return "java"
    return "python"


def find_call_sites(repo_path: Path, component: str, source_file: str) -> Dict[str, List[Tuple[int, str]]]:
    """
    在仓库中搜索目标组件的所有调用点。
    返回 {file_path: [(line_number, code_line), ...]}
    """
    language = _detect_language(source_file)
    patterns = _get_import_patterns(component, language)
    results: Dict[str, List[Tuple[int, str]]] = {}

    if language == "java":
        search_ext = "*.java"
    else:
        search_ext = "*.py"

    for pattern in patterns:
        try:
            proc = subprocess.run(
                ["rg", "--no-heading", "-n", "-F", pattern, "--glob", search_ext, str(repo_path)],
                capture_output=True, text=True, timeout=30
            )
            for line in proc.stdout.strip().split("\n"):
                if not line:
                    continue
                # rg 输出格式: file_path:line_num:content
                parts = line.split(":", 2)
                if len(parts) < 3:
                    continue
                file_path = parts[0]
                try:
                    line_num = int(parts[1])
                except ValueError:
                    continue
                code = parts[2].strip()
                if file_path not in results:
                    results[file_path] = []
                results[file_path].append((line_num, code))
        except FileNotFoundError:
            # rg 不可用，降级为 grep
            ext = "*.java" if language == "java" else "*.py"
            grep_proc = subprocess.run(
                ["grep", "-rn", "-F", pattern, "--include", ext, str(repo_path)],
                capture_output=True, text=True, timeout=30
            )
            for line in grep_proc.stdout.strip().split("\n"):
                if not line:
                    continue
                parts = line.split(":", 2)
                if len(parts) < 3:
                    continue
                results.setdefault(parts[0], []).append((int(parts[1]), parts[2].strip()))

    # 去重每个文件的调用点
    for path in results:
        seen = set()
        unique = []
        for ln, code in results[path]:
            key = (ln, code)
            if key not in seen:
                seen.add(key)
                unique.append((ln, code))
        results[path] = sorted(unique, key=lambda x: x[0])

    # ---- 后过滤：区分 import vs 实际 API 调用 ----
    # Python: 用 ast 精确认证实际调用
    # Java: 用 javalang AST 精确认证实际调用
    filtered_results: Dict[str, List[Tuple[int, str]]] = {}
    for file_path, matched_lines in results.items():
        if file_path.endswith(".py"):
            py_patterns = _get_import_patterns(component, "python")
            api_calls = _analyze_python_ast(file_path, py_patterns)
            if api_calls:
                import_line_nums = {ln for ln, _ in matched_lines}
                filtered_results[file_path] = matched_lines + [
                    (ln, code) for ln, code in api_calls if ln not in import_line_nums
                ]
            # else: 仅有 import 无调用 → 丢弃
        elif file_path.endswith(".java"):
            java_patterns = _get_import_patterns(component, "java")
            api_calls = _analyze_java_ast(file_path, java_patterns)
            if api_calls:
                import_line_nums = {ln for ln, _ in matched_lines}
                filtered_results[file_path] = matched_lines + [
                    (ln, code) for ln, code in api_calls if ln not in import_line_nums
                ]
            # else: 有 import 但无实际 API 调用 → 丢弃
        else:
            # 其他文件类型：保持原行为
            filtered_results[file_path] = matched_lines

    return filtered_results


def _analyze_python_ast(file_path: str, import_patterns: List[str]) -> List[Tuple[int, str]]:
    """用 ast 解析 Python 文件，只返回实际 API 调用行（排除纯 import 行）。

    返回 [(line_number, code_line), ...]，每项对应一个真实的 API 调用（非 import）。
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
        tree = ast.parse(source, filename=file_path)
    except (SyntaxError, Exception):
        return []

    # 将 grep 风格的模式（"import yaml", "from PIL"）提取为纯模块名
    module_names: set = set()
    for pat in import_patterns:
        p = pat.strip()
        if p.startswith("from "):
            module_names.add(p[5:].split()[0].strip())
        elif p.startswith("import "):
            module_names.add(p[7:].strip())
        else:
            module_names.add(p)

    if not module_names:
        return []

    # Step 1: 找到所有与目标组件匹配的 import 绑定名称
    # import xxx  → 绑定名 xxx
    # from xxx import yyy → 绑定名 yyy
    # from xxx import yyy as zzz → 绑定名 zzz
    bound_names: set = set()
    import_lines: set = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                full_name = alias.name
                as_name = alias.asname or alias.name
                # 检查 import 路径或其前缀是否匹配目标模块
                parts = full_name.split(".")
                for i in range(len(parts)):
                    prefix = ".".join(parts[:i + 1])
                    if prefix in module_names:
                        bound_names.add(as_name)
                        import_lines.add(node.lineno)
                        break
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module in module_names:
                for alias in node.names:
                    as_name = alias.asname or alias.name
                    bound_names.add(as_name)
                    import_lines.add(node.lineno)

    if not bound_names:
        return []

    # Step 2: 找到对 bound_names 的实际调用
    # Call(func=Name(id=bound_name)), Call(func=Attribute(value=Name(id=bound_name)))
    api_call_lines: List[Tuple[int, str]] = []
    source_lines = source.split("\n")

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # 跳过 import 行内的调用（不太可能但做个保护）
        if node.lineno in import_lines:
            continue

        func = node.func
        if isinstance(func, ast.Name) and func.id in bound_names:
            if node.lineno <= len(source_lines):
                api_call_lines.append((node.lineno, source_lines[node.lineno - 1].strip()))
        elif isinstance(func, ast.Attribute):
            # 检查 attribute 链，如 yaml.full_load() 或 yaml.Loader(...)
            root = func
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id in bound_names:
                if node.lineno <= len(source_lines):
                    api_call_lines.append((node.lineno, source_lines[node.lineno - 1].strip()))

    return sorted(set(api_call_lines), key=lambda x: x[0])


def _analyze_java_ast(file_path: str, import_patterns: List[str]) -> List[Tuple[int, str]]:
    """用 javalang 解析 Java 文件，只返回实际 API 调用行（排除纯 import 行）。

    返回 [(line_number, code_line), ...]
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
        tree = javalang.parse.parse(source)
    except Exception:
        return []

    # 目标包前缀（来自 COMPONENT_IMPORT_PATTERNS，如 com.fasterxml.jackson）
    target_packages = set(import_patterns)
    if not target_packages:
        return []

    source_lines = source.split("\n")

    # Step 1: 找到与目标包匹配的 import，收集导入的简单类名
    imported_classes: set = set()  # 如 {"ObjectMapper", "JsonFactory"}
    import_line_nums: set = set()

    for imp in tree.imports:
        for pkg in target_packages:
            if imp.path.startswith(pkg):
                if imp.wildcard:
                    imported_classes.add("*")
                else:
                    imported_classes.add(imp.path.rsplit(".", 1)[-1])
                if imp.position:
                    import_line_nums.add(imp.position.line)
                break

    if not imported_classes:
        return []

    def _type_name(type_node) -> str | None:
        """从 javalang Type 节点提取简单类型名"""
        if type_node is None:
            return None
        if isinstance(type_node, javalang.tree.BasicType):
            return type_node.name
        if isinstance(type_node, javalang.tree.ReferenceType):
            return type_node.name
        return None

    # Step 2: 收集声明了被导入类型变量的变量名，并记录声明行为 API 调用
    api_lines: List[Tuple[int, str]] = []

    def _add_line(line_no):
        if line_no and line_no not in import_line_nums and line_no <= len(source_lines):
            api_lines.append((line_no, source_lines[line_no - 1].strip()))

    typed_vars: Dict[str, int] = {}  # var_name -> 声明行号

    for _, node in tree.filter(javalang.tree.FieldDeclaration):
        tname = _type_name(node.type)
        if tname in imported_classes:
            _add_line(node.position.line if node.position else None)
            for decl in node.declarators:
                typed_vars[decl.name] = node.position.line if node.position else -1

    for _, node in tree.filter(javalang.tree.LocalVariableDeclaration):
        tname = _type_name(node.type)
        if tname in imported_classes:
            _add_line(node.position.line if node.position else None)
            for decl in node.declarators:
                typed_vars[decl.name] = node.position.line if node.position else -1

    # Step 3: 查找方法调用/构造函数

    wildcard_active = "*" in imported_classes

    # ClassCreator: new ObjectMapper()
    for _, node in tree.filter(javalang.tree.ClassCreator):
        tname = _type_name(node.type)
        if tname and (tname in imported_classes or wildcard_active):
            _add_line(node.position.line if node.position else None)

    # MethodInvocation: mapper.readValue() / LogManager.getLogger()
    for _, node in tree.filter(javalang.tree.MethodInvocation):
        qualifier = node.qualifier
        if qualifier and (qualifier in typed_vars or qualifier in imported_classes):
            _add_line(node.position.line if node.position else None)
        elif not qualifier and wildcard_active:
            _add_line(node.position.line if node.position else None)

    # Static method calls via class name, or field accesses
    for _, node in tree.filter(javalang.tree.MemberReference):
        qualifier = node.qualifier
        if qualifier and (qualifier in typed_vars or qualifier in imported_classes):
            _add_line(node.position.line if node.position else None)

    return sorted(set(api_lines), key=lambda x: x[0])


# ===================================================================
# Step 3: LLM 分析漏洞调用模式
# ===================================================================

def _extract_python_func(lines: List[str], target_ln: int) -> Optional[Tuple[int, int, str]]:
    """从 Python 文件的行号提取所在完整函数/类定义。返回 (起始行, 结束行, 代码) 或 None。"""
    idx = target_ln - 1
    if idx >= len(lines) or idx < 0:
        return None

    target_line = lines[idx]
    if not target_line.strip():
        return None
    target_indent = len(target_line) - len(target_line.lstrip())

    # 向上查找 def / class / async def，缩进必须 < 目标行缩进
    func_start = None
    for i in range(idx, -1, -1):
        stripped = lines[i].lstrip()
        if stripped.startswith(('def ', 'class ', 'async def ')):
            indent = len(lines[i]) - len(stripped)
            if indent < target_indent or (indent == target_indent and i == idx):
                func_start = i
                break

    if func_start is None:
        return None

    # 向上继续查找装饰器，将其纳入函数范围
    for i in range(func_start - 1, -1, -1):
        if lines[i].strip().startswith('@'):
            func_start = i
        else:
            break

    func_indent = len(lines[func_start]) - len(lines[func_start].lstrip())

    # 向下查找函数结束：遇到非空、非注释、缩进 <= func_indent 的行
    func_end = len(lines) - 1
    for i in range(func_start + 1, len(lines)):
        stripped = lines[i].strip()
        if not stripped or stripped.startswith('#'):
            continue
        indent = len(lines[i]) - len(stripped)
        if indent <= func_indent:
            func_end = i - 1
            break

    func_lines = lines[func_start:func_end + 1]
    while func_lines and not func_lines[-1].strip():
        func_lines.pop()

    if not func_lines:
        return None
    return (func_start + 1, func_start + len(func_lines), '\n'.join(func_lines))


def _extract_java_method(lines: List[str], target_ln: int) -> Optional[Tuple[int, int, str]]:
    """从 Java 文件的行号提取所在完整方法。返回 (起始行, 结束行, 代码) 或 None。"""
    idx = target_ln - 1
    if idx >= len(lines):
        return None

    # 计算每行之前的大括号深度
    depth_at_line = []
    depth = 0
    for line in lines:
        depth_at_line.append(depth)
        depth += line.count('{') - line.count('}')

    target_depth = depth_at_line[idx]
    if target_depth == 0:
        return None  # 在类级别，不在任何方法内

    # 向上找到开启此深度的大括号行
    block_start = None
    for i in range(idx, -1, -1):
        open_b = lines[i].count('{')
        close_b = lines[i].count('}')
        if depth_at_line[i] + open_b - close_b >= target_depth and '{' in lines[i]:
            block_start = i
            break

    if block_start is None:
        return None

    # 向上找方法签名起始（跳过注解和空行）
    method_start = block_start
    for i in range(block_start - 1, -1, -1):
        stripped = lines[i].strip()
        if not stripped:
            continue
        if stripped.startswith('@'):
            method_start = i
            continue
        elif stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
            continue
        else:
            method_start = i
            break

    # 向下匹配大括号找到方法结束
    brace_count = 0
    found_open = False
    for k in range(block_start, len(lines)):
        brace_count += lines[k].count('{')
        if lines[k].count('{') > 0:
            found_open = True
        brace_count -= lines[k].count('}')
        if found_open and brace_count == 0:
            func_lines = lines[method_start:k + 1]
            return (method_start + 1, k + 1, '\n'.join(func_lines))

    return None


def _extract_surrounding_context(all_lines: List[str], target_ln: int, window: int = 20) -> Tuple[int, int, str]:
    """回退方案：提取目标行周围的代码窗口。"""
    start = max(0, target_ln - 1 - window)
    end = min(len(all_lines), target_ln - 1 + window + 1)
    snippet = all_lines[start:end]
    while snippet and not snippet[0].strip():
        snippet = snippet[1:]
        start += 1
    while snippet and not snippet[-1].strip():
        snippet.pop()
    return (start + 1, start + len(snippet), '\n'.join(snippet))


def _extract_function_context(
    repo_path: Path, file_path: str, matched_lines: List[Tuple[int, str]], language: str
) -> str:
    """对一个文件的所有命中行，提取所在完整函数的上下文描述。"""
    # 处理文件路径（可能是绝对路径或相对路径）
    file_abs = Path(file_path)
    if not file_abs.is_absolute():
        file_abs = repo_path / file_path
    if not file_abs.exists():
        return ""

    try:
        all_lines = file_abs.read_text(encoding="utf-8", errors="replace").split('\n')
    except Exception:
        return ""

    extractor = _extract_python_func if language == "python" else _extract_java_method

    # 收集命中行号（去重）
    hit_line_nums = set(ln for ln, _ in matched_lines)

    # 按函数/区域去重：key=(start, end)
    # value: {"code": ..., "hits": set(), "is_func": bool}
    extracted_blocks = {}

    for ln in hit_line_nums:
        result = extractor(all_lines, ln)
        if result is not None:
            key = (result[0], result[1])
            if key not in extracted_blocks:
                extracted_blocks[key] = {"code": result[2], "hits": set(), "is_func": True}
            extracted_blocks[key]["hits"].add(ln)
        else:
            # 没有封闭函数，直接用周围代码窗口
            start, end, code = _extract_surrounding_context(all_lines, ln)
            key = (start, end)
            if key not in extracted_blocks:
                extracted_blocks[key] = {"code": code, "hits": set(), "is_func": False}
            extracted_blocks[key]["hits"].add(ln)

    if not extracted_blocks:
        return ""

    # 获取相对路径（用 file_abs 而非原始 file_path，确保路径解析一致）
    try:
        rel_path = str(file_abs.resolve().relative_to(repo_path.resolve()))
    except ValueError:
        rel_path = str(file_abs)

    parts = []
    for (start, end), block in sorted(extracted_blocks.items()):
        label = f"函数范围: L{start}-L{end}" if block["is_func"] else f"周围代码: L{start}-L{end}"
        annotated_lines = []
        for i, line in enumerate(block["code"].split('\n'), start=start):
            marker = "  ← 命中" if i in block["hits"] else ""
            annotated_lines.append(f"  L{i}: {line}{marker}")
        parts.append(
            f"### 文件: {rel_path}  |  {label}\n" + '\n'.join(annotated_lines)
        )

    # 追加文件尾部：若提取块未覆盖文件尾部 80%，追加最后 25 行
    if extracted_blocks:
        max_end = max(end for _, end in extracted_blocks.keys())
        if max_end < len(all_lines) * 0.8 and len(all_lines) > 25:
            tail_start = max(max_end + 1, len(all_lines) - 25)
            tail_lines = all_lines[tail_start:]
            annotated_tail = [f"  L{tail_start + i}: {line}" for i, line in enumerate(tail_lines)]
            parts.append(
                f"### 文件: {rel_path}  |  文件尾部 (L{tail_start + 1}-L{len(all_lines)})\n"
                + '\n'.join(annotated_tail)
            )

    return '\n\n'.join(parts)


def analyze_vulnerability_pattern(
    base_url: str, api_key: str, model: str,
    component: str, used_version: str, vuln_version: str,
    cve_id: str, description: str,
    call_sites: Dict[str, List[Tuple[int, str]]],
    repo_path: Optional[Path] = None,
    log_dir: Optional[Path] = None,
    repo_name: str = "",
    checkpoints: Optional[dict] = None,
) -> Optional[dict]:
    """用 LLM 分析 CVE 描述和当前调用代码，预测漏洞注入方案。返回 JSON dict 或 None。

    若提供 checkpoints，会在 prompt 中嵌入结构化信息（safe_condition、match_terms 等），
    替代原始 description[:2000]。"""
    if not (base_url and api_key and model):
        return None

    # 构建调用点上下文：传入完整函数源码而不只是命中行
    file_limit = 5  # 最多传 5 个文件
    line_limit = 80  # 每个文件最多取 80 个命中行（用于去重前）
    context_parts = []
    for fpath, lines in list(call_sites.items())[:file_limit]:
        # 判断语言
        language = "java" if fpath.endswith('.java') else "python"

        # 尝试提取完整函数上下文
        func_ctx = _extract_function_context(repo_path, fpath, lines[:line_limit], language) if repo_path else ""

        if func_ctx:
            context_parts.append(func_ctx)
        else:
            # 回退：只传命中行（原逻辑）
            fallback_lines = []
            fallback_lines.append(f"\n### 文件: {fpath}")
            for ln, code in lines[:line_limit]:
                fallback_lines.append(f"  L{ln}: {code}")
            context_parts.append('\n'.join(fallback_lines))

    call_site_text = '\n\n'.join(context_parts)

    if not call_site_text:
        return None

    # 构建 CVE 信息块：优先用结构化 checkpoints，否则回退到原始描述
    if checkpoints:
        safe_cond = checkpoints.get("safe_condition", "")
        preconditions = checkpoints.get("preconditions", [])
        match_terms = checkpoints.get("match_terms", {})
        version_constraint = checkpoints.get("version_constraint", {})
        cp_list = checkpoints.get("check_points", [])

        cve_info_parts = []
        if safe_cond:
            cve_info_parts.append(f"**安全条件**: {safe_cond}")
        if version_constraint:
            cve_info_parts.append(
                f"**版本范围**: ecosystem={version_constraint.get('ecosystem', '')}, "
                f">= {version_constraint.get('introduced', '?')}, "
                f"< {version_constraint.get('fixed', '?')}"
            )
        if preconditions:
            cve_info_parts.append(f"**前置条件**: {'; '.join(preconditions)}")
        # check_points 按 priority 分等级选取: critical > high > medium
        priority_order = {"critical": 0, "high": 1, "medium": 2}
        sorted_cps = sorted(cp_list, key=lambda cp: priority_order.get(cp.get("priority", ""), 99))
        for cp in sorted_cps:
            pid = cp.get("id", "")
            priority = cp.get("priority", "")
            q = cp.get("question", "")
            htc = cp.get("how_to_check", "")
            pc = cp.get("pass_condition", "")
            if q:
                cve_info_parts.append(f"**检查点[{priority}] {pid}**: {q} | 如何检查: {htc} | 通过条件: {pc}")
        if match_terms.get("modules"):
            cve_info_parts.append(f"**受影响模块**: {', '.join(match_terms['modules'])}")
        if match_terms.get("config_keys"):
            cve_info_parts.append(f"**相关配置项**: {', '.join(match_terms['config_keys'])}")
        if match_terms.get("concepts"):
            cve_info_parts.append(f"**漏洞概念**: {', '.join(match_terms['concepts'])}")

        cve_info_block = "\n".join(cve_info_parts) if cve_info_parts else description[:2000]
    else:
        cve_info_block = description[:2000]

    prompt = (
        "你是一位安全研究员，负责分析 CVE 漏洞并找到项目中可利用的注入点。\n\n"
        f"**CVE 编号**: {cve_id}\n"
        f"**组件**: {component}\n"
        f"**当前使用版本**: {used_version}\n"
        f"**最后漏洞版本**: {vuln_version}\n\n"
        f"**CVE 信息**:\n{cve_info_block}\n\n"
        f"**项目中对 {component} 的实际调用代码（含完整函数上下文，标注了 ← 命中的行）**:\n{call_site_text}\n\n"
        "## 任务：先分类，再执行\n\n"
        "### 第一步：判定场景（status 字段）\n"
        "根据以上代码和 CVE 信息，判断属于以下哪种场景：\n\n"
        f"1. **already_vulnerable**：代码中**已经存在**有漏洞的 API 调用模式（如 yaml.full_load()、eval() 等危险函数），无需修改即存在漏洞\n"
        f"2. **injectable**：代码中有该组件实际 API 调用，可修改调用参数/替换危险 API 或补充不安全参数来构造漏洞。禁止凭空插入新代码段。\n"
        f"3. **not_injectable**：漏洞机制无法通过源码层注入（如 C 层内存 bug、纯运行时配置、依赖版本本身的二进制漏洞等）\n\n"
        "### 第二步：根据场景执行\n\n"
        "- **already_vulnerable**：modifications 为空数组，在 already_vulnerable_details 中描述已有漏洞代码的位置和调用方式\n"
        "- **injectable**：给出具体修改方案，old_code 从提供的代码中逐字符复制，new_code 为修改/插入后的代码\n"
        "- **not_injectable**：modifications 为空数组\n\n"
        "**重要提示**:\n"
        "- old_code 必须从提供的代码上下文中**逐字符复制**，包括所有空格、缩进、换行符，不得自行简化或改写\n"
        "- new_code 必须包含 old_code 的全部原有内容（插入场景）或替换原有内容（修改场景）\n"
        "- 如果无法精确定位 old_code，将 status 设为 not_injectable\n\n"
        "请只回复 JSON，格式如下：\n"
        "```json\n"
        "{{\n"
        '  "vulnerable_api": ["api1", "api2"],\n'
        '  "cve_summary_short": "一句话描述该CVE的漏洞机制",\n'
        '  "status": "already_vulnerable | injectable | not_injectable",\n'
        '  "already_vulnerable_details": "已有漏洞位置描述（仅 status=already_vulnerable 时填写，其他场景为空字符串）",\n'
        '  "modifications": [\n'
        '    {{"file": "相对路径", "line": 行号, "old_code": "原始代码（锚点）", "new_code": "修改后代码（锚点+新代码）", "reason": "修改理由"}}\n'
        '  ]\n'
        "}}\n"
        "```\n"
        "注意：modifications 中 old_code 和 new_code 必须是完整的单行或多行代码，可直接用于字符串替换。"
    )

    url = base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a precise security vulnerability researcher. Reply JSON only."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0,
    }
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
    response_text = ""

    # 写日志
    log_record = {
        "cve_id": cve_id,
        "component": component,
        "used_version": used_version,
        "vuln_version": vuln_version,
        "prompt": prompt,
        "response_raw": None,
        "parsed": None,
        "error": None,
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
        response_text = response.text or ""
        response.raise_for_status()
        data = response.json()
        content = data["choices"][0]["message"]["content"]
        log_record["response_raw"] = content
        stripped = re.sub(r"^```(?:json)?\s*", "", content.strip(), flags=re.IGNORECASE)
        stripped = re.sub(r"\s*```$", "", stripped)
        parsed = json.loads(stripped)
        log_record["parsed"] = parsed
        return parsed
    except Exception as exc:
        details = f" response_text={response_text[:500]}" if response_text else ""
        log_record["error"] = f"{exc}{details}"
        log_record["response_raw"] = response_text[:2000] if response_text else None
        LOGGER.warning("LLM analysis failed for %s: %s%s", cve_id, exc, details)
        return None
    finally:
        _write_llm_log(log_dir, cve_id, component, repo_name, log_record)


def _write_llm_log(log_dir: Optional[Path], cve_id: str, component: str, repo_name: str, record: dict) -> None:
    """将 LLM 输入输出写入 JSON 文件。"""
    if log_dir is None:
        return
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        # 用 CVE + 组件 + repo 三元组确保不互相覆盖
        safe_cve = cve_id.replace("/", "_").replace(" ", "_")
        safe_comp = component.replace("/", "_").replace(" ", "_")
        safe_repo = repo_name.replace("/", "_").replace(" ", "_")
        log_path = log_dir / f"{safe_cve}__{safe_comp}__{safe_repo}.json"
        log_path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as exc:
        LOGGER.warning("Failed to write LLM log for %s: %s", cve_id, exc)


# ===================================================================
# Step 4: 应用代码修改
# ===================================================================

def apply_injections(repo_path: Path, modifications: List[dict]) -> List[str]:
    """将 LLM 建议的修改应用到文件。返回成功修改的文件路径列表。"""
    modified_files = []
    for mod in modifications:
        file_rel = mod.get("file", "")
        old_code = mod.get("old_code", "")
        new_code = mod.get("new_code", "")
        # 处理 LLM 可能返回绝对路径或已包含 repo_path 前缀的情况
        file_rel = str(file_rel).replace(str(repo_path) + "/", "").replace(str(repo_path), "")
        file_abs = repo_path / file_rel

        if not file_rel or not old_code or old_code == new_code:
            continue
        if not file_abs.exists():
            LOGGER.warning("File not found: %s", file_abs)
            continue

        try:
            content = file_abs.read_text(encoding="utf-8", errors="replace")
            if old_code not in content:
                LOGGER.warning("old_code not found in %s: %s...", file_rel, old_code[:80])
                continue
            new_content = content.replace(old_code, new_code, 1)
            file_abs.write_text(new_content, encoding="utf-8")
            modified_files.append(file_rel)
            LOGGER.info("Modified %s", file_rel)
        except Exception as exc:
            LOGGER.warning("Failed to modify %s: %s", file_rel, exc)

    return modified_files


def _save_patch_and_restore(repo_path: Path, patch_dir: Path, cve_id: str, repo_name: str) -> None:
    """保存当前修改为 patch 文件，然后恢复仓库到干净状态。"""
    try:
        patch_dir.mkdir(parents=True, exist_ok=True)
        safe_cve = cve_id.replace("/", "_").replace(" ", "_")
        safe_repo = repo_name.replace("/", "_").replace(" ", "_")
        patch_path = patch_dir / f"{safe_cve}__{safe_repo}.patch"
        diff_result = subprocess.run(
            ["git", "diff"],
            cwd=str(repo_path), capture_output=True, text=True, timeout=30
        )
        if diff_result.stdout.strip():
            patch_path.write_text(diff_result.stdout, encoding="utf-8")
            LOGGER.info("Saved patch: %s", patch_path)
    except Exception as exc:
        LOGGER.warning("Failed to save patch for %s: %s", cve_id, exc)

    try:
        subprocess.run(
            ["git", "checkout", "."],
            cwd=str(repo_path), capture_output=True, text=True, timeout=30
        )
        LOGGER.info("Restored repo to clean state: %s", repo_path)
    except Exception as exc:
        LOGGER.warning("Failed to git checkout . for %s: %s", repo_path, exc)# ===================================================================
# Step 5: 编译检查
# ===================================================================

def _find_module_root(file_path: Path) -> Optional[Path]:
    """向上查找 Java/Python 模块的根目录（包含 pom.xml 或 build.gradle 或 setup.py）。"""
    current = file_path.parent
    while current != file_path.root:
        for marker in ["pom.xml", "build.gradle", "build.gradle.kts", "setup.py", "pyproject.toml"]:
            if (current / marker).exists():
                return current
        current = current.parent
    return None


def _find_mvn() -> str:
    """查找 mvn 可执行文件，优先用 PATH，否则搜索常见安装位置。"""
    # 先看 PATH
    shutil_mvn = shutil.which("mvn")
    if shutil_mvn:
        return shutil_mvn
    # 搜索 ~ 下的 Maven 安装
    for mvn_dir in sorted(Path.home().glob("apache-maven*"), reverse=True):
        candidate = mvn_dir / "bin" / "mvn"
        if candidate.is_file():
            return str(candidate)
    return "mvn"  # 回退，让 subprocess 报错


def check_compilability(repo_path: Path, modified_files: List[str]) -> Tuple[str, str]:
    """
    检查修改后的代码是否可编译。
    返回 (compilable_status, error_message)
    compilable_status: "yes" / "no" / "partial" / "skipped"
    """
    if not modified_files:
        return "skipped", ""

    # 按语言分组
    java_files = [f for f in modified_files if f.endswith(".java")]
    py_files = [f for f in modified_files if f.endswith(".py")]
    errors = []
    results = []

    # Java: 对每个文件找模块根目录，运行 mvn compile
    checked_modules = set()
    for jf in java_files:
        module_root = _find_module_root(repo_path / jf)
        if module_root is None or str(module_root) in checked_modules:
            continue
        checked_modules.add(str(module_root))

        if (module_root / "pom.xml").exists():
            LOGGER.info("Compiling Maven module: %s", module_root)
            try:
                proc = subprocess.run(
                    [_find_mvn(), "compile", "-q"],
                    cwd=str(module_root), capture_output=True, text=True, timeout=120
                )
                if proc.returncode == 0:
                    results.append("yes")
                else:
                    errors.append(f"Maven {module_root}: {proc.stderr[-500:]}")
                    results.append("no")
            except FileNotFoundError:
                results.append("skipped")
                errors.append("mvn not found")
            except subprocess.TimeoutExpired:
                results.append("skipped")
                errors.append("mvn timeout")
        elif (module_root / "build.gradle").exists() or (module_root / "build.gradle.kts").exists():
            LOGGER.info("Compiling Gradle module: %s", module_root)
            try:
                proc = subprocess.run(
                    ["gradle", "compileJava"],
                    cwd=str(module_root), capture_output=True, text=True, timeout=120
                )
                if proc.returncode == 0:
                    results.append("yes")
                else:
                    errors.append(f"Gradle {module_root}: {proc.stderr[-500:]}")
                    results.append("no")
            except FileNotFoundError:
                results.append("skipped")
                errors.append("gradle not found")
            except subprocess.TimeoutExpired:
                results.append("skipped")
                errors.append("gradle timeout")

    # Python: py_compile 语法检查每个修改的文件
    for pf in py_files:
        py_path = repo_path / pf
        if not py_path.exists():
            continue
        try:
            proc = subprocess.run(
                ["python3", "-m", "py_compile", str(py_path)],
                capture_output=True, text=True, timeout=30
            )
            if proc.returncode == 0:
                results.append("yes")
            else:
                errors.append(f"Python {pf}: {proc.stderr[-300:]}")
                results.append("no")
        except FileNotFoundError:
            results.append("skipped")
            errors.append("python3 not found")
        except subprocess.TimeoutExpired:
            results.append("skipped")

    if not results:
        return "skipped", ""

    if all(r == "yes" for r in results):
        return "yes", ""
    elif all(r == "no" for r in results):
        return "no", " | ".join(errors[:3])
    else:
        return "partial", " | ".join(errors[:3])


# ===================================================================
# Phase 4 主入口
# ===================================================================

def run_phase4(
    match_df: pd.DataFrame,
    vuln_db_path: str,
    cache_dir: Path,
    base_url: str,
    api_key: str,
    model: str,
    dry_run: bool = False,
    repo_limit: int = 0,
    workers: int = 5,
) -> pd.DataFrame:
    """Phase 4 主入口。"""
    # 从 DB 加载 CVE 描述
    conn = sqlite3.connect(vuln_db_path)
    conn.row_factory = sqlite3.Row
    cve_rows = conn.execute("SELECT cve_id, content_preview FROM cve_records").fetchall()
    conn.close()
    desc_map: Dict[str, str] = {r["cve_id"]: (r["content_preview"] or "") for r in cve_rows}
    LOGGER.info("Loaded %d CVE descriptions from DB", len(desc_map))

    # 从 DB 加载结构化 checkpoints（若 cve_checkpoints 表存在）
    cve_checkpoint.init_db(vuln_db_path)
    checkpoints_map = cve_checkpoint.load_all_checkpoints(vuln_db_path)
    LOGGER.info("Loaded %d CVE checkpoints from DB", len(checkpoints_map))

    # 按 repo 分组去重
    unique_repos = match_df[["RepoName", "Tag"]].drop_duplicates()
    unique_repos = unique_repos.sort_values(["RepoName", "Tag"])

    if repo_limit > 0:
        unique_repos = unique_repos.head(repo_limit)
        LOGGER.info("Limited to %d repos", repo_limit)

    LOGGER.info("Total unique repo*Tag combinations to process: %d", len(unique_repos))

    result_rows = []
    repo_processed = 0

    for _, repo_row in unique_repos.iterrows():
        repo_name = str(repo_row["RepoName"])
        tag = str(repo_row["Tag"])
        repo_processed += 1

        LOGGER.info("[%d/%d] Processing repo: %s @ %s", repo_processed, len(unique_repos), repo_name, tag)

        # 1. 克隆
        repo_path = clone_repo(repo_name, tag, cache_dir)
        if (repo_path / "CLONE_FAILED").exists():
            LOGGER.warning("Skip %s @ %s: clone failed", repo_name, tag)
            repo_matches = match_df[(match_df["RepoName"] == repo_name) & (match_df["Tag"] == tag)]
            for _, match in repo_matches.iterrows():
                result_rows.append({
                    "RepoName": repo_name, "Tag": tag,
                    "Component": str(match["Component"]),
                    "UsedVersion": str(match["UsedVersion"]),
                    "CVE": str(match["CVE"]),
                    "VulnerableVersion": str(match.get("VulnerableVersion", "") or ""),
                    "Determination": str(match.get("Determination", "")),
                    "ModifiedFiles": "", "InjectionSummary": "Clone failed",
                    "Compilable": "skipped", "CompileError": "",
                    "Status": "clone_failed",
                })
            continue

        # 2. 获取该 repo 的所有 CVE
        repo_matches = match_df[(match_df["RepoName"] == repo_name) & (match_df["Tag"] == tag)]

        # ---- Phase A: 串行发现调用点（快速 grep + AST）----
        tasks: List[dict] = []  # 需要 LLM 分析的 CVE
        for _, match in repo_matches.iterrows():
            component = str(match["Component"])
            used_version = str(match["UsedVersion"])
            vuln_version = str(match.get("VulnerableVersion", "") or "")
            source_file = str(match.get("SourceFile", ""))
            cve_id = str(match["CVE"])
            determination = str(match.get("Determination", ""))

            call_sites = find_call_sites(repo_path, component, source_file)
            if not call_sites:
                result_rows.append({
                    "RepoName": repo_name, "Tag": tag,
                    "Component": component, "UsedVersion": used_version,
                    "CVE": cve_id, "VulnerableVersion": vuln_version,
                    "Determination": determination,
                    "ModifiedFiles": "", "InjectionSummary": "",
                    "Compilable": "skipped", "CompileError": "",
                    "Status": "no_call_site",
                })
                continue

            LOGGER.info("  Found %d files with call sites for %s", len(call_sites), component)
            description = desc_map.get(cve_id, "")
            checkpoints = checkpoints_map.get(cve_id)
            tasks.append({
                "match": match, "component": component, "used_version": used_version,
                "vuln_version": vuln_version, "cve_id": cve_id,
                "determination": determination, "call_sites": call_sites,
                "description": description, "checkpoints": checkpoints,
            })

        # ---- Phase B: 并行 LLM 分析（主力加速点）----
        if tasks:
            log_dir = cache_dir / "llm_logs"
            max_workers = min(len(tasks), workers) if workers > 0 else min(len(tasks), 5)

            def _llm_task(task):
                """单个 LLM 分析任务（在线程池中执行）"""
                analysis = analyze_vulnerability_pattern(
                    base_url, api_key, model,
                    task["component"], task["used_version"], task["vuln_version"],
                    task["cve_id"], task["description"], task["call_sites"], repo_path,
                    log_dir=log_dir, repo_name=repo_name,
                    checkpoints=task.get("checkpoints"),
                )
                return {**task, "analysis": analysis}

            LOGGER.info("  Submitting %d LLM tasks with %d workers...", len(tasks), max_workers)
            analysis_results: List[dict] = []
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(_llm_task, t): i for i, t in enumerate(tasks)}
                for i, future in enumerate(as_completed(futures), 1):
                    result = future.result()
                    analysis_results.append(result)
                    cve = result["cve_id"]
                    status = result["analysis"].get("status", "") if result["analysis"] else "llm_failed"
                    LOGGER.info("  [%d/%d] LLM done: %s -> %s", i, len(tasks), cve, status)

        else:
            analysis_results = []

        # ---- Phase C: 串行结果处理（apply + compile，避免文件写冲突）----
        for task in analysis_results:
            component = task["component"]
            used_version = task["used_version"]
            vuln_version = task["vuln_version"]
            cve_id = task["cve_id"]
            determination = task["determination"]
            analysis = task["analysis"]

            if analysis is None:
                result_rows.append({
                    "RepoName": repo_name, "Tag": tag,
                    "Component": component, "UsedVersion": used_version,
                    "CVE": cve_id, "VulnerableVersion": vuln_version,
                    "Determination": determination,
                    "ModifiedFiles": "", "InjectionSummary": "LLM analysis failed",
                    "Compilable": "skipped", "CompileError": "",
                    "Status": "llm_failed",
                })
                continue

            status = analysis.get("status", "")
            modifications = analysis.get("modifications", [])
            injection_summary = analysis.get("cve_summary_short", "")
            vulnerable_api = analysis.get("vulnerable_api", [])

            if status == "already_vulnerable":
                result_rows.append({
                    "RepoName": repo_name, "Tag": tag,
                    "Component": component, "UsedVersion": used_version,
                    "CVE": cve_id, "VulnerableVersion": vuln_version,
                    "Determination": determination,
                    "ModifiedFiles": "",
                    "InjectionSummary": analysis.get("already_vulnerable_details", injection_summary),
                    "Compilable": "skipped", "CompileError": "",
                    "Status": "already_vulnerable",
                })
                continue

            if status == "not_injectable":
                result_rows.append({
                    "RepoName": repo_name, "Tag": tag,
                    "Component": component, "UsedVersion": used_version,
                    "CVE": cve_id, "VulnerableVersion": vuln_version,
                    "Determination": determination,
                    "ModifiedFiles": "", "InjectionSummary": injection_summary or f"API: {vulnerable_api}",
                    "Compilable": "skipped", "CompileError": "",
                    "Status": "no_injection_possible",
                })
                continue

            if status == "injectable":
                if not modifications:
                    result_rows.append({
                        "RepoName": repo_name, "Tag": tag,
                        "Component": component, "UsedVersion": used_version,
                        "CVE": cve_id, "VulnerableVersion": vuln_version,
                        "Determination": determination,
                        "ModifiedFiles": "", "InjectionSummary": injection_summary or f"API: {vulnerable_api}",
                        "Compilable": "skipped", "CompileError": "",
                        "Status": "no_injection_possible",
                    })
                    continue

                # 4. 应用修改
                if dry_run:
                    modified_files = [m.get("file", "") for m in modifications]
                    compilable, compile_error = "skipped", "dry_run"
                else:
                    modified_files = apply_injections(repo_path, modifications)
                    # 5. 编译检查
                    compilable, compile_error = check_compilability(repo_path, modified_files)

                if not modified_files:
                    result_rows.append({
                        "RepoName": repo_name, "Tag": tag,
                        "Component": component, "UsedVersion": used_version,
                        "CVE": cve_id, "VulnerableVersion": vuln_version,
                        "Determination": determination,
                        "ModifiedFiles": "", "InjectionSummary": injection_summary,
                        "Compilable": "skipped", "CompileError": "",
                        "Status": "injection_failed",
                    })
                else:
                    result_rows.append({
                        "RepoName": repo_name, "Tag": tag,
                        "Component": component, "UsedVersion": used_version,
                        "CVE": cve_id, "VulnerableVersion": vuln_version,
                        "Determination": determination,
                        "ModifiedFiles": ", ".join(modified_files),
                        "InjectionSummary": injection_summary,
                        "Compilable": compilable, "CompileError": compile_error,
                        "Status": "injected",
                    })

                # 6. 保存 patch + 恢复仓库，避免影响同一 repo 的下一个 CVE 处理
                if not dry_run and modified_files:
                    _save_patch_and_restore(repo_path, cache_dir / "patches", cve_id, repo_name)
                continue

            # 未知 status，视为 no_injection_possible
            result_rows.append({
                "RepoName": repo_name, "Tag": tag,
                "Component": component, "UsedVersion": used_version,
                "CVE": cve_id, "VulnerableVersion": vuln_version,
                "Determination": determination,
                "ModifiedFiles": "", "InjectionSummary": injection_summary or f"API: {vulnerable_api}",
                "Compilable": "skipped", "CompileError": "",
                "Status": "no_injection_possible",
            })

        # 保存中间结果（每处理完一个 repo）
        if result_rows:
            intermediate_df = pd.DataFrame(result_rows)
            intermediate_df.to_excel(cache_dir / "_vuln_injection_progress.xlsx", index=False)

    if result_rows:
        df = pd.DataFrame(result_rows)
    else:
        df = pd.DataFrame(columns=[
            "RepoName", "Tag", "Component", "UsedVersion", "CVE", "VulnerableVersion",
            "Determination", "ModifiedFiles", "InjectionSummary", "Compilable",
            "CompileError", "Status",
        ])

    LOGGER.info("Phase 4 complete: %d total records", len(df))
    return df


# ===================================================================
# 主入口
# ===================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="漏洞注入点预测 (Phase 4)")
    parser.add_argument("--match-file", default="data/cve_match_result.xlsx", help="Phase 3 输出")
    parser.add_argument("--vuln-db", default="vuln_ruler.db", help="漏洞数据库路径")
    parser.add_argument("--cache-dir", default="repos_cache", help="仓库克隆缓存目录")
    parser.add_argument("--output", default="data/vuln_injection_result.xlsx", help="Phase 4 输出")
    parser.add_argument("--base-url", default=os.environ.get("LLM_BASE_URL", ""),
                        help="API base URL（也可用 LLM_BASE_URL 环境变量）")
    parser.add_argument("--api-key", default=os.environ.get("LLM_API_KEY", ""),
                        help="API key（也可用 LLM_API_KEY 环境变量）")
    parser.add_argument("--model", default=os.environ.get("LLM_MODEL", ""),
                        help="模型名（也可用 LLM_MODEL 环境变量）")
    parser.add_argument("--dry-run", action="store_true",
                        help="仅调用 LLM 分析，不实际修改文件和编译")
    parser.add_argument("--repo-limit", type=int, default=0,
                        help="限制处理的 repo 数量（0=全部）")
    parser.add_argument("--workers", type=int, default=5,
                        help="并行 LLM 调用数（默认 5）")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    LOGGER.info("Loading match data from %s", args.match_file)
    match_df = pd.read_excel(args.match_file)
    LOGGER.info("Loaded %d match records", len(match_df))

    cache_dir = Path(args.cache_dir)

    LOGGER.info("==== Phase 4: Vulnerability Injection Point Prediction ====")
    result_df = run_phase4(
        match_df=match_df,
        vuln_db_path=args.vuln_db,
        cache_dir=cache_dir,
        base_url=args.base_url,
        api_key=args.api_key,
        model=args.model,
        dry_run=args.dry_run,
        repo_limit=args.repo_limit,
        workers=args.workers,
    )
    result_df.to_excel(args.output, index=False)
    LOGGER.info("Phase 4 output written to %s (%d rows)", args.output, len(result_df))

    # 统计
    if not result_df.empty:
        LOGGER.info("=== Summary ===")
        for status in ["injected", "already_vulnerable", "injection_failed",
                       "no_injection_possible", "no_call_site", "llm_failed",
                       "clone_failed"]:
            count = (result_df["Status"] == status).sum()
            if count > 0:
                LOGGER.info("  %s: %d", status, count)
        injected = result_df[result_df["Status"] == "injected"]
        if not injected.empty:
            comp_counts = injected["Compilable"].value_counts().to_dict()
            for k, v in comp_counts.items():
                LOGGER.info("  compilable=%s: %d", k, v)


if __name__ == "__main__":
    main()
