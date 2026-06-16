# Phase 4: 漏洞注入点预测 — Implementation Plan

## Overview

对于 Phase 3 产出的每一条 CVE 匹配结果，找到仓库中该组件的实际调用位置，利用 LLM 分析漏洞版本 API 的调用模式，将项目中的代码修改为有漏洞版本的调用方式，并检查可否编译。

## Input
- `cve_match_result.xlsx`（475 行，12 repos，116 CVEs）
- `vuln_ruler.db`（CVE 描述数据）
- GitHub API token（用于 clone repos）

## Output
- `vuln_injection_result.xlsx`，列：
  - `RepoName`, `Tag`, `Component`, `UsedVersion`, `CVE`, `VulnerableVersion`
  - `ModifiedFiles` — 被修改的文件路径列表
  - `InjectionSummary` — LLM 判断的漏洞调用模式简述
  - `Compilable` — `yes` / `no` / `partial` / `skipped`
  - `CompileError` — 编译错误摘要（如有）
  - `Status` — `injected` / `no_call_site` / `no_injection_pattern` / `error`

## 整体流程

```
cve_match_result.xlsx
       |
       v
[1] Clone repo at Tag (cached under repos_cache/<name>/<tag>)
       |
       v
[2] Find call sites: grep for component imports/usages
       |
       v
[3] LLM analyzes CVE desc + call sites → predicts vulnerable API pattern
       |
       v
[4] LLM modifies call sites to match vulnerable version's API
       |
       v
[5] Check compilability (mvn/gradle for Java, py_compile for Python)
       |
       v
vuln_injection_result.xlsx
```

## 详细设计

### Step 1: Repo 克隆与缓存

文件: `vuln_injector.py`

```python
# 从 GitHub 的 openharmony 组织克隆，使用 --depth 1 --branch <tag>
# 缓存: repos_cache/<repo_name>/<tag>/
clone_repo(repo_name, tag) -> Path
```

- 先检查 `repos_cache/<repo_name>/<tag>/.git` 是否已存在
- 若不存在，执行 `git clone --depth 1 --branch <tag> https://github.com/openharmony/<repo_name>.git repos_cache/<repo_name>/<tag>`
- 若 repo 已存在但不同 tag，增量 fetch

### Step 2: 发现调用点 (Find Call Sites)

并非完整的 VulnTriage VFind+Trace 管线（过于复杂）。针对 Phase 4 目标做简化：

**目标**：定位 repo 中所有 import/调用目标组件的位置

**策略**：
- **Java 组件**（Jackson, Log4j, Apache Commons 等）：
  1. 用 grep 搜索 `import <package>` 语句找到所有 import 该组件的 .java 文件
  2. 对找到的文件，提取该组件类的所有方法调用、字段访问、注解使用
  3. 返回 `{file_path: [(line_no, code_snippet), ...]}`

- **Python 组件**（urllib3, NumPy, SciPy, Pillow 等）：
  1. 用 grep 搜索 `import <module>` / `from <module> import` 找到使用该组件的 .py 文件
  2. 提取函数调用、方法调用、属性访问
  3. 返回 `{file_path: [(line_no, code_snippet), ...]}`

**实现**：
```python
def find_call_sites(repo_path, component_name, language) -> dict:
    """返回 {file_path: [(line_no, code_snippet), ...]}"""
    # 使用组件名到 import 路径的映射表
```

**组件→import 映射表**（基于常见开源项目的 import 模式）：
| Component | Java import pattern | Python import pattern |
|-----------|-------------------|----------------------|
| Jackson | `com.fasterxml.jackson` | — |
| Log4j | `org.apache.logging.log4j` | — |
| Apache Commons IO | `org.apache.commons.io` | — |
| Apache Commons FileUpload | `org.apache.commons.fileupload` | — |
| Apache Commons BeanUtils | `org.apache.commons.beanutils` | — |
| urllib3 | — | `urllib3` |
| NumPy | — | `numpy` |
| SciPy | — | `scipy` |
| Pillow | — | `PIL`, `Pillow` |
| PyYAML | — | `yaml` |
| joblib | — | `joblib` |

### Step 3: LLM 分析漏洞调用模式

对每个 CVE：
1. 从 `vuln_ruler.db` 获取 `content_preview`（CVE 描述）
2. 将当前代码的调用点（call sites）传给 LLM
3. LLM 分析该 CVE 涉及的 API，判断现有的调用代码是否已经是"有漏洞的调用模式"

**Prompt 设计**：
```
你是一位安全研究员。给定一个 CVE 描述和一个项目中对漏洞组件的实际调用代码，请判断：

1. 该 CVE 描述的漏洞涉及哪些具体的 API 方法/类/函数？
2. 项目当前的调用代码是否可被修改为触发该漏洞的调用模式？
3. 如果可以，给出每个调用点的修改方案（旧代码 → 新代码）。
4. 如果当前的调用代码不涉及该漏洞的 API surface，返回 "no_injection_pattern"。

输出 JSON:
{
  "vulnerable_api": ["method1", "method2"],
  "injection_possible": true/false,
  "modifications": [
    {"file": "path", "line": 10, "old_code": "...", "new_code": "...", "reason": "..."}
  ]
}
```

### Step 4: 修改代码

- 对 LLM 给出的每个 modification，原地替换文件中的代码
- 记录 `old_code` 和 `new_code`，备份原始文件
- 如果 LLM 返回 `no_injection_pattern`，跳过该 CVE

### Step 5: 检查可编译性

- **Java (Maven)**：`mvn compile -q` 在包含 pom.xml 的模块目录运行
- **Java (Gradle)**：`gradle compileJava` 在对应模块
- **Python**：`python -m py_compile <modified_file.py>` 逐个检查语法

如果编译失败：
- 记录编译错误的前 500 字符
- `Compilable` 标记为 `no`
- 不尝试修复（保持修改记录的原始状态）

### Step 6: 汇总输出

按 CVE 聚合结果，每个 `(repo, tag, component, cve)` 一行，包含：
- 修改了哪些文件
- 注入的漏洞模式简述
- 是否可编译

---

## 文件结构

新增一个独立脚本：

```
/data1/czc/projects/huawei/syn_data/vuln_injector.py   # Phase 4 主脚本
```

## CLI 参数

```
python vuln_injector.py \
  --match-file cve_match_result.xlsx \
  --vuln-db vuln_ruler.db \
  --cache-dir repos_cache \
  --output vuln_injection_result.xlsx \
  --base-url "https://api.deepseek.com" \
  --api-key "sk-xxx" \
  --model "deepseek-v4-pro" \
  --dry-run          # 可选：只看分析结果，不实际修改文件
  --repo-limit 3     # 可选：限制处理几个 repo
```

## 风险与限制

1. **Clone 耗时**：每个 repo 需要几分钟
2. **LLM 成本**：475 条 × 每条一次 LLM 调用 → 大量 token
3. **代码修改质量**：LLM 可能产生不可编译或不合理的修改
4. **大部分匹配可能是 no_call_site**：
   - 很多 repo 是第三方库的简单镜像（如 `third_party_json`），项目自身代码很少调用这些库
   - `global_i18n_lite` 的 Jackson 使用在 pom.xml 中声明的依赖，但实际 .java 可能只有少量调用
5. **编译环境依赖**：OpenHarmony 的 Java 模块可能依赖大量内部库，单独 mvn compile 可能导致环境依赖失败
6. Python 项目只做语法检查，不运行

## 实现顺序

1. `vuln_injector.py` 框架：参数解析、数据加载、主循环
2. `clone_repo()` — Git 操作与缓存
3. `find_call_sites()` — grep-based 调用点发现（Java + Python）
4. `analyze_vulnerability_pattern()` — LLM 分析
5. `apply_injections()` — 代码修改
6. `check_compilability()` — 编译检查
7. 输出与统计
