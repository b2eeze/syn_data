## 项目结构

```
syn_data/
├── dep_analyzer.py              # Phase 1: 依赖提取（扫描仓库依赖文件，提取目标组件版本）
├── cve_version_extractor.py     # Phase 2: CVE版本提取（从描述中提取最后有漏洞的版本号）
├── cve_matcher.py               # Phase 3: CVE匹配（依赖版本 vs 漏洞版本）
├── vuln_injector.py             # Phase 4: 漏洞注入（克隆→搜索调用点→LLM分析→修改→编译）
├── cve_checkpoint.py            # 工具: CVE结构化checkpoint提取 + L0-L3多粒度描述
├── recompile_injected.py        # 工具: 重新编译已注入结果
├── crawl_top_repos.py           # 工具: 爬取GitHub Top项目
├── view_vuln_db.py              # 工具: 查看数据库内容
├── data/
│   ├── uncovered_library_cves.xlsx   # 目标组件列表（20个，含CVE列表）← 流水线入口
│   ├── github_top_repos.xlsx         # 仓库列表
│   ├── dep_scan_result.xlsx          # Phase 1 输出
│   ├── cve_version_result.xlsx       # Phase 2 输出
│   ├── cve_match_result.xlsx         # Phase 3 输出 → Phase 4 输入
│   └── vuln_injection_result.json    # Phase 4 输出
├── vuln_ruler_filtered.db        # CVE数据库(content_preview) ← Phase 2/3/4用
├── repos_cache/                  # 仓库克隆缓存 + 进度断点
└── workflow_cache/               # API响应缓存
```

## 脚本说明

### Phase 1: `dep_analyzer.py` — 依赖提取

1. 从 `uncovered_library_cves.xlsx` 读取目标组件列表，通过硬编码的 Maven 坐标映射表查找 Java 组件的 group_id:artifact_id
2. 从仓库列表 Excel 读取仓库，通过 GitHub API 获取最近 N 个 tag
3. 对每个 tag 通过 GitHub Trees API 拉取文件树，筛选依赖清单文件：

| 语言 | 文件类型 | 解析方式 |
|------|----------|----------|
| Python | requirements.txt, setup.py, setup.cfg, pyproject.toml, Pipfile, Pipfile.lock, poetry.lock, pdm.lock, environment.yml, tox.ini | 正则匹配 + TOML 段解析 |
| Java | pom.xml, build.gradle, build.gradle.kts, settings.gradle, gradle.properties, build.xml, ivy.xml | Maven 坐标正则 + Gradle 依赖正则 + POM 属性继承 |
| JavaScript | package.json | 解析 dependencies / devDependencies |
| Rust | Cargo.toml | 解析 [dependencies] |

4. 通过 GitHub Raw API 下载依赖文件内容（本地 `workflow_cache/` 缓存），匹配目标组件并提取版本号
5. 输出 `dep_scan_result.xlsx`：仓库名、Tag、组件名、版本号、来源文件

### Phase 2: `cve_version_extractor.py` — CVE版本提取

1. 从 `uncovered_library_cves.xlsx` 读取 target_name → cve_list 映射
2. 从 `vuln_ruler_filtered.db` 获取 CVE 的 `content_preview`（CVE描述文本）
3. 对每条 CVE 描述用版本范围正则提取**最后一个有漏洞的版本号**：
   - `START_BEFORE_RANGE_REGEX`：`starting in version X and prior to Y`
   - `GENERIC_BOUNDED_RANGE_REGEX`：`from X through Y`
   - `BRANCH_BEFORE_REGEX`：`X.x before Y`
   - `GENERIC_UPPER_BOUND_REGEX`：`before/prior to/through/up to Y`
4. 正则未命中时可启用 LLM 兜底
5. 按 `(CVE编号, 组件名)` 去重
6. 输出 `cve_version_result.xlsx`：CVE编号、组件名、最后有漏洞版本号、提取方式

### Phase 3: `cve_matcher.py` — CVE匹配

1. 读取 Phase 1 输出 `dep_scan_result.xlsx`
2. 读取 Phase 2 输出 `cve_version_result.xlsx`
3. 对每条（仓库名, Tag, 组件名, 版本号）：
   - 在 CVE 列表中按组件名匹配（精确或相互包含）
   - 版本比较：`compare_versions(dep_version, last_vuln_version)`

     | 比较结果 | Determination | 含义 |
     |---------|--------------|------|
     | dep <= vuln | `regex` / `version_cmp_regex` | 版本在受影响范围内，可能受影响 |
     | dep > vuln | `version_above_vuln` | 版本已高于漏洞版本，但仍可通过降级 API 调用模式注入漏洞 |
     | 无版本号 | `llm` | Phase 2 未提取到版本号，LLM 根据 CVE 描述判断（需传 LLM 参数） |

4. 输出 `cve_match_result.xlsx`

### Phase 4: `vuln_injector.py` — 漏洞注入

1. **克隆仓库**：浅克隆到 `repos_cache/<owner/repo>/<tag>/`，支持 GitHub/gitee
2. **发现调用点**：grep 搜索组件 import 行 → Python AST / Java javalang AST 精确认证实际 API 调用
3. **LLM 分析**：传入 CVE 结构化 checkpoint + 调用点上下文，判断注入场景，并给出判断理由：
   - `already_vulnerable`：代码已存在有漏洞的 API 调用
   - `injectable`：存在同类 API 可替换为漏洞版本（如 `safe_load()` → `full_load()`）
   - `not_injectable`：无可用注入点
4. **应用修改**：对 injectable 的 CVE 原地替换代码
5. **编译检查**：Java 用 mvn/gradle compile，Python 用 py_compile 语法检查

   编译环境要求：

   | 需求 | 说明 |
   |------|------|
   | Maven | `mvn` 在 PATH，或 `~/apache-maven*/bin/mvn` |
   | Gradle | 优先项目自带 `gradlew`（零配置）；无 `gradlew` 时需 `gradle` 在 PATH |
   | JDK | `java` 在 PATH，多版本 JDK 放在 `~/.sdkman/candidates/java/`（自动切换） |
   | Python | `python3` 在 PATH |
6. **保存 patch + 还原仓库**：`git diff` → patch 文件 → `git checkout .`
7. 支持断点续传（`repos_cache/_vuln_injection_progress.json`）

---

## 输出文件

| 文件 | 阶段 | 内容 |
|------|------|------|
| `data/dep_scan_result.xlsx` | Phase 1 | 仓库名、Tag、组件名、版本号、来源文件 |
| `data/cve_version_result.xlsx` | Phase 2 | CVE编号、组件名、最后有漏洞版本、提取方式 |
| `data/cve_match_result.xlsx` | Phase 3 | 仓库名、Tag、组件名、使用版本、CVE、有漏洞版本、判定方式 |
| `result/vuln_injection_result_*.json` | Phase 4 | 注入结果：ModifiedFiles、PatchFile、Compilable、Status 等 |

---

## 运行方法

### 前置准备

```bash
pip install pandas openpyxl requests javalang
```

### Phase 1: 依赖提取

```bash
python dep_analyzer.py \
  --github-token "$GITHUB_TOKEN" \
  --targets-xlsx data/uncovered_library_cves.xlsx \
  --repos-excel data/github_top_repos.xlsx \
  --top-tags 5 \
  --repo-limit 5 \
  --output data/dep_scan_result.xlsx
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--github-token` | (空) | GitHub API Token，**必需** |
| `--targets-xlsx` | `data/uncovered_library_cves.xlsx` | 目标组件列表 |
| `--repos-excel` | `data/github_top_repos.xlsx` | 仓库列表 |
| `--top-tags` | 0 | 每个仓库分析的 tag 数（0=全部） |
| `--repo-limit` | 0 | 限制仓库数（0=全部） |
| `--workers` | 5 | 并发 worker 数 |
| `--cache-dir` | `workflow_cache` | 本地缓存目录 |
| `--output` | `data/dep_scan_result.xlsx` | 输出路径 |

### Phase 2: CVE版本提取

```bash
python cve_version_extractor.py \
  --targets-xlsx data/uncovered_library_cves.xlsx \
  --vuln-db vuln_ruler_filtered.db \
  --output data/cve_version_result.xlsx

# 启用 LLM 兜底（提取正则未覆盖的版本号）
python cve_version_extractor.py \
  --base-url "https://api.xxx.com/v1" \
  --api-key "sk-xxx" \
  --model "deepseek-v4-pro"
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--targets-xlsx` | `data/uncovered_library_cves.xlsx` | 目标+CVE列表 |
| `--vuln-db` | `vuln_ruler_filtered.db` | CVE描述数据源 |
| `--output` | `data/cve_version_result.xlsx` | 输出路径 |
| `--base-url` | 环境变量 `LLM_BASE_URL` | LLM API地址 |
| `--api-key` | 环境变量 `LLM_API_KEY` | LLM API Key |
| `--model` | 环境变量 `LLM_MODEL` | LLM 模型名 |

### Phase 3: CVE匹配

```bash
python cve_matcher.py \
  --dep-file data/dep_scan_result.xlsx \
  --cve-file data/cve_version_result.xlsx \
  --output data/cve_match_result.xlsx

# 启用 LLM 边界判断
python cve_matcher.py \
  --openai-base-url "https://api.xxx.com/v1" \
  --openai-api-key "sk-xxx" \
  --openai-model "deepseek-v4-pro"
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--dep-file` | `data/dep_scan_result.xlsx` | Phase 1 输出 |
| `--cve-file` | `data/cve_version_result.xlsx` | Phase 2 输出 |
| `--output` | `data/cve_match_result.xlsx` | Phase 3 输出 |
| `--openai-base-url` | (空) | LLM API地址 |
| `--openai-api-key` | (空) | LLM API Key |
| `--openai-model` | (空) | LLM 模型名 |

### Phase 4: 漏洞注入

```bash
# dry-run: 修改代码 + 生成patch + 还原，跳过编译
python vuln_injector.py \
  --base-url "https://api.xxx.com/v1" \
  --api-key "sk-xxx" \
  --model "deepseek-v4-pro" \
  --repo-limit 3 --dry-run

# 完整运行: 修改 + 编译 + patch
python vuln_injector.py \
  --base-url "https://api.xxx.com/v1" \
  --api-key "sk-xxx" \
  --model "deepseek-v4-pro" \
  --repo-limit 3
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--match-file` | `data/cve_match_result.xlsx` | Phase 3 输出 |
| `--vuln-db` | `vuln_ruler_filtered.db` | CVE描述数据源 |
| `--cache-dir` | `repos_cache` | 仓库克隆缓存 |
| `--output` | `result/vuln_injection_result_<时间戳>.json` | 输出路径 |
| `--base-url` | 环境变量 `LLM_BASE_URL` | LLM API地址 |
| `--api-key` | 环境变量 `LLM_API_KEY` | LLM API Key |
| `--model` | 环境变量 `LLM_MODEL` | LLM 模型名 |
| `--dry-run` | (flag) | 修改代码+生成patch+还原，跳过编译 |
| `--repo-limit` | 0 | 限制repo数（0=全部） |
| `--workers` | 5 | LLM并发数 |
| `--repo-workers` | 1 | repo级并发数 |

### 全量一键

```bash
python dep_analyzer.py --github-token "$GITHUB_TOKEN" && \
python cve_version_extractor.py && \
python cve_matcher.py && \
python vuln_injector.py --base-url "..." --api-key "..." --model "..."
```

### 辅助工具

```bash
# CVE Checkpoint 提取
python cve_checkpoint.py --batch --workers 10           # 批量提取
python cve_checkpoint.py --cve CVE-2020-14343 --detail 3 # L3完整描述

# 重新编译已注入结果
python recompile_injected.py --input result/xxx_injected.json

# 爬取GitHub Top项目
python crawl_top_repos.py --count 100

# 查看数据库
python view_vuln_db.py overview
python view_vuln_db.py cve CVE-2024-1234
```

## 环境变量

| 变量 | 用途 |
|------|------|
| `GITHUB_TOKEN` | GitHub API Token（Phase 1 必需） |
| `LLM_BASE_URL` | LLM API 地址（Phase 2/4 可选） |
| `LLM_API_KEY` | LLM API Key |
| `LLM_MODEL` | LLM 模型名 |
