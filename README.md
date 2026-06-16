
## 脚本说明

### 脚本 1：`dep_analyzer.py` — Phase 1 + 2

#### Phase 1：依赖提取

1. 从 `openharmony_repos.xlsx` 读取仓库列表，解析出 `owner/repo`（如 `openharmony/ai_engine`）
2. 对每个仓库，通过 GitHub Tags API 获取最近 N 个 tag（默认 top 3，可通过 `--top-tags` 配置）
3. 对每个 tag，通过 GitHub Trees API（`?recursive=1`）一次拉取完整文件树
4. 筛选依赖清单文件，支持多种语言：

| 语言 | 文件类型 | 解析方式 |
|------|----------|----------|
| Python | requirements.txt, setup.py, setup.cfg, pyproject.toml, Pipfile, Pipfile.lock, poetry.lock, pdm.lock, environment.yml, tox.ini | 正则匹配版本号 + TOML 段解析 |
| Java | pom.xml, build.gradle, build.gradle.kts, settings.gradle, gradle.properties, build.xml, ivy.xml | Maven 坐标正则 + Gradle 依赖正则 + POM 属性继承 |
| JavaScript | package.json | 解析 dependencies / devDependencies 块 |
| Rust | Cargo.toml | 解析 [dependencies] 段 |

5. 通过 GitHub Raw API 下载依赖文件内容（本地 `workflow_cache/` 缓存），解析出目标组件的版本号
6. 目标组件 = vuln_ruler.db 中 40 个 targets（24 个 Java 组件 + 16 个 Python 组件）
7. 输出 `dep_scan_result.xlsx`：仓库名、Tag、组件名、版本号、来源文件

#### Phase 2：CVE 版本提取

1. 从 `vuln_ruler.db` 读取所有 CVE 记录，按 `target_id` 关联组件名
2. 对每条 CVE 的 `content_preview`，用版本范围正则提取**最后一个有漏洞的版本号**：
   - `START_BEFORE_RANGE_REGEX`：`starting in version X and prior to Y`
   - `GENERIC_BOUNDED_RANGE_REGEX`：`from X through Y`
   - `BRANCH_BEFORE_REGEX`：`X.x before Y`
   - `GENERIC_UPPER_BOUND_REGEX`：`before/prior to/through/up to Y`
3. 按 `(CVE编号, 组件名)` 去重
4. 正则兜底：对未提取到版本的 CVE，可使用 LLM（OpenAI 兼容 API）解析版本范围
5. 输出 `cve_version_result.xlsx`：CVE编号、组件名、最后有漏洞版本号、提取方式

**Phase 2 运行结果：**
- 去重后唯一 CVE：1238 条
- 通过正则提取到版本号：487 条（39%）
- 未提取到版本号：751 条

### 脚本 2：`cve_matcher.py` — Phase 3

1. 读取 Phase 1 输出 `dep_scan_result.xlsx`
2. 读取 Phase 2 输出 `cve_version_result.xlsx`
3. 对每条（仓库名, Tag, 组件名, 版本号）：
   - 在 CVE 列表中按组件名匹配（精确或相互包含）
   - 版本比较：`dependency_version <= last_vulnerable_version` → 潜在受影响
   - 三级判定方式：
     - **regex**：版本号在 CVE 描述中被范围正则确认 → 高置信度
     - **version_cmp_regex**：版本比较命中，但描述中的范围正则未直接确认 → 中置信度
     - **uncertain**：无版本范围可用，也未配置 LLM 兜底 → 低置信度
   - LLM 兜底：可用时调用 `call_openai_judge` 判断边界情况
4. 输出 `cve_match_result.xlsx`：仓库名、Tag、组件名、使用版本、来源文件、CVE编号、有漏洞版本、判定方式

## 输出文件

| 文件 | 阶段 | 内容 |
|------|------|------|
| `dep_scan_result.xlsx` | Phase 1 | 仓库名、Tag、组件名、版本号、来源文件 |
| `cve_version_result.xlsx` | Phase 2 | CVE编号、组件名、最后有漏洞版本上限、提取方式 |
| `cve_match_result.xlsx` | Phase 3 | 仓库名、Tag、组件名、使用版本、来源文件、CVE编号、有漏洞版本、判定方式 |

## 命令行参数

### dep_analyzer.py

```
python3 dep_analyzer.py [OPTIONS]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--github-token` | (空) | GitHub API Token（**必需**，否则限速 60次/小时） |
| `--top-tags` | 3 | 每个仓库分析的 tag 数量 |
| `--repo-limit` | 0 | 限制分析的仓库数量（0 = 全部 499 个） |
| `--openai-base-url` | (空) | LLM API base URL（可选，用于 Phase 2 版本提取兜底） |
| `--openai-api-key` | (空) | LLM API key |
| `--openai-model` | (空) | LLM 模型名，例如 `gpt-4o-mini` |
| `--cache-dir` | `workflow_cache` | 本地缓存目录 |
| `--repos-excel` | `openharmony_repos.xlsx` | 仓库列表 Excel 路径 |
| `--vuln-db` | `vuln_ruler.db` | 漏洞数据库路径 |
| `--output-dep` | `dep_scan_result.xlsx` | Phase 1 输出路径 |
| `--output-cve` | `cve_version_result.xlsx` | Phase 2 输出路径 |
| `--skip-phase1` | (flag) | 跳过 Phase 1，只运行 Phase 2 |
| `--skip-phase2` | (flag) | 跳过 Phase 2，只运行 Phase 1 |

### cve_matcher.py

```
python3 cve_matcher.py [OPTIONS]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--dep-file` | `dep_scan_result.xlsx` | Phase 1 输出文件路径 |
| `--cve-file` | `cve_version_result.xlsx` | Phase 2 输出文件路径 |
| `--output` | `cve_match_result.xlsx` | Phase 3 输出文件路径 |
| `--openai-base-url` | (空) | LLM API base URL（可选，用于边界判断兜底） |
| `--openai-api-key` | (空) | LLM API key |
| `--openai-model` | (空) | LLM 模型名 |

## 运行方法

### 1. 前置准备

确保 Python 依赖已安装：

```bash
pip install pandas openpyxl requests
```

### 2. 小范围验证（推荐首次运行）

用少量仓库和单个 tag 验证全流程：

```bash
# 设置 GitHub Token（替换为你的 token）
export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"

# Phase 1 + 2：扫描 5 个仓库，每个只看 1 个 tag
python3 dep_analyzer.py \
  --github-token "$GITHUB_TOKEN" \
  --top-tags 1 \
  --repo-limit 5

# Phase 3：匹配
python3 cve_matcher.py
```

### 3. 全量运行

```bash
# Phase 1 + 2：扫描全部 499 个仓库，每个取最近 3 个 tag
python3 dep_analyzer.py \
  --github-token "$GITHUB_TOKEN" \
  --top-tags 3

# Phase 3：匹配
python3 cve_matcher.py
```

### 4. 分阶段运行

```bash
# 只运行 Phase 1（依赖提取）
python3 dep_analyzer.py --github-token "$GITHUB_TOKEN" --skip-phase2

# 只运行 Phase 2（CVE 版本提取，不需要 GitHub Token）
python3 dep_analyzer.py --skip-phase1

# 只运行 Phase 3（匹配）
python3 cve_matcher.py
```

### 5. 启用 LLM 兜底

当 CVE 描述中的版本范围无法通过正则提取时，可以使用 LLM 帮忙解析：

```bash
# Phase 2 中启用 LLM 版本提取
python3 dep_analyzer.py \
  --github-token "$GITHUB_TOKEN" \
  --openai-base-url "https://api.openai.com/v1" \
  --openai-api-key "sk-xxxxxxxx" \
  --openai-model "gpt-4o-mini"

# Phase 3 中启用 LLM 边界判断
python3 cve_matcher.py \
  --openai-base-url "https://api.openai.com/v1" \
  --openai-api-key "sk-xxxxxxxx" \
  --openai-model "gpt-4o-mini"
```

### 6. 结果验证

1. 检查 `dep_scan_result.xlsx` 是否有实际的依赖命中（部分 OpenHarmony 仓库确实有 pom.xml、package.json 等文件）
2. 抽查 `cve_version_result.xlsx` 中 `ExtractionMethod=regex` 的记录，确认版本号提取是否合理
3. 人工抽查 `cve_match_result.xlsx` 中 `Determination=regex` 的匹配结果，验证版本判断是否正确
4. `Determination=uncertain` 的匹配置信度较低，建议重点审查

## 依赖组件对照表

### Java 组件（24个）

| 组件名 | Maven 坐标 |
|--------|-----------|
| Spring Framework | org.springframework:spring-core |
| Spring Boot | org.springframework.boot:spring-boot |
| Jackson | com.fasterxml.jackson.core:jackson-databind |
| Apache Tomcat | org.apache.tomcat:tomcat |
| Apache Kafka | org.apache.kafka:kafka-clients |
| Log4j | org.apache.logging.log4j:log4j-core |
| XStream | com.thoughtworks.xstream:xstream |
| Apache ActiveMQ | org.apache.activemq:activemq-client |
| Netty | io.netty:netty-codec |
| Fastjson2 | com.alibaba.fastjson2:fastjson2 |
| Apache Solr | org.apache.solr:solr-core |
| Apache Struts2 | org.apache.struts:struts2-core |
| Apache Commons FileUpload | commons-fileupload:commons-fileupload |
| Apache Shiro | org.apache.shiro:shiro-core |
| Dom4j | org.dom4j:dom4j |
| Apache Commons IO | commons-io:commons-io |
| MyBatis | org.mybatis:mybatis |
| Apache Commons Text | org.apache.commons:commons-text |
| Apache XMLBeans | org.apache.xmlbeans:xmlbeans |
| Apache Commons BeanUtils | commons-beanutils:commons-beanutils |
| Apache Commons Collections | org.apache.commons:commons-collections4 |
| Logback | ch.qos.logback:logback-core |
| Groovy | org.apache.groovy:groovy |
| Jetty | org.eclipse.jetty:jetty-server |

### Python 组件（16个）

urllib3、Transformers、Pandas、LangChain、PyTorch、TensorFlow、PyYAML、scikit-learn、NumPy、SciPy、joblib、Pickle、FastAPI、MLflow、OpenCV-Python、Pillow

## 代码复用说明

以下功能直接从 `workflow_unified.py`（`/data1/czc/LLM-vuln-eval/workflow/workflow_unified.py`）复用：

- `normalize_version()`、`parse_version_parts()`、`compare_versions()` — 版本号处理
- `simple_version_matches()` — 版本范围正则全套
- `call_openai_judge()` — LLM 判断函数
- `REQ_LINE_REGEXES`、`TOML_DEP_SECTION_REGEXES`、`MAVEN_COORD_REGEX`、`GRADLE_DEP_REGEX` 等 — 依赖解析正则
- `parse_maven_properties()`、`parse_pom_dependencies()`、`parse_gradle_dependencies()`、`parse_python_file_for_package()` — 文件解析函数
- GitHub API session 配置（retry、header 等）

## 注意事项

1. **GitHub Token 必需**：未认证请求限速 60次/小时，使用 Token 提升至 5000次/小时。可通过 `--github-token` 参数或 `GITHUB_TOKEN` 环境变量传入
2. **OpenHarmony 仓库特点**：大部分仓库使用 GN 构建系统（C/C++），传统的 pom.xml / requirements.txt 较少，但部分仓库（如 third_party_python、third_party_node）仍包含依赖文件，需全量扫描
3. **GitCode ↔ GitHub 映射**：所有仓库的原始 URL 为 gitcode.com，脚本自动转换为 github.com/openharmony/* 镜像地址
4. **缓存机制**：依赖文件内容缓存至 `workflow_cache/` 目录，重复运行可节省 API 配额
