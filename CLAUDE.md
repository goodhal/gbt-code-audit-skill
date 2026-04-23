# CLAUDE.md

本文件为 Claude Code (claude.ai/code) 在此仓库中工作时提供指导。

## 项目概述

gbt-code-audit-skill 是基于中国国家标准（GB/T 34943/34944/34946/39412）的代码安全审计工具。支持 C/C++、Java、C#、Python 多语言漏洞检测，采用双层架构：快速扫描（正则模式 + 外部工具）+ LLM 深度语义分析。

## 常用命令

### 快速扫描（模式匹配 + 外部工具）

```bash
python skill.py quick_scan --target=/path/to/code
```

参数选项：
- `--max-workers=<n>`：并行工作线程数（默认：4）
- `--no-external-tools`：禁用 Bandit/Semgrep/Gitleaks 集成

### 验证发现（防幻觉）

```bash
python skill.py validate_finding findings/llm_audit/001.md
```

返回 JSON 结果，包含成功/失败状态，若行号不匹配会返回实际代码片段。

### 生成报告

```bash
python skill.py finalize_report --output=report.md --project=my-project --languages=java,cpp --standards=GB/T34944,GB/T34943
```

参数选项：
- `--output`：报告输出路径（默认：自动生成带时间戳的文件名）
- `--project`：项目名称
- `--languages`：语言列表（逗号分隔）
- `--standards`：标准列表（逗号分隔）
- `--date`：审计日期（默认：当前日期）

⚠️ 多值参数必须使用逗号分隔，禁止使用空格。

### 提取代码片段（使用 Grep 验证）

```bash
grep -n "问题代码模式" <文件路径>
```

通过 Grep 搜索确认行号是否正确。

## 架构说明

### 核心审计引擎 (skill.py)

- **quick_scan()**：预编译正则模式匹配 + 外部工具集成（Bandit 用于 Python，Semgrep 多语言，Gitleaks 用于密钥检测）
- **validate_finding()**：验证 md 文件防止幻觉
- **finalize_report()**：加载所有 md 文件 → 批量验证 → 去重 → 生成报告
- **parse_finding_md()**：解析 Markdown 格式审计发现（支持中文和英文字段名）

### 文档结构

- **docs/reference/**：GB/T 国标规则
  - `GBT_34943-2017.md`：C/C++ 规则（34 条）
  - `GBT_34944-2017.md`：Java 规则（37 条）
  - `GBT_34946-2017.md`：C# 规则（42 条）
  - `GBT_39412-2020.md`：通用规则（97 条）
  - `gbt_mapping.md`：漏洞类型与国标映射
- **docs/vulnerabilities/**：漏洞知识库（sql_injection、command_injection 等）
- **docs/workflow/**：审计流程、质量标准、问题排查
- **test-samples/**：漏洞代码测试样例

### 输出目录结构

```
findings/
├── baseline/    # 快速扫描结果（md 文件）
└── llm_audit/   # LLM 审计结果（md 文件）
```

## 审计流程

```
学习国标 → 创建目录 → 快速扫描 → 基线入库 → LLM 审计 → finalize_report
```

关键原则：
1. **LLM 审计独立性**：LLM 审计必须完全独立于快速扫描，不得参考快速扫描结果
2. **两级验证**：LLM 审计 md 文件创建后立即验证；基线 md 文件在 finalize_report 时批量验证
3. **去重机制**：finalize_report 时按 `{文件}:{行号}:{类型}` 去重，优先保留 LLM 审计结果

## Markdown 发现格式

md 文件必填字段：

```markdown
编号: #001
严重等级: 严重
漏洞类型: 命令注入
文件路径: test-samples/java/VulnerableJava.java
行号: 31
CWE: CWE-78
国标映射: GB/T34944-6.2.3.3 命令注入
来源: llm_audit
语言: java
问题代码: Runtime.getRuntime().exec(command);
问题描述: 问题描述内容
修复方案: 修复方案内容（必须 ≥30 字，包含具体代码/API/配置）
验证方法: 验证方法
```

## 国标映射

| 语言 | 适用标准 |
|------|----------|
| Java | GB/T 34944-2017 + GB/T 39412-2020 |
| C/C++ | GB/T 34943-2017 + GB/T 39412-2020 |
| C# | GB/T 34946-2017 + GB/T 39412-2020 |
| Python | 仅 GB/T 39412-2020 |

## 外部工具集成

快速扫描优先使用外部工具（可用时）：
- **Gitleaks**：密钥/凭证检测
- **Bandit**：Python 安全分析
- **Semgrep**：多语言模式匹配

若外部工具不可用，自动回退到正则模式匹配。

## MCP 工具：code-review-graph

本项目已配置知识图谱 MCP 服务器。在以下场景优先使用而非 Grep/Glob/Read：
- 探索代码结构
- 理解变更影响范围
- 查找组件间关系

详见项目级 CLAUDE.md 中 MCP 工具使用说明。

## 常见问题

### md 文件解析返回 0 个发现

原因：使用中文冒号 `：` 而非英文冒号 `:`。两者均支持但推荐使用英文冒号。

### 报告文件名变成参数值

原因：使用空格分隔多值参数（如 `--standards A B C`）。必须使用逗号分隔：`--standards=A,B,C`。

### LLM 审计发现被过滤为幻觉

原因：行号不匹配或代码片段不存在。创建 md 文件前使用 `Grep` 工具验证行号。