***

name: code-security-audit
description: 基于中国国家标准（GB/T 34943/34944/34946/39412）的代码安全审计工具。支持 Java、C/C++、C#、Python 多语言漏洞检测，采用「快速扫描 + LLM 深度审计」双引擎，自动去重生成的 Markdown 格式审计报告。适用于项目验收、安全合规审查、代码质量评估等场景。
---------------------------------------------------------------------

# 代码安全审计技能

> **测试环境**：已在 GLM-5 模型下测试通过
>
> **详细文档**：
> - [详细审计流程](docs/workflow/audit_workflow.md) - LLM 审计执行流程和验证机制
> - [输出质量检查标准](docs/workflow/quality_standards.md) - 修复方案编写要求和验证机制
> - [国标映射参考](docs/reference/gbt_mapping.md) - 漏洞类型与国标规则对应关系
> - [常见问题解决方案](docs/workflow/troubleshooting.md) - 问题排查指南
> - [漏洞知识库](docs/vulnerabilities/) - 各类漏洞的危险模式与修复方案

---

## 📋 概述

本技能提供完整的代码安全审计工作流，基于中国国家标准检测源代码中的安全漏洞。

**核心流程**：
```
快速扫描 → 基线入库 → LLM 深度审计 → 生成报告
```

**输出物**：
- `findings/baseline/*.md` — 快速扫描发现的漏洞
- `findings/llm_audit/*.md` — LLM 独立审计发现的漏洞
- `audit_report_YYYYMMDD_HHMMSS.md` — 最终审计报告

---

## 🎯 审计原则

- **独立性优先**：LLM 审计必须完全独立于快速扫描
- **双重验证**：LLM 审计发现创建后立即验证，finalize_report 时批量验证
- **全面覆盖**：LLM 审计应全面覆盖所有安全问题，不自我设限
- **国标为准绳**：漏洞定性和分类严格遵循 GB/T 标准

---

## 🔴 执行前必知

1. 执行前确认关键函数存在（quick_scan、validate_finding、finalize_report）
2. 发现文档提到不存在的函数时，先修复文档再执行
3. "学习标准"步骤必须输出确认

---

## 语言与标准对应关系

| 语言 | 适用标准 | 说明 |
|------|----------|------|
| Java | GB/T 34944-2017 + GB/T 39412-2020 | 专用标准 + 通用基线 |
| C/C++ | GB/T 34943-2017 + GB/T 39412-2020 | 专用标准 + 通用基线 |
| C# | GB/T 34946-2017 + GB/T 39412-2020 | 专用标准 + 通用基线 |
| Python | GB/T 39412-2020 | 仅通用基线 |

> 详细映射见 [docs/reference/gbt_mapping.md](docs/reference/gbt_mapping.md)

---

## 审计流程

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Agent 代码安全审计流程                        │
├─────────────────────────────────────────────────────────────────────┤
│  0️⃣ 学习流程  ◀ 【强制】阅读 SKILL.md                               │
│  1️⃣ 语言判定  ◀ 【LLM 自主】通过文件扩展名判断语言                  │
│  2️⃣ 学习标准  ◀ 【必须输出】确认已学习的国标及规则数                │
│  3️⃣ 创建目录  ◀ 【必须】创建 findings/baseline 和 llm_audit 目录   │
│  4️⃣ 快速扫描  ◀ 【必须调用 quick_scan】获取基线结果                 │
│  5️⃣ 基线入库  ◀ 【必须】创建 md 文件                                │
│  6️⃣ LLM 审计  ◀ 【必须】独立审计 + 创建 md + 逐个验证               │
│  7️⃣ 生成报告  ◀ 【必须调用 finalize_report】去重 + 验证 + 生成     │
│  8️⃣ 审计完成  ◀ 【输出】报告路径和验证结果                          │
└─────────────────────────────────────────────────────────────────────┘
```

> 详细流程见 [docs/workflow/audit_workflow.md](docs/workflow/audit_workflow.md)

---

## 工具列表

| 工具 | 描述 | 命令 |
|------|------|------|
| `quick_scan` | 快速扫描：正则 + Bandit/Semgrep/Gitleaks | `python skill.py quick_scan <target>` |
| `validate_finding` | 验证发现：防幻觉 | `python skill.py validate_finding <md_file>` |
| `finalize_report` | 收尾报告：去重 + 验证 + 生成 | `python skill.py finalize_report [--output=...]` |

---

## Markdown 文件格式

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
问题描述: 描述内容（2-3句话）
修复方案: 修复内容（≥30字，含具体代码/命令/API）
验证方法: 验证方法
```

> 详细质量检查标准见 [docs/workflow/quality_standards.md](docs/workflow/quality_standards.md)

---

## 🔴 禁止行为清单

| 行为 | 违规类型 |
|------|----------|
| 查看 baseline/ 目录内容 | 违反独立性 |
| 说"补充快速扫描未发现的漏洞" | 违反独立性 |
| 自我设限审计范围 | 违反全面性 |
| 跳过 validate_finding 验证 | 违反流程 |
| 行号凭记忆填写 | 违反准确性 |

> 详细流程和验证机制见 [docs/workflow/audit_workflow.md](docs/workflow/audit_workflow.md)

---

## 🔧 常见问题

| 问题 | 解决方案 |
|------|----------|
| md 文件无法解析 | 使用英文冒号 `:` |
| 报告名称变成参数值 | 多值参数用逗号分隔 `--standards=A,B,C` |
| LLM 审计发现被过滤 | 使用 Grep 工具验证行号 |

> 详细问题解决方案见 [docs/workflow/troubleshooting.md](docs/workflow/troubleshooting.md)

---

## 路线图

- **Q2 2026**: 支持更多语言（Go/PHP/JavaScript）
- **Q3 2026**: CI/CD 集成、Web UI
- **Q4 2026**: 多 LLM 模型支持