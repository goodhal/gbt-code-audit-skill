# CLAUDE.md

本文件为 Claude Code 在此仓库中工作时提供指导。

## 项目概述

基于中国国家标准（GB/T 34943/34944/34946/39412）的代码安全审计工具。理论上支持所有编程语言漏洞检测，采用双层架构：快速扫描 + LLM 深度语义分析。

> **详细技能文档**：见 [SKILL.md](SKILL.md)

## 常用命令

```bash
# 快速扫描
python skill.py quick_scan --target=/path/to/code

# 验证发现
python skill.py validate_finding findings/llm_audit/001.md

# 生成报告
python skill.py finalize_report --project=my-project --languages java python
```

> ⚠️ 多值参数使用空格分隔，如 `--languages java python`。

## 审计流程

```
学习国标 → 创建目录 → 快速扫描 → 基线入库 → LLM 审计 → finalize_report
```

> **详细流程**：见 [docs/workflow/audit_workflow.md](docs/workflow/audit_workflow.md)

## 关键原则

1. **LLM 审计独立性**：完全独立于快速扫描，不得参考快速扫描结果
2. **两级验证**：创建后立即验证，报告前批量验证
3. **去重机制**：按 `{文件}:{行号}:{类型}` 去重
4. **质量判断**：代码仅做格式验证，语义判断由 LLM 负责

## 国标映射

| 语言类型 | 映射格式 |
|----------|----------|
| **有专用标准**（Java/C/C++/C#） | 双映射：`GB/T349XX-规则；GB/T39412-规则` |
| **无专用标准**（Python/Go/JS等） | 单映射：`GB/T39412-规则` |

> **详细规则**：见 [docs/reference/](docs/reference/) 目录下的国标文件

## 职责划分

| 功能 | 代码负责 | LLM 负责 |
|------|----------|----------|
| 文件解析、格式验证 | ✅ | ❌ |
| 行号验证、防幻觉 | ✅ | ❌ |
| 基本完整性（字数） | ✅ | ❌ |
| 问题描述质量 | ❌ | ✅ |
| 修复方案合理性 | ❌ | ✅ |
| 误报判定 | ❌ | ✅ |

## 外部工具集成

- **Gitleaks**：密钥/凭证检测
- **Bandit**：Python 安全分析
- **Semgrep**：多语言模式匹配