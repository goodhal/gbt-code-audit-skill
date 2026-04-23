# 变更日志

本文件记录项目的主要变更历史。

## [2.1.0] - 2026-04-23

### 修复

- 删除 skill.py 中重复函数定义 `_get_severity_icon` 和 `_get_source_icon`
- 统一所有文档版本号为 2.1.0（README.md、DESCRIPTION.md）
- 补充 manifest.json 中缺失的 `validate_finding` 工具定义
- 删除文档对未实现命令的引用（`audit_context`、`extract_code`）

### 文档重构

- 精简 SKILL.md 从 1089 行到 149 行（减少 86%）
- 合并文档目录：
  - `rules/` → `docs/reference/`
  - `knowledge/vulnerabilities/` → `docs/vulnerabilities/`
- 创建 docs 子目录结构：
  - `docs/workflow/` - 流程文档
  - `docs/reference/` - 国标规则和映射
  - `docs/vulnerabilities/` - 漏洞知识库

### 新增

- 创建 CLAUDE.md - Claude Code 工作指导文档
- 创建 test_skill.py - 单元测试（22 个测试）
- 创建 pyproject.toml - 项目安装配置
- 创建 docs 各子目录 README.md 索引文件

## [2.0.0] - 2026-04-18

### 新增

- 双重验证机制（LLM 创建时 + finalize_report 时）
- 国标自动映射函数 `get_gbt_mapping()`
- 修复方案质量验证（字数、禁用词、技术关键词）
- 外部工具集成（Bandit、Semgrep、Gitleaks）

### 修复

- `validate_finding` 支持中文冒号和英文冒号
- `finalize_report` 参数解析改进（逗号分隔）

## [1.0.0] - 2026-04-14

### 新增

- 基于国标的代码安全审计功能
- 支持 Java/C/C++/C#/Python 四种语言
- 快速扫描（正则模式匹配）
- LLM 深度审计
- Markdown 格式审计报告生成