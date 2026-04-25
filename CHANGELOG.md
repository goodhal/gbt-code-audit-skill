# 变更日志

本文件记录项目的主要变更历史。

## [2.4.1] - 2026-04-26

### 代码重构

- **脚本目录规范化**：将核心Python代码统一移动到 `scripts/` 目录
  - `skill.py` → `scripts/skill.py`
  - `constants.py` → `scripts/constants.py`
  - `patterns.py` → `scripts/patterns.py`
  - `validation.py` → `scripts/validation.py`
- **删除冗余文件**：移除 `pyproject.toml` 和 `test_skill.py`
- **新增验证模块**：`scripts/validation.py` 提供完整的审计结果验证功能
  - 必填字段验证
  - 国标映射格式验证
  - 描述和修复方案格式验证
  - 代码片段验证

### 文档完善

- **审计工作流程**：`docs/workflow/audit_workflow.md` 详细说明三层审计分工
- **质量标准**：`docs/workflow/quality_standards.md` 定义审计质量判断标准
- **故障排除**：`docs/workflow/troubleshooting.md` 提供常见问题解决方案
- **项目文档优化**：更新 SKILL.md、CLAUDE.md、README.md

### 项目结构优化

- 目录结构清晰化：scripts/（代码）、docs/（文档）、test-samples/（测试）
- .gitignore 配置完善：正确忽略运行时产物和临时文件
- 配置文件规范化：确保Git跟踪必要文件，忽略生成文件

## [2.4.0] - 2026-04-24

### 代码重构

- **代码文件组织优化**：将所有 Python 代码文件移动到 `scripts/` 目录
  - `skill.py` → `scripts/skill.py`
  - `constants.py` → `scripts/constants.py`
  - `patterns.py` → `scripts/patterns.py`
  - `validation.py` → `scripts/validation.py`
- **项目结构优化**：代码文件集中管理，提高可维护性
- **文档更新**：所有文档中的 skill.py 引用已更新为 scripts/skill.py

## [2.3.0] - 2026-04-23

### 新增

- **支持16+种编程语言**：Java、C/C++、C#、Python、Go、JavaScript、TypeScript、PHP、Ruby、Rust、Kotlin、Swift、Scala、Perl、Lua、Shell
- **双国标映射机制**：有专用标准的语言使用双映射（专用标准 + GB/T39412），无专用标准的使用单映射（仅 GB/T39412）
- **validate_finding 扩展验证**：
  - 必填字段完整性检查（13个字段）
  - 国标映射格式验证（双映射/单映射）
  - 代码片段行号验证（防幻觉）
  - 问题描述字数检查
  - 修复方案字数检查
- **LLM 审计优势发挥指引**：跨文件调用链、业务逻辑漏洞、组合攻击链、上下文关联分析
- **上下文检查要求**：本文件检查（Read）+ 跨文件检查（Grep）
- **去重统计输出优化**：添加 `total_before_dedup` 和 `dedup_removed` 字段

### 优化

- **代码重构**：消除冗余，skill.py 从 2220行 → 2124行（减少96行）
- **删除硬编码关键词检查**：移除描述和修复的关键词列表，由 LLM 语义判断
- **删除死代码**：`calculate_confidence_score` 函数
- **常量集中管理**：`VALID_GBT_PREFIXES`、`GBT_PREFIX_TO_STANDARD`、`GBT_PREFIX_TO_DESCRIPTION`

### 文档

- 更新 SKILL.md：LLM 审计优势发挥、上下文检查要求、质量判断要求
- 更新 README.md：全语言支持、双国标映射、工具列表验证内容
- 修复文档引用：删除不存在的 `gbt_mapping.md` 引用

## [2.2.0] - 2026-04-23

### 流程重构

**核心理念**：承认同一会话记忆持续，通过提示词约束"尽可能独立"

| 步骤 | 内容 | 可看 |
|------|------|------|
| 步骤5 | Agent 分析补全 + 创建 baseline | scan_result.json |
| 步骤6 | LLM 审计（提示词约束） | 只看源代码和国标，不看 baseline |

### 新增

- `--output-file` 参数：quick_scan 保存完整结果到 JSON 文件
- `--show-details` 参数：调试模式，显示完整 findings 详情
- **LLM 审计重点扩展**（11个领域）：
  - 调用链分析、缓解措施验证、业务逻辑漏洞
  - 认证/授权缺陷、配置安全、上下文关联
  - 第三方依赖、资源并发、API边界安全
  - 语义深度、模块边界
- **快速扫描未检出原因类型**：7种原因分类

### 移除

- `create_baseline_from_scan` 函数：自动创建跳过分析补全
- `--save-baseline` 参数：改为 Agent 手动分析补全后创建
- "强制新会话"设计：新会话会丢失已学习的210条国标

### 文档

- 更新 SKILL.md 审计原则：改为"提示词约束尽可能独立"
- 更新独立审计提示词：7项重点，覆盖11个领域
- 添加快速扫描未检出原因类型：供LLM审计发现时说明

## [2.1.0] - 2026-04-23

### 修复

- 删除 skill.py 中重复函数定义 `_get_severity_icon` 和 `_get_source_icon`
- 统一所有文档版本号为 2.1.0（README.md）
- 补充工具定义文档（validate_finding）
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