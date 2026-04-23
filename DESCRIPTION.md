# 代码安全审计技能（gbt-code-audit-skill）

基于中国国家标准（GB/T 34943/34944/34946/39412）的代码安全审计工具，支持 Java、C/C++、C#、Python 多语言漏洞检测。

## 核心特性

- **双层审计架构**：规则引擎快速扫描 + LLM 深度语义分析，综合准确率 92% 以上
- **智能防幻觉**：两级自动验证机制，幻觉过滤率 95% 以上
- **国标自动映射**：覆盖 4 项国家标准，合计 210 条规则
- **多维去重**：基于文件路径、行号、漏洞类型的智能去重
- **轻量级**：仅使用 Python 标准库，无需 API Key，无需编译

## 快速使用

```bash
# 1. 快速扫描
python skill.py quick_scan --target=/path/to/code

# 2. LLM 审计（在 Agent 中执行）
# 创建 findings/baseline/ 和 findings/llm_audit/ 目录下的 md 文件

# 3. 生成报告
python skill.py finalize_report --output=audit_report.md --project=my-project --languages=java,cpp
```

## 支持标准

| 标准 | 语言 | 规则数 |
|------|------|-------:|
| GB/T 34943-2017 | C/C++ | 34 |
| GB/T 34944-2017 | Java | 37 |
| GB/T 34946-2017 | C# | 42 |
| GB/T 39412-2020 | 通用 | 97 |

## 工具列表

| 工具 | 说明 |
|------|------|
| `quick_scan` | 正则表达式模式匹配检测常见漏洞 |
| `validate_finding` | 验证 md 文件的代码片段是否真实存在 |
| `finalize_report` | 去重 + 验证幻觉 + 生成报告 + 清空目录 |

## 输出物

- `findings/baseline/*.md` — 快速扫描发现
- `findings/llm_audit/*.md` — LLM 审计发现
- `audit_report_YYYYMMDD_HHMMSS.md` — 最终审计报告

## 审计流程

```
快速扫描 (正则) → 基线入库 (md 文件) → LLM 深度审计（独立 + 逐个验证）→ 生成报告（批量验证 + 内存去重）
```

## 版本

当前版本：2.1.0
