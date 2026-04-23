# 代码安全审计技能（gbt-code-audit-skill）

基于中国国家标准（GB/T 34943/34944/34946/39412）的代码安全审计技能，理论上支持所有编程语言的源代码安全漏洞扫描和检测。该技能利用 Agent 的 LLM 能力进行智能审计，无需 API Key 和外部 LLM 客户端。

> **测试环境**：已在 GLM-5 模型下测试通过

## 功能特性

- **全语言支持**: Java、C/C++、C#、Python、Go、JavaScript、TypeScript、PHP、Ruby、Rust 等 16+ 种语言
- **国标覆盖**: GB/T 34943-2017 (C/C++)、GB/T 34944-2017 (Java)、GB/T 34946-2017 (C#)、GB/T 39412-2020 (通用基线)
- **双层审计架构**: 规则引擎快速扫描 + LLM 深度语义分析
- **LLM审计优势**: 跨文件调用链分析、业务逻辑漏洞、组合攻击链、上下文关联分析
- **智能防幻觉**: 两级自动验证机制（创建时验证 + 报告前批量验证）
- **多维去重**: 基于文件路径、行号、漏洞类型的智能去重
- **双国标映射**: 有专用标准的语言使用双映射，无专用标准的使用 GB/T 39412 单映射
- **标准报告**: 按国标章节分类，生成合规审计报告
- **无需编译**: 直接审计源代码

## 快速开始

### 安装依赖

```bash
# 克隆项目
git clone https://github.com/goodhal/gbt-code-audit-skill.git
cd gbt-code-audit-skill

# 无需安装依赖（仅使用 Python 标准库）
```

### 使用技能

在 AI Agent 中加载技能，然后按照以下流程使用：

```bash
# 步骤 0-2: 学习流程（Agent 会自动完成）
# 步骤 3: 创建 findings 目录
mkdir -p findings/baseline findings/llm_audit

# 步骤 4: 快速扫描（隔离模式，详情保存到文件）
python skill.py quick_scan --target=/path/to/code

# 步骤 5: Agent 分析补全
# - 读取 scan_result.json
# - 补全国标映射、问题描述、修复方案
# - 创建完整的 baseline md 文件

# 步骤 6: LLM 独立审计（提示词约束）
# - 不看 baseline 目录
# - 专注调用链分析、缓解措施验证、业务逻辑漏洞

# 步骤 7: 生成报告
python skill.py finalize_report --project=my-project
```

## 支持的标准与语言

| 语言类型 | 适用标准 | 映射格式 |
|----------|----------|----------|
| **有专用标准**（双映射） | 专用标准 + GB/T 39412-2020 | `GB/T349XX-规则；GB/T39412-规则` |
| Java | GB/T 34944-2017 + GB/T 39412-2020 | 双映射 |
| C/C++ | GB/T 34943-2017 + GB/T 39412-2020 | 双映射 |
| C# | GB/T 34946-2017 + GB/T 39412-2020 | 双映射 |
| **无专用标准**（单映射） | 仅 GB/T 39412-2020 | `GB/T39412-规则` |
| Python/Go/JS/PHP/Rust 等 | GB/T 39412-2020 | 单映射 |

> **GB/T 39412-2020 是通用基线**，适用于所有语言的代码安全审计。

覆盖的安全领域：

- 输入验证与数据清洗
- 命令注入、SQL注入、代码注入
- 路径遍历、XSS、CSRF
- 硬编码密码、弱加密、弱哈希
- 敏感数据泄露、日志安全
- 内存安全、并发安全
- 会话管理、认证授权

## 检测能力

### 严重问题（🔴）

- SQL 注入、命令注入、代码注入
- 不安全反序列化（RCE）
- 硬编码密钥/凭证
- XXE、SSRF

### 高危问题（🟠）

- XSS、CSRF
- 路径遍历
- 弱加密/弱哈希
- 敏感数据泄露

### 中危问题（🟡）

- 空指针解引用、资源泄漏
- 整数溢出、缓冲区溢出
- 错误信息泄露
- 日志注入

### 低危问题（🟢）

- 代码质量问题
- 死代码、未使用的变量
- 不充分的随机数
- 弱密码策略

## 审计流程

```
快速扫描 → 基线入库 → LLM 深度审计 → 生成报告
```

### 流程步骤

1. **学习流程**: Agent 阅读 SKILL.md 和国标规则文件
2. **语言判定**: 通过文件扩展名判断语言类型
3. **创建目录**: 创建 findings/baseline 和 llm_audit 目录
4. **快速扫描**: 使用正则 + 外部工具检测常见漏洞
5. **基线入库**: 创建 md 文件 + 状态判定（有效/误报）+ 上下文检查
6. **LLM 审计**: 独立审计 + 创建 md + 逐个验证
7. **生成报告**: 去重 + 批量验证 + 生成最终报告

### LLM 审计优势

LLM 审计相比传统工具能发现：

- **跨文件调用链**: 用户输入从 A 文件传递到 B 文件的危险函数
- **业务逻辑漏洞**: 认证绕过、权限越权、状态篡改
- **组合攻击链**: 信息泄露 + 身份伪造 → 账户接管
- **上下文关联**: 变量用途、函数语义、数据流分析

## 输出物

- `findings/baseline/*.md` — 快速扫描发现的漏洞（所有文件已通过 validate_finding 验证）
- `findings/llm_audit/*.md` — LLM 独立审计发现的漏洞（所有文件已通过 validate_finding 验证）
- `audit_report_YYYYMMDD_HHMMSS.md` — 最终审计报告（含汇总表格和详细发现）

## 工具列表

| 工具 | 说明 | 命令行用法 |
|------|------|----------|
| `quick_scan` | 快速扫描：正则 + Bandit/Semgrep/Gitleaks | `python skill.py quick_scan --target=<path>` |
| `validate_finding` | 验证发现：完整性和质量检查 | `python skill.py validate_finding <md_file>` |
| `finalize_report` | 收尾报告：去重 + 验证 + 生成 | `python skill.py finalize_report --project=<name>` |

**validate_finding 验证内容**：
- 必填字段（13个字段完整性）
- 国标映射（格式正确性、双映射/单映射）
- 代码片段（行号准确性、防幻觉）
- 问题描述（字数≥20）
- 修复方案（字数≥20）

> **质量判断由 LLM 负责**：问题描述是否说明漏洞原因/风险、修复方案是否合理可行

## 项目结构

```
gbt-code-audit-skill/
├── skill.py                 # 核心审计引擎
├── SKILL.md                 # 技能定义文档
├── README.md                # 项目说明
├── CLAUDE.md                # Claude Code 工作指导
├── docs/                    # 文档目录
│   ├── workflow/            # 流程文档
│   ├── reference/           # 国标规则和映射
│   └── vulnerabilities/     # 漏洞知识库
├── test-samples/            # 测试样例
│   ├── java/
│   ├── python/
│   ├── cpp/
│   └── csharp/
└── findings/                # 审计发现（运行时生成）
    ├── baseline/            # 快速扫描结果
    └── llm_audit/           # LLM 审计结果
```

## 版本

当前版本：2.3.0

**更新日志**：
- v2.3.0: 支持16+种语言、双国标映射、LLM审计优势发挥指引、validate_finding 扩展验证
- v2.2.0: 重构代码消除冗余、添加去重统计输出

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！

## 联系方式

- GitHub: https://github.com/goodhal/gbt-code-audit-skill
- Issues: https://github.com/goodhal/gbt-code-audit-skill/issues
