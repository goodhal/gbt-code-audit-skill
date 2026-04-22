# 代码安全审计技能（gbt-code-audit-skill）

基于中国国家标准（GB/T 34943/34944/34946/39412）的代码安全审计技能，支持 C/C++、Java、C#、Python 等语言的源代码安全漏洞扫描和检测。该技能利用 Agent 的 LLM 能力进行智能审计，无需 API Key 和外部 LLM 客户端。

> **测试环境**：已在 GLM-5 模型下测试通过

## 功能特性

- **多语言支持**: C/C++、Java、C#、Python 等
- **国标覆盖**: GB/T 34943-2017 (C/C++)、GB/T 34944-2017 (Java)、GB/T 34946-2017 (C#)、GB/T 39412-2020 (通用)，合计 210 条规则
- **双层审计架构**: 规则引擎快速扫描 + LLM 深度语义分析
- **智能防幻觉**: 两级自动验证机制（创建时 + 报告前）
- **修复方案质量验证**: 自动检测修复方案可执行性，过滤模糊表述
- **多维去重**: 基于文件路径、行号、漏洞类型的智能去重，优先保留 LLM 审计结果
- **标准报告**: 按国标章节分类，生成合规审计报告
- **时间戳命名**: 报告文件自动添加时间戳，便于追溯和管理
- **无需 API Key**: 直接利用 Agent 的内置 LLM 能力
- **无需编译**: 直接审计源代码，无需编译生成字节码
- **轻量级架构**: 基于 Markdown 文件存储，无数据库依赖

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
# 步骤 1: 创建 findings 目录（LLM 直接创建）
New-Item -ItemType Directory -Force -Path findings\baseline
New-Item -ItemType Directory -Force -Path findings\llm_audit

# 步骤 2: 快速扫描
python skill.py quick_scan /path/to/code

# 步骤 3: 创建 Markdown 文件
# - 为快速扫描结果创建 md 文件到 findings/baseline/
# - LLM 审计创建 md 文件到 findings/llm_audit/

# 步骤 4: 生成报告（自动添加时间戳）
python skill.py finalize_report --project=my-project --languages=java,cpp --standards=GB/T34944,GB/T34943
```

## 支持的标准

| 标准 | 语言 | 规则数 |
|------|------|-------:|
| GB/T 34943-2017 | C/C++ | 34 |
| GB/T 34944-2017 | Java | 37 |
| GB/T 34946-2017 | C# | 42 |
| GB/T 39412-2020 | 通用 | 97 |

覆盖的安全领域：

- 输入验证与数据清洗
- 错误处理与异常安全
- 代码质量与内存管理
- 封装与序列化安全
- Web 安全（XSS、CSRF、SSRF）
- SQL/命令/代码注入
- 敏感数据保护
- 加密与密钥管理
- 线程安全与并发
- 会话管理

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
快速扫描 (正则) → 基线入库 (md 文件) → LLM 深度审计（独立 + 逐个验证）→ 生成报告（批量验证 + 内存去重）
```

### 步骤说明

1. **快速扫描**: 使用正则表达式模式匹配检测常见漏洞
2. **基线入库**: 为快速扫描结果创建 Markdown 文件到 `findings/baseline/`
3. **LLM 深度审计**: LLM 独立审计源代码，创建 Markdown 文件到 `findings/llm_audit/`，每个文件立即验证
4. **生成报告**: 加载所有 md 文件 → 批量验证（过滤幻觉 + 更新行号）→ 内存去重 → 生成最终报告

## 输出物

- `findings/baseline/*.md` — 快速扫描发现的漏洞（所有文件已通过 validate_finding 验证）
- `findings/llm_audit/*.md` — LLM 独立审计发现的漏洞（所有文件已通过 validate_finding 验证）
- `audit_report_YYYYMMDD_HHMMSS.md` — 最终审计报告（含汇总表格和详细发现）

## 工具列表

| 工具 | 说明 | 命令行用法 |
|------|------|----------|
| `quick_scan` | 快速扫描：正则表达式模式匹配检测常见漏洞 | `python skill.py quick_scan --target=<path>` |
| `extract_code` | 提取代码：获取指定文件和行号的真实代码片段 | `python skill.py extract_code <file_path> <line_number>` |
| `validate_finding` | 验证发现：验证 md 文件的代码片段是否真实存在（防幻觉） | `python skill.py validate_finding <md_file_path>` |
| `finalize_report` | 收尾报告：去重 + 验证幻觉 + 生成报告 | `python skill.py finalize_report --output=<path> --project=<name>` |

## 项目结构

```
gbt-code-audit-skill/
├── skill.py                 # 核心审计引擎
├── SKILL.md                 # 技能定义文档
├── README.md                # 项目说明
├── DESCRIPTION.md           # 技能描述
├── manifest.json            # 技能清单
├── knowledge/               # 漏洞知识库
│   └── vulnerabilities/     # 按漏洞类型组织的知识
│       ├── sql_injection.md
│       ├── command_injection.md
│       └── ...
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

当前版本：2.0.0

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！

## 联系方式

- GitHub: https://github.com/goodhal/gbt-code-audit-skill
- Issues: https://github.com/goodhal/gbt-code-audit-skill/issues
