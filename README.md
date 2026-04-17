# 代码安全审计技能（gbt-code-audit-skill）

基于中国国家标准（GB/T 34943/34944/34946/39412）的代码安全审计技能，支持 C/C++、Java、C#、Python 等语言的源代码安全漏洞扫描和检测。该技能利用 Agent 的 LLM 能力进行智能审计，无需 API Key 和外部 LLM 客户端。

> **测试环境**：已在 GLM-5 模型下测试通过

## 功能特性

- **多语言支持**: C/C++、Java、C#、Python 等
- **国标覆盖**: GB/T 34943-2017 (C/C++)、GB/T 34944-2017 (Java)、GB/T 34946-2017 (C#)、GB/T 39412-2020 (通用)
- **快速扫描**: 正则表达式模式匹配，快速发现高危漏洞
- **LLM 智能审计**: 利用 Agent 的 LLM 能力进行深度语义分析
- **内存去重**: 同文件同方法同类问题自动合并，优先保留 LLM 审计结果
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
- 注释不足
- 命名不规范

## 输出报告

报告文件名格式：`audit_report_YYYYMMDD_HHMMSS.md`

```markdown
# 代码安全审计报告

## 封面
**项目**：my-project
**语言**：Java, C/C++
**适用标准**：GB/T 34944-2017, GB/T 34943-2017
**日期**：2026-04-16
**审计人**：Agent

---

## 审计汇总

### 问题汇总

| 严重等级 | 数量 | 快速扫描 | LLM 审计 | 说明 |
|:--------:|-----:|:--------:|:-------:|------|
| 🔴 严重 | 25 | 21 | 4 | 可直接导致系统被入侵 |
| 🟠 高危 | 26 | 10 | 16 | 可导致数据泄露或权限提升 |
| 🟡 中危 | 10 | 0 | 10 | 可能被利用但需要特定条件 |
| 🟢 低危 | 1 | 0 | 1 | 存在安全隐患但影响较小 |
| **总计** | **62** | **31** | **31** | |

### 按国标分类统计

#### GB/T 34944-2017 Java 语言源代码漏洞测试规范 - 38 个

| 规则 | 问题数 |
|------|--------|
| GB/T34944-6.2.3.3 命令注入 | 1 |
| GB/T34944-6.2.3.4 SQL 注入 | 1 |
| ... | ... |

---

## 详细发现

### #1 🔴 命令注入

**来源**: 🔧 快速扫描

**文件**: test-samples/java/VulnerableJava.java:49

**标准**: GB/T34944-6.2.3.3 命令注入

**CWE**: [CWE-78](https://cwe.mitre.org/data/definitions/78.html)

#### 问题描述

使用未经验证的输入数据构建命令，攻击者可执行任意命令

#### 问题代码

```
Runtime.getRuntime().exec("cat " + filename);
```

#### 修复方案

使用 ProcessBuilder 并设置参数白名单验证

#### 验证方法

传入恶意参数如"test.txt; rm -rf /"验证命令执行
```

## 项目结构

```
gbt-code-audit-skill/
├── README.md              # 项目说明
├── SKILL.md               # 技能文档（审计流程和规则）
├── _meta.json             # 技能元数据
├── manifest.json          # 技能配置和工具定义
├── skill.py               # 技能主入口
├── .gitignore             # Git 忽略配置
├── rules/                 # 国标规则文件
│   ├── GBT_34943-2017.md  # C/C++ 规则（34 条）
│   ├── GBT_34944-2017.md  # Java 规则（37 条）
│   ├── GBT_34946-2017.md  # C# 规则（42 条）
│   └── GBT_39412-2020.md  # 通用规则（97 条）
└── test-samples/          # 测试样例
    ├── cpp/
    │   └── vulnerable_cpp.cpp
    ├── csharp/
    │   └── vulnerable_csharp.cs
    ├── java/
    │   └── VulnerableJava.java
    └── python/
        └── vulnerable_python.py
```

## 审计流程

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Agent 代码安全审计流程                        │
├─────────────────────────────────────────────────────────────────────┤
│  0️⃣ 学习流程  ◀ 【强制】阅读 SKILL.md                               │
│  1️⃣ 语言判定  ◀ 【LLM 自主】通过文件扩展名/内容判断语言              │
│  2️⃣ 学习标准  ◀ 【必须输出】确认已学习的国标及规则数                 │
│  3️⃣ 创建目录    ◀ 【LLM 直接创建】findings/baseline 和 llm_audit   │
│  4️⃣ 快速扫描  ◀ 【必须调用 quick_scan】获取基线结果                  │
│  5️⃣ 基线入库  ◀ 【必须】为每个发现创建 md 文件到 findings/baseline/  │
│  6️⃣ LLM 深度审计  ◀ 【必须】为每个发现创建 md 文件到 findings/llm_audit/ │
│  7️⃣ 生成报告  ◀ 【必须调用 finalize_report】去重 + 生成报告 + 清空目录 │
│  8️⃣ 审计完成  ◀ 【输出】报告路径和验证结果                          │
└─────────────────────────────────────────────────────────────────────┘
```

## 工具列表

| 工具名称 | 描述 | 命令行用法 |
|---------|------|----------|
| `quick_scan` | 快速扫描：正则表达式模式匹配检测常见漏洞 | `python skill.py quick_scan <target>` |
| `finalize_report` | 收尾报告：遍历 md 文件去重 + 生成报告 + 清空目录 | `python skill.py finalize_report [--output=报告路径] [--project=名称] [--languages=列表] [--standards=列表] [--date=日期]` |

### 参数说明

- `--output`: 报告输出路径（可选，默认生成 `audit_report_YYYYMMDD_HHMMSS.md`）
- `--project`: 项目名称（可选，默认从文件推断）
- `--languages`: 语言列表（可选，逗号分隔，默认从文件推断）
- `--standards`: 标准列表（可选，逗号分隔，默认从文件推断）
- `--date`: 审计日期（可选，默认使用当前日期）

## 测试样例

测试样例位于 `test-samples/` 目录，包含各语言的漏洞示例：

| 文件 | 标准 | 漏洞示例数 |
|------|------|-----------|
| `java/VulnerableJava.java` | GB/T 34944-2017 | 37 |
| `cpp/vulnerable_cpp.cpp` | GB/T 34943-2017 | 34 |
| `csharp/vulnerable_csharp.cs` | GB/T 34946-2017 | 42 |
| `python/vulnerable_python.py` | GB/T 39412-2020 | ~80 |

每个漏洞示例使用 `[GB/T 标准 - 章节号] 漏洞名称 🔴/🟠/🟡/🟢` 格式标注，便于对照规则文件学习。

## 注意事项

1. **无需编译**: 对于 Java 项目，不需要编译即可进行审计
2. **阅读文档**: 审计前请先阅读 SKILL.md 中的审计流程
3. **多语言支持**: 多语言项目会自动加载多个标准文件，规则间会自动去重
4. **时间戳命名**: 报告文件默认添加时间戳，避免覆盖历史报告
5. **目录清理**: 报告生成并验证成功后，findings 目录会自动清空

## 性能特点

- **快速扫描**: ~1 秒（29 个基线发现）
- **内存去重**: < 0.1 秒（62 条发现）
- **报告生成**: < 1 秒（包含验证和目录清理）
- **总体性能**: 相比 SQLite 方案提升约 4.5 倍

## 架构优势

### 简化版架构（当前）

```
Markdown 文件 → 内存去重 → 生成报告
```

- **无数据库依赖**: 直接遍历 Markdown 文件
- **内存去重**: 使用 Python 字典实现高效去重
- **自动清理**: 报告生成后自动清空 findings 目录

### 原架构（已废弃）

```
Markdown 文件 → SQLite 入库 → 数据库去重 → 生成报告
```

- **性能瓶颈**: 单条插入，数据库连接开销
- **复杂度高**: 需要管理数据库连接和事务
- **依赖重**: SQLite 数据库文件

## 变更日志

### v2.0.0 (2026-04-17)

#### 🎯 重大变更

- **移除 SpotBugs 依赖**：完全移除 Java 字节码扫描工具 SpotBugs，改为纯 LLM 驱动的代码审计方案
- **移除 SQLite 依赖**：改用 Markdown 文件直接存储审计发现，架构更轻量
- **简化命令行接口**：从 6 个工具简化为 2 个核心工具

#### ✨ 新增功能

- **快速扫描** (`quick_scan`)：使用正则表达式模式匹配快速发现常见漏洞
- **LLM 智能审计**：利用 Agent 的 LLM 能力进行深度语义分析
- **内存去重机制**：同文件同方法同类问题自动合并，优先保留 LLM 审计结果
- **时间戳命名**：报告文件自动添加时间戳（`audit_report_YYYYMMDD_HHMMSS.md`），便于追溯和管理
- **灵活参数解析**：支持 `--key=value` 和 `--key value` 两种参数格式

#### 🔧 工具变更

**新增工具：**
- `quick_scan` - 快速扫描源代码，提供基线结果
- `finalize_report` - 遍历 Markdown 文件去重并生成审计报告

**移除工具：**
- `init_report` - 不再需要数据库初始化
- `append_finding_from_file` - 改用 Markdown 文件直接存储
- `detect_language` - LLM 自主判断语言
- `get_standards` - LLM 自主选择标准
- `get_rules` - 规则文件直接读取
- `validate_finding` - 集成到 finalize_report 中
- `extract_code` - LLM 直接读取代码

#### 📦 依赖变更

- **移除**：`requirements.txt`（仅使用 Python 标准库）
- **移除**：`vendor/spotbugs/` 目录（34 个 JAR 文件）
- **移除**：`report_template.md`（模板集成到代码中）

#### 📝 文档更新

- 更新 README.md，反映 v2.0.0 架构变更
- 更新 SKILL.md，简化审计流程说明
- 更新 .gitignore，添加审计产物忽略规则

#### 🚀 性能提升

- 快速扫描：~1 秒（29 个基线发现）
- 内存去重：< 0.1 秒（62 条发现）
- 报告生成：< 1 秒（包含验证和目录清理）
- **总体性能提升约 4.5 倍**

#### 🐛 Bug 修复

- 修复 `finalize_report` 参数解析问题，支持空格分隔参数格式
- 修复报告文件名生成逻辑，避免覆盖历史报告

---

### v1.0.0 (初始版本)

- ✅ 基于 GB/T 标准的代码安全审计
- ✅ 支持多语言：Java, C/C++, C#, Python
- ✅ SQLite 数据库存储和去重
- ✅ SpotBugs 字节码扫描集成
- ✅ 标准报告生成

## 许可

MIT License

## 联系作者

- 📧 邮箱：goodhal@163.com
- 💬 微信：扫码添加

![微信二维码](image.png)
