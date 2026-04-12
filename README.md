# 代码安全审计技能（Code Security Audit Skill）

基于中国国家标准（GB/T 34943/34944/34946/39412）的代码安全审计技能，支持 C/C++、Java、C#、Python、JavaScript 等语言的源代码安全漏洞扫描和检测。该技能利用 Agent 的 LLM 能力进行智能审计，不需要 API Key 和 LLM 客户端。

## 功能特性

- **多语言支持**: C/C++、Java、C#、Python、JavaScript、TypeScript、Go 等
- **国标覆盖**: GB/T 34943-2017 (C/C++)、GB/T 34944-2017 (Java)、GB/T 34946-2017 (C#)、GB/T 39412-2020 (通用)
- **双重检测**: SpotBugs 字节码扫描 + LLM 智能审计
- **智能去重**: 同文件同方法同类问题自动合并
- **标准报告**: 按国标章节分类，生成合规审计报告
- **无需 API Key**: 直接利用 Agent 的内置 LLM 能力

## 快速开始

### 安装依赖

```bash
# 克隆项目
git clone https://github.com/goodhal/gbt-code-audit-skill.git
cd gbt-code-audit-skill

# 安装 Python 依赖
pip install -r requirements.txt
```

### Java 工具扫描（可选）

若要使用 SpotBugs 进行 Java 字节码扫描，本机需安装 JDK 8+：

1. 下载并安装 JDK：[Oracle JDK](https://www.oracle.com/java/technologies/downloads/) 或 [OpenJDK](https://openjdk.java.net/)
2. 确保 `java` 命令在系统 PATH 中
3. 编译 Java 代码生成 `.class` 文件（SpotBugs 需要字节码文件）

```bash
# 编译 Java 代码
javac -d ./bin ./src/**/*.java
```

### 使用技能

在 Trae IDE 中加载技能，然后按照以下流程使用：

```bash
# 第0步：阅读 SKILL.md 中的「报告生成规则」章节，学习审计流程

# 第1步：检测代码语言
python skill.py detect_language /path/to/code

# 第2步：获取适用标准
python skill.py get_standards --languages=java,python

# 第3步：学习标准规则（standard: 34943/34944/34946/39412）
python skill.py get_rules 39412

# 第4步：执行工具扫描
python skill.py scan /path/to/java-project --bytecode

# 第5步：智能审计
python skill.py audit_code /path/to/code

# 第6步：获取报告模板
python skill.py get_report_template
```

## 支持的标准

| 标准 | 语言 | 规则数 |
|------|------|-------:|
| GB/T 34943-2017 | C/C++ | 32 |
| GB/T 34944-2017 | Java | 44 |
| GB/T 34946-2017 | C# | 44 |
| GB/T 39412-2020 | 通用 | 97 |

覆盖：

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

## 输出报告

```markdown
# 代码安全审计报告

| 严重等级 | 数量 | 来源 |
|:--------:|-----:|------|
| 🔴 严重 | XX | SpotBugs: X, LLM: X |
| 🟠 高危 | XX | SpotBugs: X, LLM: X |
| 🟡 中危 | XX | SpotBugs: X, LLM: X |
| 🟢 低危 | XX | SpotBugs: X, LLM: X |
| **总计** | **XX** | |

### 问题汇总表格
每个问题包含：
- 严重等级、CWE 编号、来源
- 涉及国标章节
- 问题代码示例
- 修复建议代码示例
- 上下文安全分析
```

## 项目结构

```
gbt-code-audit-skill/
├── README.md              # 项目说明
├── SKILL.md               # 技能文档
├── _meta.json             # 技能元数据
├── _skillhub_meta.json    # 技能中心元数据
├── manifest.json          # 技能配置文件
├── skill.py               # 技能主入口
├── requirements.txt       # 项目依赖
├── .gitignore             # Git 忽略配置
├── rules/                 # 国标规则文件
│   ├── GBT_34943-2017.md
│   ├── GBT_34944-2017.md
│   ├── GBT_34946-2017.md
│   └── GBT_39412-2020.md
├── report_template.md     # 报告模板
├── test-samples/          # 测试样例
│   ├── cpp/
│   ├── csharp/
│   ├── java/
│   └── python/
└── vendor/                # 第三方工具
    └── spotbugs/          # SpotBugs + FindSecBugs
```

## 审计流程

```
0️⃣ 学习流程     → 阅读 SKILL.md → 学习审计流程和注意事项
1️⃣ 语言判定     → 调用 detect_language → 得到适用标准（包含39412通用基线）
2️⃣ 学习标准     → 调用 get_rules → 读取规则文件，输出「已学习标准」确认
3️⃣ 双轨扫描     → 调用 scan（SpotBugs 字节码扫描） + LLM 遍历所有源文件审计
4️⃣ 汇总合并     → 工具发现 ∪ LLM发现 → 去重合并
5️⃣ 国标映射     → 每个发现标注 GB/TXXXXX-X.X
6️⃣ 获取报告模板 → 调用 get_report_template → 得到标准报告模板
7️⃣ 生成报告     → 按模板格式生成审计报告
```

## 工具列表

| 工具名称 | 描述 | 参数 |
|---------|------|------|
| `detect_language` | 检测代码目录使用的语言，返回语言列表和对应的标准 | `target` (目标代码目录路径) |
| `get_standards` | 获取语言对应的审计标准 | `languages` (语言列表，可选)、`target` (目标目录，可选) |
| `get_rules` | 获取标准的完整规则列表 | `standard` (标准代码，默认 34944)、`format` (输出格式，默认 summary) |
| `scan` | 执行工具扫描（SpotBugs 字节码扫描） | `target` (目标代码目录路径)、`bytecode` (是否执行字节码扫描，默认 false) |
| `get_report_template` | 返回标准的报告模板，供生成报告时参考 | 无 |
| `audit_code` | 使用 LLM 对代码进行安全审计 | `target` (目标代码目录路径)、`languages` (代码语言，可选)、`standards` (审计标准，可选) |

## 测试样例

测试样例位于 `test-samples/` 目录，包含：

- `java/VulnerableJava.java` - 20+ 漏洞点
- `cpp/vulnerable_cpp.cpp` - 15+ 漏洞点
- `csharp/vulnerable_csharp.cs` - 12+ 漏洞点
- `python/vulnerable_python.py` - 18+ 漏洞点

## 注意事项

1. 使用前请确保已安装 Java 8+（用于 SpotBugs 字节码扫描）
2. 对于 Java 项目，需要先编译生成 .class 文件才能进行字节码扫描
3. 审计前请先阅读 SKILL.md 中的「报告生成规则（强制）」章节
4. 多语言项目会自动加载多个标准文件，规则间会自动去重
5. 生成报告时请使用 `get_report_template` 获取标准模板，确保报告格式合规

## 许可

MIT License
