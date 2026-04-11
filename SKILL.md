---
name: code-security-audit
description: 基于中国国家标准的代码安全审计工具，支持多语言代码安全漏洞检测，利用 Agent 的 LLM 能力进行智能审计。
---

# 代码安全审计技能

## 什么时候使用

当你需要对代码进行安全审计，检测潜在的安全漏洞，确保代码符合中国国家标准时使用此技能。适用于代码开发、代码审查、安全评估等场景。

## 安装设置

### 依赖项
- Python 3.7+
- Java 8+（用于 SpotBugs 字节码扫描）
- SpotBugs + FindSecBugs（用于 Java 字节码扫描）

### 安装步骤
1. 克隆项目到本地
2. 确保安装了所需的依赖项
3. 加载技能到 Agent 中

## 如何使用

### 第0步：学习审计流程（重要）

在使用本技能进行代码安全审计之前，**必须先调用 `get_audit_prompt` 获取完整的审计指南**，学习审计流程和注意事项。

```python
# 第0步：获取审计指南，学习审计流程
get_audit_prompt()
```

审计指南包含：
- 完整的审计流程说明
- SpotBugs 发现验证流程
- 报告模板使用说明
- 修复代码生成指南
- 二次验证检查清单

**注意**：虽然所有工具函数都可以独立调用，但先学习审计流程可以确保审计质量和报告的合规性。

### 基本审计流程

1. **获取审计指南**
   ```python
   # 调用工具获取审计指南
   get_audit_prompt()
   ```

2. **检测代码语言**
   ```python
   # 检测目标目录的代码语言
   detect_language(target="/path/to/code")
   ```

3. **获取适用标准**
   ```python
   # 获取语言对应的审计标准
   get_standards(languages=["java", "python"])
   ```

4. **学习标准规则**
   ```python
   # 获取标准的完整规则
   get_rules(standard="34944", format="summary")
   ```

5. **执行工具扫描**
   ```python
   # 执行 SpotBugs 字节码扫描
   scan(target="/path/to/java-project", bytecode=True)
   ```

6. **智能审计**
   ```python
   # 使用 LLM 进行智能审计
   audit_code(target="/path/to/code")
   ```

7. **生成报告**
   ```python
   # 获取报告模板
   get_report_template()
   ```

### 完整审计脚本

使用提供的 `full_audit.py` 脚本执行完整的审计流程：

```bash
python full_audit.py
```

## 功能特性

- **多语言支持**: C/C++、Java、C#、Python、JavaScript、TypeScript、Go 等
- **国标覆盖**: GB/T 34943-2017 (C/C++)、GB/T 34944-2017 (Java)、GB/T 34946-2017 (C#)、GB/T 39412-2020 (通用)
- **双重检测**: SpotBugs 字节码扫描 + LLM 智能审计
- **智能去重**: 同文件同方法同类问题自动合并
- **标准报告**: 按国标章节分类，生成合规审计报告

## 支持的标准

| 标准              | 语言    | 规则数 |
| --------------- | ----- | --: |
| GB/T 34943-2017 | C/C++ |  32 |
| GB/T 34944-2017 | Java  |  44 |
| GB/T 34946-2017 | C#    |  44 |
| GB/T 39412-2020 | 通用    |  97 |

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

## 审计流程

### 完整审计流程

```
0️⃣ 学习流程     → 调用 get_audit_prompt → 获取审计指南，学习审计流程
1️⃣ 语言判定     → 调用 detect_language → 得到适用标准（包含39412通用基线）
2️⃣ 学习标准     → 调用 get_rules → 读取规则文件，输出「已学习标准」确认
3️⃣ 双轨扫描     → 调用 scan（SpotBugs 字节码扫描） + LLM 遍历所有源文件审计
4️⃣ 汇总合并     → 工具发现 ∪ LLM发现 → 去重合并
5️⃣ 国标映射     → 每个发现标注 GB/TXXXXX-X.X
6️⃣ 生成报告     → 调用 get_report_template → 生成审计报告
```

### 详细步骤说明

#### 步骤 0：学习审计流程
**目的**：了解完整的审计流程和注意事项，确保审计质量。

**操作**：
```python
# 获取审计指南
result = get_audit_prompt()
# 仔细阅读返回的审计指南内容
```

**输出**：完整的审计指南，包含流程说明、验证流程、报告模板使用说明等。

#### 步骤 1：语言判定
**目的**：检测目标代码目录使用的编程语言，确定适用的审计标准。

**操作**：
```python
# 检测代码语言
result = detect_language(target="/path/to/code")
# 查看检测到的语言和适用标准
languages = result["languages"]
standards = result["standards"]
```

**输出**：
- 检测到的语言列表
- 适用标准列表（自动包含 GB/T 39412-2020 通用基线）
- 各语言文件数量统计

#### 步骤 2：学习标准
**目的**：学习适用的国家标准规则，为后续审计提供依据。

**操作**：
```python
# 获取标准规则
for standard in standards:
    rules = get_rules(standard=standard, format="summary")
    # 学习规则内容
```

**输出**：
- 标准名称和规则数量
- 规则列表（包含规则编号、CWE、名称、严重程度）

**重要**：必须输出「已学习标准」确认，格式如下：
```
✅ 已学习标准：
   - GB/T 39412-2020（通用基线）：XX条规则
   - GB/T 34944-2017（Java专用）：XX条规则
   - 本次审计共 XX 条规则待检查
```

#### 步骤 3：双轨扫描
**目的**：通过工具扫描和 LLM 智能审计双重方式发现安全问题。

**操作**：
```python
# 工具扫描（SpotBugs 字节码扫描）
scan_result = scan(target="/path/to/code", bytecode=True)

# LLM 智能审计
audit_result = audit_code(target="/path/to/code")
```

**输出**：
- SpotBugs 发现的问题列表
- LLM 审计请求（包含代码文件、规则信息等）

**注意事项**：
- SpotBugs 扫描需要 Java 环境和编译后的 .class 文件
- LLM 审计会遍历所有源文件，逐条对照规则检查

#### 步骤 4：汇总合并
**目的**：合并工具发现和 LLM 发现，去除重复问题。

**操作**：
- 按 (文件, CWE) 去重
- 保留置信度最高的发现
- 合并描述信息

**去重规则**：
- SpotBugs 和 LLM 都发现同一问题 → 保留 LLM 的（有更详细描述）
- SpotBugs 独立发现 → 补充后加入报告
- LLM 独立发现 → 直接加入报告

#### 步骤 5：国标映射
**目的**：为每个发现标注对应的国家标准章节。

**操作**：
- 根据漏洞类型查找对应国标章节
- 标注格式：GB/TXXXXX-X.X 规则名称

**示例**：
- SQL 注入 → GB/T34944-6.1.1 输入数据验证 + GB/T39412-8.3.2 SQL注入
- 硬编码密钥 → GB/T34944-7.2 密钥管理 + GB/T39412-7.1.3 敏感数据保护

#### 步骤 6：生成报告
**目的**：生成符合国家标准格式的审计报告。

**操作**：
```python
# 获取报告模板
template = get_report_template()
# 按照模板格式生成报告
```

**报告内容**：
- 封面（项目名、语言、适用标准、日期、审计人）
- 已学习标准确认
- 审计汇总（问题统计表格）
- 详细发现（按国标规则号排序）
- 二次验证（检查表格式）

**重要**：必须进行二次验证，确保报告质量。

## 工具列表

| 工具名称 | 描述 | 参数 |
|---------|------|------|
| `get_audit_prompt` | 获取审计流程和完整的审计指南 | 无 |
| `detect_language` | 检测代码目录使用的语言，返回语言列表和对应的标准 | `target` (目标代码目录路径) |
| `get_standards` | 获取语言对应的审计标准 | `languages` (语言列表，可选)、`target` (目标目录，可选) |
| `get_rules` | 获取标准的完整规则列表 | `standard` (标准代码，默认 34944)、`format` (输出格式，默认 summary) |
| `scan` | 执行工具扫描（SpotBugs 字节码扫描） | `target` (目标代码目录路径)、`bytecode` (是否执行字节码扫描，默认 false) |
| `get_report_template` | 返回标准的报告模板，供生成报告时参考 | 无 |
| `audit_code` | 使用 LLM 对代码进行安全审计 | `target` (目标代码目录路径)、`languages` (代码语言，可选)、`standards` (审计标准，可选) |

## 注意事项

1. 使用前请确保已安装 Java 8+（用于 SpotBugs 字节码扫描）
2. 对于 Java 项目，需要先编译生成 .class 文件才能进行字节码扫描
3. 审计前请先调用 `get_audit_prompt` 获取完整的审计指南
4. 多语言项目会自动加载多个标准文件，规则间会自动去重
5. 生成报告时请使用 `get_report_template` 获取标准模板，确保报告格式合规

## 许可证

MIT License
