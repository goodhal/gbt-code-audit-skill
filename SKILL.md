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

### 基本审计流程

1. **检测代码语言**
   ```python
   # 检测目标目录的代码语言
   detect_language(target="/path/to/code")
   ```

2. **获取适用标准**
   ```python
   # 获取语言对应的审计标准
   get_standards(languages=["java", "python"])
   ```

3. **学习标准规则**
   ```python
   # 获取标准的完整规则
   get_rules(standard="34944", format="summary")
   ```

4. **执行工具扫描**
   ```python
   # 执行 SpotBugs 字节码扫描
   scan(target="/path/to/java-project", bytecode=True)
   ```

5. **智能审计**
   ```python
   # 使用 LLM 进行智能审计
   audit_code(target="/path/to/code")
   ```

6. **生成报告**
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

| 标准 | 语言 | 规则数 |
|------|------|-------:|
| GB/T 34943-2017 | C/C++ | 32 |
| GB/T 34944-2017 | Java | 44 |
| GB/T 34946-2017 | C# | 44 |
| GB/T 39412-2020 | 通用 | 97 |

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

> ⚠️ **强制要求**：审计流程中涉及的每个步骤，如 skill.py 中有对应方法，**必须调用该方法**，禁止跳过或自行模拟结果！

Agent 执行代码安全审计的标准流程：

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Agent 代码安全审计流程                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  0️⃣ 学习流程  ◀ 【强制，不可跳过】                                  │
│      └─ 阅读 SKILL.md → 了解审计流程和注意事项                      │
│                                                                     │
│  1️⃣ 语言判定  ◀ 【必须调用 detect_language】                        │
│      └─ 调用 detect_language → 得到适用标准（包含39412通用基线）    │
│                                                                     │
│  2️⃣ 学习标准  ◀ 【强制，不可跳过】                                  │
│      └─ 调用 get_rules → 得到标准规则详情                           │
│      └─ ⚠️ 审计前必须输出「已学习标准」确认，格式如下：              │
│                                                                     │
│  ✅ 已学习标准：                                                     │
│     - GB/T 39412-2020（通用基线）：XX条规则                          │
│     - GB/T 34944-2017（Java专用）：XX条规则                          │
│     - 本次审计共 XX 条规则待检查                                     │
│                                                                     │
│  3️⃣ 双轨扫描                                                        │
│      ├─ 工具扫描  ◀ 【必须调用 scan】                                │
│      │   └─ 调用 scan --bytecode（SpotBugs 字节码）                 │
│      │   ⚠️ 不可跳过（除非无Java环境/无.class文件）                 │
│      │   ⚠️ 结果保存到 spotbugs_result.json                        │
│      └─ LLM审计：Agent 遍历所有源文件，逐条对照国标规则检查         │
│          ⚠️ 必须：审计所有源文件，不是只验证                        │
│          ⚠️ 目标：发现工具漏掉的问题                                │
│                                                                     │
│  3️⃣🅰️ SpotBugs 发现验证（重要）                                     │
│      ├─ 国标比对：所有发现先与已学国标规则比对                       │
│      │   ⚠️ 符合国标规则的发现必须报告，不能直接丢弃！              │
│      ├─ 验证：读源码确认是否真阳性                                   │
│      ├─ 补充：description / fix_code / verification / standards     │
│      └─ 去重：与 LLM 发现比较，避免重复                              │
│                                                                     │
│  4️⃣ 汇总合并                                                        │
│      └─ 工具发现 ∪ LLM自主发现 → 去重合并                           │
│          - SpotBugs审计                                              │
│          - LLM：不管工具审计的结果，再独立按学习到的标准规则对所有源文件审计 │
│          - 去重：同一文件同一行同一类型只保留一个                    │
│                                                                     │
│  5️⃣ 国标映射  ◀ 【强制】                                            │
│      └─ 每个发现必须标注：GB/TXXXXX-X.X                              │
│      └─ 典型映射示例：                                               │
│         - SQL 注入 → GB/T34944-6.1.1 + GB/T39412-8.3.2              │
│         - 硬编码密钥 → GB/T34944-7.2 + GB/T39412-7.1.3              │
│         - 路径穿越 → GB/T34944-6.3 + GB/T39412-8.2.1                │
│                                                                     │
│  6️⃣ 获取报告模板  ◀ 【必须调用 get_report_template】                │
│      └─ 调用 get_report_template → 得到标准报告模板                 │
│                                                                     │
│  7️⃣ 生成报告                                                        │
│      └─ 封面 → 审计汇总 → 详细发现（按规则号排序）→ 二次验证         │
│      └─ ⚠️ 必须按照 get_report_template 返回的标准模板格式输出       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 详细步骤说明

#### 步骤 0：学习审计流程（重要）

在使用本技能进行代码安全审计之前，**必须先阅读 SKILL.md 了解完整的审计流程和注意事项**。

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

**语言检测规则**：

| 语言 | 必读标准 | 说明 |
|------|----------|------|
| Java | GB/T 34944-2017 + GB/T 39412-2020 | 专用标准 + 通用基线 |
| C/C++ | GB/T 34943-2017 + GB/T 39412-2020 | 专用标准 + 通用基线 |
| C# | GB/T 34946-2017 + GB/T 39412-2020 | 专用标准 + 通用基线 |
| 其他 | GB/T 39412-2020 | 仅通用基线 |

多语言项目：同时读取多个标准文件，标准间规则互补，重复规则自动去重。

**规则过滤原则**：叠加时，通用标准中不适用于当前语言的规则（如指针规则之于 Java）直接忽略，不影响审计结果。

**39412 通用标准说明**：

GB/T 39412-2020 是所有语言的**通用基线**，不是补充：
- 所有语言都必须先加载 39412
- 有专用标准的语言（Java/C/C++/C#）叠加专用标准
- 无专用标准的语言（Python/Go/JS/PHP等）仅用 39412
- 注入类（SQL/命令/代码）、加密类、Web 安全类 → 通用

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
- LLM审计请求（包含代码文件、规则信息等）

**⚠️ 工具扫描强制要求**：
- **工具扫描不可跳过**，除非遇到以下情况：
  - Java 环境未安装（需要 JDK）
  - 目标目录无 Java 源文件
  - 目标目录无编译后的 .class 文件
- **如果扫描失败但非环境问题**，必须排查原因并重试，不能直接跳过
- 扫描结果会保存到 `spotbugs_result.json` 文件，供后续分析
- **推荐做法**：扫描编译输出目录（如 `target/classes`）而非整个项目

**注意事项**：
- SpotBugs 扫描需要 Java 环境和编译后的 .class 文件
- LLM审计会遍历所有源文件，逐条对照规则检查
- 结果中 `scanned_classes` 表示实际扫描的文件数，`total_classes` 表示总文件数

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

## SpotBugs 发现验证流程

SpotBugs 字节码扫描会返回大量发现，需要 LLM 验证后才能合并到最终报告。

### 验证步骤

**1. 国标规则比对（关键步骤）**
> ⚠️ **所有工具扫描发现问题应先与已学国标规则比对，所有符合国标规则的发现都应报告。不能直接丢弃！**

对于每个 SpotBugs 发现，按以下流程处理：

```
SpotBugs 发现 → 查找对应 CWE → 检查是否在已学习的国标规则中 → 决定处理方式
```

| 比对结果 | 处理方式 |
|----------|----------|
| CWE 在国标规则中 | ✅ 必须验证并加入报告 |
| CWE 不在国标规则中，但属于安全相关 | ⚠️ 评估是否需要关注 |
| CWE 不在国标规则中，且非安全问题 | ❌ 可以丢弃 |

**常见 SpotBugs 发现类型与国标规则对应关系**：

| SpotBugs 类型 | CWE | 国标规则 | 是否计入 |
|---------------|-----|----------|----------|
| SQL_INJECTION | CWE-89 | GB/T34944-6.1.1, GB/T39412-8.3.2 | ✅ |
| COMMAND_INJECTION | CWE-78 | GB/T34944-6.2.1, GB/T39412-8.3.3 | ✅ |
| PATH_TRAVERSAL_IN | CWE-22 | GB/T34944-6.3.1, GB/T39412-8.2.2 | ✅ |
| DESERIALIZATION | CWE-502 | GB/T34944-12.1.1, GB/T39412-8.5.1 | ✅ |
| XXE | CWE-611 | GB/T39412-8.4.1 | ✅ |
| XSS | CWE-79 | GB/T39412-8.6.1 | ✅ |
| HARD_CODE_PASSWORD | CWE-259 | GB/T34944-7.2.1, GB/T39412-7.1.3 | ✅ |
| WEAK_CRYPTO | CWE-327 | GB/T39412-7.1.1 | ✅ |
| PREDICTABLE_RANDOM | CWE-338 | GB/T39412-7.1.2 | ✅ |
| RESOURCE_LEAK | CWE-772 | GB/T39412-6.3.1 | ✅ 资源释放问题 |
| NULL_DEREFERENCE | CWE-476 | GB/T39412-7.4.1 | ✅ 空指针异常 |
| REC_CATCH_EXCEPTION | CWE-396 | GB/T39412-7.4.2 | ⚠️ 异常处理问题 |
| SPRING_ENDPOINT | - | - | ❌ 非安全问题 |

**2. 真阳性验证**
对于符合国标规则的发现，必须读源码验证：

```python
# SpotBugs 返回的发现
{
  "type": "SQL_INJECTION_JDBC",
  "file": "UserDao.java",
  "line": 42,
  "cwe": "CWE-89"
}

# LLM 验证步骤：
1. 读取 UserDao.java 第 42 行附近代码
2. 确认是否存在 SQL 字符串拼接
3. 确认用户输入是否可控
4. 判断是否真阳性
```

**3. 补充完整信息**
SpotBugs 只返回基本信息，需要 LLM 补充：

```json
{
  "cwe": "CWE-89",
  "severity": "高危",
  "confidence": "高",
  "file": "UserDao.java",
  "line": 42,
  "description": "SQL注入漏洞：用户输入直接拼接到SQL语句，攻击者可执行任意SQL命令",
  "problem_code": "// 实际源代码",
  "fix_code": "// 使用参数化查询修复",
  "verification": "检查是否已改用PreparedStatement",
  "source": "spotbugs",
  "standards": ["GB/T34944-6.1.1 输入数据验证", "GB/T39412-8.3.2 SQL注入"]
}
```

**4. 去重合并**
与 LLM 自己的发现比较，避免重复：

| 场景 | 处理 |
|------|------|
| SpotBugs 和 LLM 都发现同一问题 | 保留 LLM 的（有更详细描述） |
| SpotBugs 独立发现 | 补充后加入报告 |
| LLM 独立发现 | 直接加入报告 |

### 去重规则

```
去重键: (file, cwe)

示例：
- LLM 发现: ("JDBC.java", "CWE-89")
- SpotBugs 发现: ("JDBC.java", "CWE-89")
→ 重复，保留 LLM 的

- LLM 发现: ("JDBC.java", "CWE-89")
- SpotBugs 发现: ("Upload.java", "CWE-22")
→ 不重复，都保留
```

### 源代码提取

SpotBugs 只返回文件名（如 `UserDao.java`），不返回完整路径。

提取源代码方法：
```python
# 方法1：在项目目录递归搜索
import Path
matches = list(project_path.rglob("UserDao.java"))

# 方法2：优先选择 src/main/java 下的文件
java_files = [m for m in matches if 'src/main/java' in str(m)]
```

### 验证示例

**SpotBugs 原始发现：**
```json
{
  "type": "JACKSON_UNSAFE_DESERIALIZATION",
  "file": "JacksonVul.java",
  "line": 38,
  "cwe": "CWE-502"
}
```

**LLM 验证后：**
```json
{
  "cwe": "CWE-502",
  "severity": "严重",
  "confidence": "高",
  "file": "JacksonVul.java",
  "line": 38,
  "description": "Jackson反序列化RCE：enableDefaultTyping()开启后，攻击者可通过JSON指定恶意类导致远程代码执行",
  "problem_code": ">>>   38: String payload = \"[\\\"com.oracle.wls.shaded.org.apache.xalan.lib.sql.JNDIConnectionPool\\\",{\"jndiPath\":\"ldap://127.0.0.1:1389/zrnug1\"}]\";\n      39: ObjectMapper mapper = new ObjectMapper();\n      40: mapper.enableDefaultTyping();",
  "fix_code": "// 禁用 DefaultTyping 或使用白名单\nObjectMapper mapper = new ObjectMapper();\nmapper.disable(DeserializationFeature.USE_JAVA_LANG_OBJECT_FOR_EMPTY_STRINGS);\n// 或配置安全的类型解析器",
  "verification": "检查是否已关闭 enableDefaultTyping 或配置了安全的反序列化策略",
  "source": "spotbugs",
  "standards": ["GB/T34944-12.1.1 对象注入", "GB/T39412-8.5.1 反序列化"]
}
```

### 规则输出格式要求

**⚠️ 规则输出格式要求（必须遵守）**：
- 规则必须包含：**规则号 + 规则名称**
- 格式：`GB/T{标准号}-{章节号} {规则名称}`
- ✅ 正确：`GB/T34944-6.1.1 输入数据验证`、`GB/T39412-8.3.2 SQL注入`
- ❌ 错误：`GB/T34944-6.1.1`（缺少规则名称）

**如何确定规则**：
1. 根据漏洞类型，在规则文件中查找对应章节
2. 例如 SQL 注入 → 查找规则文件中的 "SQL 注入" → 找到 `GB/T39412-8.3.2 SQL 注入`
3. 将完整的规则（规则号 + 规则名称）写入 standards 字段

## 修复代码生成指南

LLM 验证 SpotBugs 发现或自主审计时，生成的修复代码必须满足以下要求：

### 修复代码质量要求

1. **必须是可执行代码**（不是伪代码或注释）
2. **必须针对具体漏洞类型**（不能用通用模板）
3. **必须保留原有功能**（不能只删代码）
4. **必须有注释说明修复原理**
5. **优先使用安全库**（如有 OWASP、Apache Commons 等）

### 常见漏洞修复模式

| 漏洞类型 | CWE | 修复方法 | 示例 |
|---------|-----|---------|------|
| **SQL 注入** | CWE-89 | 参数化查询（PreparedStatement） | `PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?")` |
| **命令注入** | CWE-78 | 避免拼接，用 ProcessBuilder + 参数列表 | `ProcessBuilder pb = new ProcessBuilder("ping", userInput)` |
| **XSS** | CWE-79 | 输出编码（OWASP Encoder） | `Encode.forHtml(userInput)` |
| **反序列化** | CWE-502 | 白名单类型解析器 | `mapper.activateDefaultTyping(ptv, DefaultTyping.NON_FINAL)` |
| **路径遍历** | CWE-22 | 文件名白名单 + 规范化 | `Path p = baseDir.resolve(userPath).normalize().toAbsolutePath()` |
| **SSRF** | CWE-918 | URL 白名单 + 内网 IP 段校验 | `if (!isInternalIp(url.getHost())) { ... }` |
| **XXE** | CWE-611 | 禁用外部实体 | `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` |
| **硬编码密码** | CWE-259 | 使用密钥管理服务 | `String key = System.getenv("DB_PASSWORD")` |
| **弱加密算法** | CWE-327 | 使用安全算法（AES-GCM、SHA-256） | `Cipher.getInstance("AES/GCM/NoPadding")` |
| **弱随机数** | CWE-338 | 使用安全随机数生成器 | `SecureRandom.getInstanceStrong()` |

### 修复代码示例

#### SQL 注入修复

**问题代码**：
```java
String sql = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql);
```

**修复代码**：
```java
// 使用参数化查询，防止 SQL 注入
String sql = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = conn.prepareStatement(sql);
stmt.setString(1, userId);
ResultSet rs = stmt.executeQuery();
```

#### 命令注入修复

**问题代码**：
```java
String cmd = "ping " + userHost;
Runtime.getRuntime().exec(cmd);
```

**修复代码**：
```java
// 使用 ProcessBuilder 参数列表，避免命令拼接
// 可选：添加白名单校验 userHost 是否为合法域名/IP
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", userHost);
pb.start();
```

#### 反序列化修复

**问题代码**：
```java
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();
Object obj = mapper.readValue(json, Object.class);
```

**修复代码**：
```java
// 方案1：禁用 DefaultTyping
ObjectMapper mapper = new ObjectMapper();
mapper.disable(DeserializationFeature.USE_JAVA_LANG_OBJECT_FOR_EMPTY_STRINGS);

// 方案2：使用白名单类型解析器（推荐）
ObjectMapper mapper = new ObjectMapper();
PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
    .allowIfBaseType(Object.class)
    .allowIfSubType("com.yourcompany.")
    .build();
mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);
```

#### 路径遍历修复

**问题代码**：
```java
File file = new File(baseDir + "/" + userPath);
```

**修复代码**：
```java
// 规范化路径 + 校验是否在允许的目录内
Path basePath = Paths.get(baseDir).normalize().toAbsolutePath();
Path targetPath = basePath.resolve(userPath).normalize().toAbsolutePath();

if (!targetPath.startsWith(basePath)) {
    throw new SecurityException("非法路径");
}
File file = targetPath.toFile();
```

#### XXE 修复

**问题代码**：
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(inputStream);
```

**修复代码**：
```java
// 禁用外部实体，防止 XXE 攻击
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(inputStream);
```

### 修复代码检查清单

每条修复代码生成后，必须检查：

- [ ] 是否是可执行代码（不是伪代码）
- [ ] 是否针对具体漏洞类型（不是通用模板）
- [ ] 是否保留原有功能（没有破坏业务逻辑）
- [ ] 是否有注释说明修复原理
- [ ] 是否符合项目编码规范
- [ ] 是否已考虑边界情况

## 上下文安全分析维度

审计和二次验证时，必须综合分析以下因素：

### 1. 上下级调用的安全处理
- **上游调用是否已做安全处理？**
  - 输入是否已验证/净化？
  - 是否有参数校验？
  - 如上游已充分处理，可去掉此问题
- **下游调用是否有保护？**
  - 调用链中是否有安全边界？
  - 是否在网关/Filter层有防护？

### 2. 方法名敏感度
| 敏感度 | 示例 | 评估权重 |
|--------|------|----------|
| 高 | `login`, `auth`, `pwd`, `secret`, `encrypt`, `decrypt`, `exec`, `eval` | 高权重 |
| 中 | `process`, `handle`, `parse`, `update`, `delete` | 中权重 |
| 低 | `get`, `set`, `list`, `query`, `find` | 低权重 |

### 3. 业务重要性
| 业务场景 | 示例 | 风险放大系数 |
|----------|------|--------------|
| 核心业务 | 认证、支付、订单、资金 | ×1.5 |
| 用户数据 | 用户信息、地址、联系方式 | ×1.3 |
| 一般业务 | 查询、统计、配置 | ×1.0 |
| 内部工具 | 管理后台、运维工具 | ×0.8 |

### 4. 综合判断规则
```
最终风险 = 基础风险等级 × 上下文系数

上下文系数 = (上游安全处理系数) × (方法敏感度系数) × (业务重要性系数)

- 上下文系数 > 1.2：升级风险等级
- 上下文系数 < 0.8：降级风险等级
- 上下文系数 0.8~1.2：维持原等级
```

**示例**：
- `PlatformController.custom()`: 反射调用 + 上游无验证 = 高风险 × 1.5 = 🔴严重
- `getUserByName(name)`: 上游已有SQL净化 + 非核心查询 = 中风险 × 0.7 = 🟡中危

## 工具列表

| 工具名称 | 描述 | 参数 |
|---------|------|------|
| `detect_language` | 检测代码目录使用的语言，返回语言列表和对应的标准 | `target` (目标代码目录路径) |
| `get_standards` | 获取语言对应的审计标准 | `languages` (语言列表，可选)、`target` (目标目录，可选) |
| `get_rules` | 获取标准的完整规则列表 | `standard` (标准代码，默认 34944)、`format` (输出格式，默认 summary) |
| `scan` | 执行工具扫描（SpotBugs 字节码扫描） | `target` (目标代码目录路径)、`bytecode` (是否执行字节码扫描，默认 false) |
| `get_report_template` | 返回标准的报告模板，供生成报告时参考 | 无 |
| `audit_code` | 使用 LLM 对代码进行安全审计 | `target` (目标代码目录路径)、`languages` (代码语言，可选)、`standards` (审计标准，可选) |

## 注意事项

1. 使用前请确保已安装 JDK（用于 SpotBugs 字节码扫描）
2. 对于 Java 项目，需要先编译生成 .class 文件才能进行字节码扫描
3. 多语言项目会自动加载多个标准文件，规则间会自动去重
4. 生成报告时请使用 `get_report_template` 获取标准模板，确保报告格式合规

## 报告生成规则（强制）

### 核心原则：每个问题必须独立展示

> ⚠️ **【强制】禁止合并展示，每个问题独立条目**

**独立展示规则**：
1. **同一文件、不同行号** → 每行一个独立问题条目
2. **不同文件、同类型漏洞** → 每个文件一个独立问题条目
3. **即使代码完全相同** → 只要在不同文件/行号，必须分开列出

**禁止合并示例**：
```markdown
❌ 错误（合并）：
### 硬编码密钥 — Java/Python/C++/C#
文件: A.java:110, B.py:105, C.cpp:120, D.cs:130

✅ 正确（独立）：
### 🔴 [严重] 硬编码密钥 — Java
**文件**: `A.java:110`
...

### 🔴 [严重] 硬编码密钥 — Python
**文件**: `B.py:105`
...

### 🔴 [严重] 硬编码密钥 — C++
**文件**: `C.cpp:120`
...

### 🔴 [严重] 硬编码密钥 — C#
**文件**: `D.cs:130`
...
```

**数量一致性要求**：
- 统计表中的问题数 = 详细发现中的独立问题条目数
- 统计表写 55 个 → 详细发现必须有 55 个独立条目
- 不允许统计表和详细发现数量不一致

### 条目格式要求

每个问题必须包含以下 **10** 个字段：

| # | 字段 | 格式要求 | 常见错误 |
|---|------|----------|---------|
| 1 | **问题编号** ⚠️ | `#N`（N从1开始递增） | ❌ **缺少编号** |
| 2 | **来源标注** ⚠️ | 🤖 LLM审计 / 🔧 SpotBugs | ❌ **缺少来源标注** |
| 3 | **文件** | `文件名:行号` | ❌ 表格格式、❌ 省略行号 |
| 4 | **标准分类** | `GB/T34944-X.X + GB/T39412-X.X` | ❌ 缺少章节号、❌ **39412缺失** |
| 5 | **CWE** | `CWE-XX` + 链接 | ❌ 无链接、❌ 错误CWE编号 |
| 6 | **置信度** ⚠️ | 高/中/低 | ❌ **最容易遗漏，单独检查** |
| 7 | **问题** | 2-3句，说清攻击后果 | ❌ 太笼统 |
| 8 | **问题代码块** | ```[语言]``` + 行号 + 完整上下文 | ❌ 表格代替、❌ 只有片段、❌ 省略 |
| 9 | **修复代码块** | ```[语言]``` + 可执行修复代码 | ❌ 表格代替、❌ 只有描述、❌ "见上述" |
| 10 | **验证** | 一句话确认修复 | ❌ 遗漏 |

**格式红线（触犯任何一条立即修正）**：
- **禁止用表格代替代码块** — 只能用 ```[语言]``` 格式
- **禁止省略字段** — 10个字段缺一不可
- **禁止只有描述无代码** — 问题代码和修复代码必须同时存在
- **禁止表格格式条目** — 所有条目必须是标准模板格式
- **禁止在代码块里写"见上述"或"同上"** — 修复代码块必须独立完整
- ⛔ **禁止条目内无代码块** — 每个条目必须同时有「问题代码块」和「修复代码块」
- ⛔ **禁止缺少问题编号** — 每个条目必须有唯一的编号，便于统计和引用
- ⛔ **禁止缺少来源标注** — 必须明确标注是 LLM审计发现还是 SpotBugs 工具发现

**条目分隔硬性规则**：
- 每条发现之间必须用 `\n---\n` 分隔
- 禁止两个条目之间无分隔符直接相连
- 分隔符 = `\n` + `---` + `\n`，三个元素缺一不可

### 完整条目模板

```markdown
### #1 🔴 [严重] [漏洞类型] — [语言] 🤖 LLM审计

**文件**：`[文件名:行号]`

**标准分类**：
- GB/T 34944-X.X（Java专用）
- GB/T 39412-X.X（通用基线）

**CWE**：[CWE-XX](https://cwe.mitre.org/data/definitions/XX.html)

**置信度**：高 / 中 / 低

**问题**：
[2-3句话，说清攻击者能干什么，攻击后果]

**问题代码**：
```[语言]
// [文件名:行号]
[有问题的代码片段，必须包含行号注释]
```

**修复代码**：
```[语言]
// 修复后的安全代码
[可执行的修复方案，必须可直接使用]
```

**验证**：
[一句话说明如何确认修复成功]
```

**来源标注说明**：
- 🤖 **LLM审计**：由 LLM 遍历源代码自主发现的问题
- 🔧 **SpotBugs**：由 SpotBugs + FindSecurityBugs 工具扫描发现，经 LLM 验证后确认的问题

## 二次验证（强制）

> ⚠️ **二次验证是审计报告的核心质量保证环节，必须认真执行！**
> ⚠️ **每项检查必须实际验证，不能凭空勾选！**

生成完报告后，**必须按以下检查表逐项认真验证并勾选**：

```markdown
## 二次验证

| # | 检查项 | 结果 | 备注 |
|---|--------|------|------|
| 1 | 问题编号：每个问题都有唯一编号（#1, #2, ...） | ☑ 通过 ☐ 缺失 (X 条) | |
| 2 | 来源标注：每个问题都有来源（🤖 LLM审计 / 🔧 SpotBugs） | ☑ 通过 ☐ 缺失 (X 条) | |
| 3 | 真实性验证：每个问题的代码上下文确实存在该问题 | ☑ 通过 ☐ 存疑 (X 条) | |
| 4 | CWE 正确性：CWE 编号与漏洞类型匹配 | ☑ 通过 ☐ 错误 (X 条) | |
| 5 | 定类准确性：国标章节映射正确 | ☑ 通过 ☐ 错误 (X 条) | |
| 6 | 上游安全处理：已验证上游是否有安全处理 | ☑ 通过 ☐ 需关注 (X 条) | |
| 7 | 下游保护：已验证下游是否有保护措施 | ☑ 通过 ☐ 需关注 (X 条) | |
| 8 | 修复可行性：每个问题都有可行修复方案 | ☑ 通过 ☐ 不可修复 (X 条) | |
```

**状态说明**：
- `☑ 通过`：该项检查通过
- `☐ 存疑/错误/需关注/不可修复 (X 条)`：该项存在问题，括号内填写具体数量

### 报告生成前自检（5项）

```markdown
## 报告生成前自检

### 【判定结果】自检一：双标准统计表检查
| 检查项 | 结果 |
|--------|------|
| 34944 独立统计表存在（章节 + 问题数） | ☑ ☐ |
| 39412 独立统计表存在（章节 + 问题数） | ☑ ☐ |
| 每个问题的标准分类包含 34944 + 39412 | ☑ ☐ |

---

### 【判定结果】自检二：来源数量一致性检查
| 检查项 | 结果 |
|--------|------|
| SpotBugs 发现数 + LLM审计发现数 = 总发现数 | ☑ ☐ |
| LLM审计发现数 > 0 | ☑ ☐ |

---

### 【判定结果】自检三：二次验证完整性检查
| 检查项 | 结果 |
|--------|------|
| 8 项检查全部填写（不能有空白） | ☑ ☐ |
| 备注栏有具体数字（X 条） | ☑ ☐ |

---

### 【判定结果】自检四：问题来源标注检查
| 检查项 | 结果 |
|--------|------|
| 每个 TOP 问题有来源标注（🤖 / 🔧） | ☑ ☐ |
| 来源与实际审计方法一致 | ☑ ☐ |

---

### 【判定结果】自检五：国标映射完整性检查
| 检查项 | 结果 |
|--------|------|
| 每个问题至少有一个国标章节 | ☑ ☐ |
| 无法归类的问题归入「其它」 | ☑ ☐ |
```

**⚠️ 硬性规则**：
- 5项自检全部通过 ← 才能生成最终报告
- 任何一项不通过 ← 立即修正后再生成
- 不得以"时间不够"跳过任何一项

---

## 许可证

MIT License
