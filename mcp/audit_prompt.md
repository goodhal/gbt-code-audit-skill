# 代码安全审计 Agent 提示词

## 审计流程

Agent 执行代码安全审计的标准流程：

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Agent 代码安全审计流程                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  0️⃣ 读取提示词  ◀ 【强制，不可跳过】                                 │
│      └─ 调用 MCP: get_audit_prompt → 得到完整的提示词内容           │
│                                                                     │
│  1️⃣ 语言判定                                                        │
│      └─ 调用 MCP: detect_language → 得到适用标准                   │
│                                                                     │
│  2️⃣ 学习标准  ◀ 【强制，不可跳过】                                  │
│      └─ 调用 MCP: get_rules → 得到标准规则详情                     │
│      └─ ⚠️ 审计前必须输出「已学习标准」确认，格式如下：              │
│                                                                     │
│  ✅ 已学习标准：                                                     │
│     - GB/T 39412-2020（通用基线）：XX条规则                          │
│     - GB/T 34944-2017（Java专用）：XX条规则                          │
│     - 本次审计共 XX 条规则待检查                                     │
│                                                                     │
│  3️⃣ 双轨扫描                                                        │
│      ├─ 工具扫描：调用 MCP: scan --bytecode（SpotBugs 字节码）      │
│      └─ LLM审计：Agent 遍历所有源文件，逐条对照规则检查             │
│          ⚠️ 必须：审计所有源文件（Java/JS/Python 等），不是只验证   │
│          ⚠️ 目标：发现工具漏掉的问题（逻辑漏洞、硬编码、配置缺陷等）   │
│                                                                     │
│  3️⃣🅰️ SpotBugs 发现验证（重要）                                     │
│      ├─ 分类：安全漏洞类 vs 代码质量类 vs 误报                       │
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
│  6️⃣ 获取报告模板  ◀ 【强制】                                        │
│      └─ 调用 MCP: get_report_template → 得到标准报告模板            │
│                                                                     │
│  7️⃣ 生成报告                                                        │
│      └─ 封面 → 审计汇总 → 详细发现（按规则号排序）→ 二次验证         │
│      └─ ⚠️ 必须按照 get_report_template 返回的标准模板格式输出       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## SpotBugs 发现验证流程

SpotBugs 字节码扫描会返回大量发现，需要 LLM 验证后才能合并到最终报告。

### 验证步骤

**1. 分类筛选**
SpotBugs 发现分为三类：

| 类别 | 示例 | 处理方式 |
|------|------|----------|
| 安全漏洞类 | SQL_INJECTION、COMMAND_INJECTION、DESERIALIZATION、XXE、SSRF | ✅ 必须验证 |
| 代码质量类 | SPRING_ENDPOINT、REC_CATCH_EXCEPTION、资源泄漏 | ❌ 通常不计入安全问题 |
| 误报 | 正常业务逻辑被误判 | ❌ 过滤掉 |

**2. 真阳性验证**
对于安全漏洞类发现，必须读源码验证：

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
  "severity": "高危",  // LLM 根据上下文评估
  "confidence": "高",
  "file": "UserDao.java",
  "line": 42,
  "description": "SQL注入漏洞：用户输入直接拼接到SQL语句，攻击者可执行任意SQL命令",  // LLM 补充
  "problem_code": "// 实际源代码",  // 从源文件提取
  "fix_code": "// 使用参数化查询修复",  // LLM 生成
  "verification": "检查是否已改用PreparedStatement",  // LLM 补充
  "source": "spotbugs",
  "standards": ["GB/T34944-6.1.1 输入数据验证", "GB/T39412-8.3.2 SQL注入"]  // LLM 从规则文件中查找并输出完整规则（规则号 + 规则名称）
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

**⚠️ 规则输出格式要求（必须遵守）**：
- 规则必须包含：**规则号 + 规则名称**
- 格式：`GB/T{标准号}-{章节号} {规则名称}`
- ✅ 正确：`GB/T34944-6.1.1 输入数据验证`、`GB/T39412-8.3.2 SQL注入`
- ❌ 错误：`GB/T34944-6.1.1`（缺少规则名称）

**如何确定规则**：
1. 根据漏洞类型，在规则文件中查找对应章节
2. 例如 SQL 注入 → 查找规则文件中的 "SQL 注入" → 找到 `GB/T39412-8.3.2 SQL 注入`
3. 将完整的规则（规则号 + 规则名称）写入 standards 字段
```

---

## 报告模板使用说明

**调用方法**：
```
调用 MCP: get_report_template → 得到标准报告模板
```

**模板内容**：
`get_report_template` 返回标准的审计报告模板，包含以下部分：

1. **封面**：项目名、语言、适用标准、日期、审计人
2. **已学习标准**：列出已学习的国标及规则数
3. **审计汇总**：问题汇总表格、按国标分类统计
4. **详细发现**：每个问题的完整描述（问题、问题代码、修复代码、验证）
5. **二次验证**：真实性、CWE 正确性、定类准确性等检查项

**使用要求**：
- ✅ 必须调用 `get_report_template` 获取标准模板
- ✅ 必须按照模板格式生成报告
- ✅ 必须填写所有必填字段（用 `[ ]` 标注的部分）
- ✅ 统计表格必须准确反映实际发现数量

---

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
    .allowIfSubType("com.yourcompany.")  // 只允许你的包名
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

---

## MCP 调用指南

### 1. detect_language - 检测语言
```bash
python audit_mcp.py --method detect_language --target ./code_dir
```
返回：检测到的语言和对应的标准

### 2. get_standards - 获取标准
```bash
python audit_mcp.py --method get_standards --languages java,python
# 或自动检测
python audit_mcp.py --method get_standards --target ./code_dir
```
返回：语言对应的标准列表

### 3. get_rules - 获取规则详情
```bash
python audit_mcp.py --method get_rules --standard 34944 --format summary
```
返回：标准的完整规则列表（用于 Agent 参考）

### 4. get_categories - 获取分类定义
```bash
python audit_mcp.py --method get_categories
```
返回：问题分类结构（12 大类）

### 5. scan - 执行工具扫描
```bash
# 字节码扫描（Java）
python audit_mcp.py --method scan --target ./code_dir --bytecode --json > tool_findings.json
```
返回：SpotBugs + FindSecurityBugs 字节码扫描结果（JSON）

### 6. 学习标准规则 - 读取 rules/*.md 文件

Agent 必须先读取对应标准的 md 文件，学习审计要点后再开始审计：



```

**多语言项目**：同时读取多个标准文件，标准间规则互补。

**每个规则包含**：
- **规则ID**: 如 GBT34944-12.1
- **严重级别**: CRITICAL / HIGH / MEDIUM / LOW
- **CWE**: 对应的 CWE 编号和链接
- **审计要点**: 如何检查该问题（Agent 审计时参考）
- **修复建议**: 具体修复方案

**Agent 审计时必须**：
1. 先完整阅读标准 md 文件
2. 记住每个章节的审计要点
3. 审计过程中对照检查每条规则
4. 发现问题时标注对应的规则 ID

## Agent 审计要点

### ⚠️ 重要：先学习标准规则

**Agent 审计前必须先读取对应标准的 md 文件**：

1. 使用 `read_file` 工具读取 `rules/GBT_XXXX-XXXX.md`
2. 理解每个规则的审计要点和修复建议
3. 审计时对照标准检查代码

### 语言检测规则
| 语言 | 必读标准 | 说明 |
|------|----------|------|
| Java | GB/T 34944-2017 + GB/T 39412-2020 | 专用标准 + 通用基线 |
| C/C++ | GB/T 34943-2017 + GB/T 39412-2020 | 专用标准 + 通用基线 |
| C# | GB/T 34946-2017 + GB/T 39412-2020 | 专用标准 + 通用基线 |
| 其他 | GB/T 39412-2020 | 仅通用基线 |

多语言项目：同时读取多个标准文件，标准间规则互补，重复规则自动去重。

**规则过滤原则**：叠加时，通用标准中不适用于当前语言的规则（如指针规则之于 Java）直接忽略，不影响审计结果。

### 39412 通用标准
GB/T 39412-2020 是所有语言的**通用基线**，不是补充：
- 所有语言都必须先加载 39412
- 有专用标准的语言（Java/C/C++/C#）叠加专用标准
- 无专用标准的语言（Python/Go/JS/PHP等）仅用 39412
- 注入类（SQL/命令/代码）、加密类、Web 安全类 → 通用

### 发现合并规则
工具发现 + Agent 发现合并时：
1. 按 (文件, 行号, CWE) 去重
2. 保留置信度最高的发现
3. 合并置信度都高时，保留更详细的描述

### 上下文安全分析维度  ◀ NEW
审计和二次验证时，必须综合分析以下因素：

#### 1. 上下级调用的安全处理
- **上游调用是否已做安全处理？**
  - 输入是否已验证/净化？
  - 是否有参数校验？
  - 如上游已充分处理，可去掉此问题
- **下游调用是否有保护？**
  - 调用链中是否有安全边界？
  - 是否在网关/Filter层有防护？

#### 2. 方法名敏感度
| 敏感度 | 示例 | 评估权重 |
|--------|------|----------|
| 高 | `login`, `auth`, `pwd`, `secret`, `encrypt`, `decrypt`, `exec`, `eval` | 高权重 |
| 中 | `process`, `handle`, `parse`, `update`, `delete` | 中权重 |
| 低 | `get`, `set`, `list`, `query`, `find` | 低权重 |

#### 3. 业务重要性
| 业务场景 | 示例 | 风险放大系数 |
|----------|------|--------------|
| 核心业务 | 认证、支付、订单、资金 | ×1.5 |
| 用户数据 | 用户信息、地址、联系方式 | ×1.3 |
| 一般业务 | 查询、统计、配置 | ×1.0 |
| 内部工具 | 管理后台、运维工具 | ×0.8 |

#### 4. 综合判断规则
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

### 验证检查清单
每个发现必须逐项验证：
- [ ] **真实性**：代码上下文确实存在问题
- [ ] **CWE 分类正确**
- [ ] **标准问题分类正确**（可命中多个国标）
- [ ] **上下文安全处理分析**：
  - 上游调用是否已做安全处理？（是→降级，否→维持/升级）
  - 下游是否有保护措施？
  - 调用链中是否有安全边界？
- [ ] **方法敏感度评估**（高/中/低）
- [ ] **业务重要性评估**（核心/用户数据/一般/内部）
- [ ] **严重等级**：综合上下文系数后是否合理
- [ ] **修复建议**：有具体可执行的修复方案

**多国标命中规则**：
- 一个问题可能同时属于多个国标（如 SQL注入 同时属于 34944-8.1.1 和 39412-8.3.1）
- 分类统计时两边都算
- 问题说明里列出所有命中的国标规则号

## 报告格式

> ⚠️ **【强制结构约束】报告必须严格按以下顺序生成，不得调换顺序：**
> ```
> 1. 封面（基本信息）
> 2. 已学习标准确认 ◀ 审计前必须输出
> 3. 审计汇总（含问题汇总表格）
>    ├─ 按严重等级统计
>    └─ 按国标分类统计
> 4. 详细发现（按国标规则号排序）
> 5. 二次验证（检查表格式）
> ```

### ✅ 已学习标准确认 ◀ 【必须输出】
```markdown
## 已学习标准

本次审计已学习以下国标：

| 标准 | 规则数 | 主要章节 |
|------|--------|----------|
| GB/T 39412-2020（通用基线） | XX | 6-9章 |
| GB/T 34944-2017（Java专用） | XX | 6-14章 |
| **合计** | **XX** | |

本次审计共覆盖 **XX** 条规则。
```

### 封面
```markdown
# 代码安全审计报告

**项目**: [项目名]
**语言**: [检测到的语言，如 Java, Python, JavaScript 等]
**适用标准**: [GB/T XXXXX-XXXX, GB/T XXXXX-XXXX]（可多标准）
**日期**: [YYYY-MM-DD]
**审计人**: Agent
```

### 明细
**⚠️ 强制要求（生成后逐项自检）：**

| # | 字段 | 格式要求 | 常见错误 |
|---|------|----------|---------|
| 1 | **文件** | `文件名:行号` | ❌ 表格格式、❌ 省略行号 |
| 2 | **标准分类** | `GB/T34944-X.X + GB/T39412-X.X` | ❌ 缺少章节号、❌ **39412缺失** |
| 3 | **CWE** | `CWE-XX` + 链接 | ❌ 无链接、❌ 错误CWE编号 |
| 4 | **置信度** ⚠️ | 高/中/低 | ❌ **最容易遗漏，单独检查** |
| 5 | **问题** | 2-3句，说清攻击后果 | ❌ 太笼统 |
| 6 | **问题代码块** | ```[语言]``` + 行号 + 完整上下文 | ❌ 表格代替、❌ 只有片段、❌ 省略 |
| 7 | **修复代码块** | ```[语言]``` + 可执行修复代码 | ❌ 表格代替、❌ 只有描述、❌ "见上述" |
| 8 | **验证** | 一句话确认修复 | ❌ 遗漏 |
| 9 | **来源标注** ⚠️ | 🤖 LLM审计 / 🔧 SpotBugs | ❌ **缺少来源标注** |

**⚠️ 格式红线（触犯任何一条立即修正）：**
- **禁止用表格代替代码块** — 只能用 ```[语言]``` 格式
- **禁止省略字段** — 8个字段缺一不可
- **禁止只有描述无代码** — 问题代码和修复代码必须同时存在
- **禁止表格格式条目** — 所有条目必须是标准模板格式
- **禁止在代码块里写"见上述"或"同上"** — 修复代码块必须独立完整
- ⛔ **禁止条目内无代码块** — 每个条目必须同时有「问题代码块」和「修复代码块」，缺任何一个=违规

**⚠️ 条目分隔硬性规则（必须遵守）：**
- 每条发现之间必须用 `\n---\n` 分隔
- 禁止两个条目之间无分隔符直接相连
- 分隔符 = `\n` + `---` + `\n`，三个元素缺一不可
- **生成后自检**：全文扫描，确认每条后都有分隔符

**⚠️ 违规检测与惩罚机制（生成后强制执行）：**

> **每生成一个条目，立即检查是否违规：**
> 1. 该条目是否有「问题代码块」（```xxx 格式，有内容）？
> 2. 该条目是否有「修复代码块」（```xxx 格式，有内容）？
> 3. 两者缺一 → **立即在原位置补充**，不允许跳过

> **违规示例（必须避免）：**
> ```markdown
> ❌ 违规：只有文字描述，无代码块
> ### 🔴 [严重] 弱加密算法
> **问题**: 使用不安全的加密算法...
> **修复建议**: 建议使用更安全的算法...
> ```
>
> ✅ 正确：必须同时包含两个代码块
> ```markdown
> ### 🔴 [严重] 弱加密算法
> **问题**: 使用不安全的加密算法...
> **问题代码**:
> ```java
> Cipher c = Cipher.getInstance("DES");  // 不安全
> ```
> **修复代码**:
> ```java
> Cipher c = Cipher.getInstance("AES/GCM/NoPadding");  // 安全
> ```
> ```

**⚠️ 自检流程（生成后必须执行，8个字段逐一核查）：**

> ⚠️ **【执行顺序】生成完所有条目后，才能开始自检；自检发现问题立即修正，不得跳过！**

1. **逐条扫描**，每个条目必须同时包含：
   - ✅ **文件**（`文件名:行号`格式）
   - ✅ **标准分类**（GB/T34944 + GB/T39412，若有语言专用标准）
   - ✅ **CWE**（CWE编号 + 链接）
   - ✅ **置信度**（高/中/低，**最容易遗漏，单独检查**）
   - ✅ **问题**（2-3句，攻击后果清晰）
   - ✅ **问题代码块**（```语言``` 格式，**必须有内容**，不是空壳）
   - ✅ **修复代码块**（```语言``` 格式，**必须有内容**，不是空壳）
   - ✅ **验证**（一句话）

2. **代码块专项检查**（最容易违规，必须单独检查）：
   - 扫描全文，找出所有 ` ```[语言]` 代码块
   - 每个条目必须有 **2个** 代码块（问题+修复）
   - 代码块内不能是空的，不能只是"省略..."，不能写"见上述"
   - 如有任何条目缺失任意一个代码块 → **立即补充**

3. 扫描分隔符，确认无连续条目无分隔符
4. 确认无误后输出最终报告


完整条目模板（**所有严重等级均使用此格式**，不可简化）：

> ⚠️ **【模板使用规则】生成每个条目时，严格按以下顺序填充，8个字段缺一不可！**
> ⚠️ **【代码块强制】问题代码块和修复代码块必须同时存在，缺一=违规！**

```markdown
### 🔴 [严重] [漏洞类型] — [语言]

**文件**：`[文件名:行号]`

**标准分类**：
- GB/T 34944-X.X（Java专用）
- GB/T 39412-X.X（通用基线）

**CWE**：[CWE-XX](https://cwe.mitre.org/data/definitions/XX.html)

**置信度**：高 / 中 / 低

**问题**：
[2-3句话，说清攻击者能干什么，攻击后果]

**问题代码** ◀【必须存在】：
```[语言]
// [文件名:行号]
[有问题的代码片段，必须包含行号注释]
```

**修复代码** ◀【必须存在】：
```[语言]
// 修复后的安全代码
[可执行的修复方案，必须可直接使用]
```

**验证**：
[一句话说明如何确认修复成功]
```

**⚠️ 条目分隔硬性规则（必须遵守，否则报告解析会失败）：**
- 每条发现之间必须用 `\n---\n` 分隔
- 禁止两个条目之间无分隔符直接相连
- 分隔符位置：`\n` + `---` + `\n`，三个元素缺一不可
- 生成后自检：若发现无分隔符，立即补上

---

## 二次验证  ◀【强制】报告生成后必须认真执行

> ⚠️ **二次验证是审计报告的核心质量保证环节，必须认真执行，不得敷衍！**
> ⚠️ **每项检查必须实际验证，不能凭空勾选！**

生成完整报告后，**必须按以下检查表逐项认真验证并勾选**：

```markdown
## 二次验证

| # | 检查项 | 结果 | 备注 |
|---|--------|------|------|
| 1 | 真实性验证：每个问题的代码上下文确实存在该问题 | ☑ 通过 ☐ 存疑 (X 条) | |
| 2 | CWE 正确性：CWE 编号与漏洞类型匹配 | ☑ 通过 ☐ 错误 (X 条) | |
| 3 | 定类准确性：国标章节映射正确 | ☑ 通过 ☐ 错误 (X 条) | |
| 4 | 上游安全处理：已验证上游是否有安全处理 | ☑ 通过 ☐ 需关注 (X 条) | |
| 5 | 下游保护：已验证下游是否有保护措施 | ☑ 通过 ☐ 需关注 (X 条) | |
| 6 | 修复可行性：每个问题都有可行修复方案 | ☑ 通过 ☐ 不可修复 (X 条) | |
```

**⚠️ 状态设置规则（必须遵守）**：
- **通过**：使用 `☑ 通过`（实心勾选）
- **存疑/错误/需关注/不可修复**：使用 `☐ 存疑 (X 条)` 等格式，括号内填写具体数量
- **禁止使用空勾选框 `☐ 通过`** — 必须明确显示状态
- **禁止留空** — 每项必须有明确结果

**⚠️ 硬性规则**：
- 不输出二次验证 = 报告不完整，不交付
- 检查表必须全部勾选（通过/存疑/错误），不得留空
- 每项检查必须实际验证，不能凭空勾选

---

**二次验证标题状态规则**：
- **全部通过**：标题写 `## ✅ 二次验证` + 所有子项写 `☑ 通过`
- **部分未通过**：标题写 `## ⚠️ 二次验证` + 通过的写 `☑ 通过`、未通过的写 `☐ 存疑/错误 (X 条)`
- **全部未通过**：标题写 `## ❌ 二次验证` + 所有子项写 `☐ 存疑/错误 (X 条)`，不得生成报告

**5项自检内容**：

```markdown
## 报告生成前自检

### 【判定结果】自检一：双标准统计表检查
| 检查项 | 结果 |
|--------|------|
| 34944 独立统计表存在（章节 + 问题数） | ✅/❌ |
| 39412 独立统计表存在（章节 + 问题数） | ✅/❌ |
| 每个问题的标准分类包含 34944 + 39412 | ✅/❌ |

---

### 【判定结果】自检二：来源数量一致性检查
| 检查项 | 结果 |
|--------|------|
| SpotBugs 发现数 + LLM审计发现数 = 总发现数 | ✅/❌ |
| LLM审计发现数 > 0 | ✅/❌ |

---

### 【判定结果】自检三：二次验证完整性检查
| 检查项 | 结果 |
|--------|------|
| 6 项检查全部填写（不能有空白） | ✅/❌ |
| 备注栏有具体数字（X 条） | ✅/❌ |

---

### 【判定结果】自检四：问题来源标注检查
| 检查项 | 结果 |
|--------|------|
| 每个TOP问题有来源标注（🤖 / 🔧） | ✅/❌ |
| 来源与实际审计方法一致 | ✅/❌ |

---

### 【判定结果】自检五：国标映射完整性检查
| 检查项 | 结果 |
|--------|------|
| 每个问题至少有一个国标章节 | ✅/❌ |
| 无法归类的问题归入「其它」 | ✅/❌ |

```

**⚠️ 硬性规则**：
- 5项自检全部通过 → 才能生成最终报告
- 任何一项不通过 → 立即修正后再生成
- 不得以"时间不够"跳过任何一项


---

