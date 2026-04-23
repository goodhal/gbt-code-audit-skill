# 输出质量检查标准

本文档定义审计报告的质量检查规则，防止敷衍内容。

## 修复方案编写要求

### ❌ 禁止以下敷衍内容（出现则验证失败）

1. "根据国标要求修复"
2. "消除安全隐患"
3. "使用安全的方法"
4. "加强验证"
5. "进行过滤"
6. "根据相关标准处理"
7. "修复安全漏洞"
8. 字数 < 30 字
9. 不包含具体代码、命令、配置或 API 名称
10. 不包含可执行的技术方案

### ✅ 必须包含以下内容

1. **具体代码示例**（如 `PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");`）
2. **或具体命令**（如 `chmod 600 /etc/secret`）
3. **或具体 API/类名**（如 `Cipher.getInstance("AES/GCM/NoPadding")`、`BCrypt.hashpw()`）
4. **或具体配置参数**（如 `-fstack-protector`、`TLS 1.2+`）
5. **字数 ≥ 30 字**
6. **必须包含技术动作词**：如"使用"、"改用"、"替代"、"配置"、"启用"等

---

## 修复方案示例库

| 漏洞类型 | ✅ 合格修复方案 | ❌ 不合格修复方案 |
|---------|----------------|-----------------|
| SQL 注入 | 使用 PreparedStatement：`ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); ps.setString(1, userId);` 禁止字符串拼接 SQL。 | 根据国标要求修复，消除安全隐患。 |
| 命令注入 | 改用 ProcessBuilder 参数数组：`new ProcessBuilder("cat", filename).start()` 并对 filename 白名单验证仅允许字母数字。 | 使用安全的方法执行命令。 |
| 硬编码密码 | 密码移至环境变量：`System.getenv("DB_PASSWORD")` 或使用配置文件（权限 600），口令存储使用 bcrypt 哈希。 | 加强密码管理。 |
| 弱加密 | 使用 AES-256/GCM 替代 DES：`Cipher.getInstance("AES/GCM/NoPadding")` 密钥至少 256 位，使用 SecureRandom 生成。 | 使用更安全的加密算法。 |
| 弱哈希 | 使用 SHA-256 或 SM3 替代 MD5/SHA-1，口令哈希使用 bcrypt：`BCrypt.hashpw(password, BCrypt.gensalt(12))`。 | 进行过滤。 |
| 缓冲区溢出 | 使用 strncpy 替代 strcpy：`strncpy(buf, input, sizeof(buf)-1); buf[sizeof(buf)-1] = '\0';` 启用编译器保护 `-fstack-protector`。 | 加强边界检查。 |
| 反序列化 | 禁止 pickle.loads() 反序列化不受信任数据，改用 JSON，或实现白名单类限制可反序列化的类。 | 进行验证。 |

---

## 双保险验证机制

### 第一道：LLM 自主检查（创建 md 时执行）

LLM 创建 md 文件时必须自行检查修复方案质量：

| 检查项 | 要求 | 示例 |
|--------|------|------|
| 字数 | ≥ 30 字 | ❌ "根据国标修复" → ✅ 提供具体代码 |
| 禁用词 | 不含"根据国标""消除隐患""加强""进行过滤" | ❌ "使用安全的方法" → ✅ "改用 ProcessBuilder" |
| 技术关键词 | 包含 `()`、`=`、`:` 或"使用""改用""替代""配置" | ❌ "加强验证" → ✅ "使用 PreparedStatement" |

### 第二道：validate_finding 函数验证（程序化检查）

`validate_finding` 函数会自动检查修复方案质量，验证失败将拒绝该 md 文件：
- 字数 < 30 → 拒绝
- 包含禁用词 → 拒绝
- 不含技术关键词 → 拒绝

---

## 分步确认清单

### 步骤 5（基线入库）完成确认

```
【步骤 5 完成确认】
- 已创建：X 个 md 文件
- 已验证：每个文件的修复方案≥30 字，包含具体代码/命令/API
- 无敷衍内容：已检查无"根据国标""消除隐患"等敷衍词汇
- 下一步：步骤 6 - LLM 审计
```

### 步骤 6（LLM 审计）完成确认

```
【步骤 6 完成确认】
- 已执行：LLM 独立审计所有源文件
- 已验证：所有 md 文件通过 validate_finding 验证（含修复方案质量检查）
- 独立性：未参考快速扫描结果，逐行阅读源代码
- 修复方案：每个漏洞的修复方案包含具体代码或配置，字数≥30
- 下一步：步骤 7 - 生成报告
```