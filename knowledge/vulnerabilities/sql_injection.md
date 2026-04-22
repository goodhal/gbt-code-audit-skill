# SQL 注入漏洞知识库

## 漏洞概述

SQL注入是一种代码注入技术，攻击者通过在应用程序查询中插入恶意SQL代码来操纵数据库。

## 危险模式

### Java
```java
// 危险 - 字符串拼接
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = conn.createStatement();
stmt.executeQuery(query);

// 危险 - ORM原始查询
User.objects.raw("SELECT * FROM users WHERE name = '" + name + "'");
```

### Python
```python
# 危险 - 字符串拼接
query = f"SELECT * FROM users WHERE name = '{name}'"
cursor.execute(query)

# 危险 - 格式化字符串
query = "SELECT * FROM users WHERE id = %s" % user_id
```

### C/C++
```cpp
// 危险
char query[256];
sprintf(query, "SELECT * FROM users WHERE id = %s", user_id);
```

## 安全实践

1. 使用参数化查询/预编译语句
2. 使用ORM框架的安全API
3. 输入验证和类型检查
4. 最小权限原则

## 修复示例

### Java
```java
// 安全 - 参数化查询
PreparedStatement pstmt = conn.prepareStatement(
    "SELECT * FROM users WHERE id = ?"
);
pstmt.setString(1, userId);

// 安全 - JPA
User user = entityManager.find(User.class, userId);
```

### Python
```python
# 安全 - 参数化查询
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# 安全 - SQLAlchemy
result = db.query(User).filter(User.id == user_id)
```

## CWE 关联

- CWE-89: SQL Injection
- CWE-943: Improper Neutralization of Special Elements in Data Query Logic

## 国标映射

| 语言 | 标准 |
|------|------|
| Java | GB/T34944-6.2.3.4 SQL 注入 |
| C/C++ | GB/T34943-6.2.3.4 SQL 注入 |
| C# | GB/T34946-6.2.3.4 SQL 注入 |
| Python | GB/T39412-8.3.2 SQL 注入 |
