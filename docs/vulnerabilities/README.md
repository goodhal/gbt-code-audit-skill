# 漏洞知识库

本目录按漏洞类型组织知识库，包含危险模式、安全实践、修复示例。

## 知识库文件

| 文件 | 漏洞类型 | CWE |
|------|----------|-----|
| [sql_injection.md](sql_injection.md) | SQL 注入 | CWE-89 |
| [command_injection.md](command_injection.md) | 命令注入 | CWE-78 |
| [code_injection.md](code_injection.md) | 代码注入 | CWE-94 |
| [hardcoded_credentials.md](hardcoded_credentials.md) | 硬编码凭证 | CWE-798 |
| [path_traversal.md](path_traversal.md) | 路径遍历 | CWE-22 |
| [deserialization.md](deserialization.md) | 反序列化 | CWE-502 |
| [weak_crypto.md](weak_crypto.md) | 弱加密 | CWE-327 |

## 使用方式

LLM 审计时可参考这些知识库：
- 了解漏洞的危险模式（各语言示例）
- 获取修复方案参考
- 确定 CWE 和国标映射