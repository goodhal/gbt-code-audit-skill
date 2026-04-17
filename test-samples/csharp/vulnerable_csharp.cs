using System;
using System.Diagnostics;
using System.Data.SqlClient;
using System.IO;
using System.Web;
using System.Web.Mvc;
using System.Security.Cryptography;
using System.Xml;
using System.Xml.XPath;
using System.Runtime.Serialization.Formatters.Binary;
using System.Net;
using System.Text;
using System.Threading;

/**
 * C#代码安全测试样例
 * 覆盖 GB/T 34946-2017 所有规则
 * 规则编号对应标准章节
 */

namespace VulnerableApp
{
    public class VulnerableCSharp
    {
        // ========== 6.2.1 行为问题 ==========

        // [GB/T34946-6.2.1.1] 不可控的内存分配 🟠 HIGH
        public void UncontrolledMemoryAllocation(int size)
        {
            byte[] data = new byte[size];  // size来自用户输入，无上限检查
        }

        // ========== 6.2.2 路径错误 ==========

        // [GB/T34946-6.2.2.1] 不可信的搜索路径 🟡 MEDIUM
        public void UntrustedSearchPath(string command)
        {
            Process.Start(command);  // PATH可能被依赖，DLL劫持风险
        }

        // ========== 6.2.3 数据处理 ==========

        // [GB/T34946-6.2.3.1] 相对路径遍历 🟠 HIGH
        public void RelativePathTraversal(string filename)
        {
            string path = Path.Combine("/var/www/uploads/", filename);  // filename可能包含../
            string content = File.ReadAllText(path);
        }

        // [GB/T34946-6.2.3.2] 绝对路径遍历 🟠 HIGH
        public void AbsolutePathTraversal(string path)
        {
            string content = File.ReadAllText(path);  // 直接使用用户输入作为绝对路径
        }

        // [GB/T34946-6.2.3.3] 命令注入 🔴 CRITICAL
        public void CommandInjection(string filename)
        {
            Process.Start("cmd.exe", "/c type " + filename);  // 命令拼接
            Process.Start("ls", "-la " + filename);  // 参数拼接
        }

        // [GB/T34946-6.2.3.4] SQL注入 🔴 CRITICAL
        public void SqlInjection(string userId)
        {
            string sql = "SELECT * FROM users WHERE id = " + userId;  // SQL拼接
            using (SqlConnection conn = new SqlConnection("connection_string"))
            {
                SqlCommand cmd = new SqlCommand(sql, conn);
                conn.Open();
                cmd.ExecuteNonQuery();
            }
        }

        // [GB/T34946-6.2.3.5] 代码注入 🔴 CRITICAL
        public object CodeInjection(string code)
        {
            return Microsoft.CSharp.CSharpCodeProvider.CreateProvider("C#")
                .CompileAssemblyFromSource(
                    new System.CodeDom.Compiler.CompilerParameters(),
                    code);  // 动态编译执行用户代码
        }

        // [GB/T34946-6.2.3.6] 进程控制 🟠 HIGH
        public void ProcessControl(string libraryPath)
        {
            System.Reflection.Assembly.LoadFrom(libraryPath);  // 加载用户指定的DLL
        }

        // [GB/T34946-6.2.3.7] 信息通过错误消息泄露 🟡 MEDIUM
        public void InfoLeakViaErrorMsg(Exception ex, HttpResponse resp)
        {
            resp.Write("Error: " + ex.ToString());  // 泄露异常详情
            resp.Write("StackTrace: " + ex.StackTrace);
        }

        // [GB/T34946-6.2.3.8] 信息通过服务器日志文件泄露 🟡 MEDIUM
        public void InfoLeakViaServerLog(string password)
        {
            System.Diagnostics.Trace.WriteLine("User login with password: " + password);  // 密码写入日志
        }

        // [GB/T34946-6.2.3.9] 信息通过调试日志文件泄露 🟡 MEDIUM
        public void InfoLeakViaDebugLog(string token)
        {
            System.Diagnostics.Debug.WriteLine("Token value: " + token);  // 调试日志包含敏感信息
        }

        // [GB/T34946-6.2.3.10] 信息通过持久Cookie泄露 🟠 HIGH
        public void InfoLeakViaPersistentCookie(HttpResponse resp, string username)
        {
            HttpCookie cookie = new HttpCookie("username", username);  // 敏感信息存入Cookie
            cookie.Expires = DateTime.Now.AddDays(14);  // 持久化Cookie
            resp.Cookies.Add(cookie);
        }

        // [GB/T34946-6.2.3.11] 未检查的输入作为循环条件 🟡 MEDIUM
        public void UncheckedLoopCondition(int count)
        {
            for (int i = 0; i < count; i++)  // count来自用户输入，无上限检查
            {
                ProcessItem(i);
            }
        }

        // [GB/T34946-6.2.3.12] XPath注入 🟠 HIGH
        public void XPathInjection(string userInput)
        {
            XmlDocument doc = new XmlDocument();
            doc.Load("users.xml");
            string expression = "/users/user[name='" + userInput + "']";  // XPath拼接
            XPathNavigator nav = doc.CreateNavigator();
            XPathNodeIterator iter = nav.Select(expression);
        }

        // ========== 6.2.4 处理程序错误 ==========

        // [GB/T34946-6.2.4.1] 未限制危险类型文件的上传 🟠 HIGH
        public void UnrestrictedFileUpload(string filename, byte[] content)
        {
            File.WriteAllBytes("/uploads/" + filename, content);  // 未检查文件类型
        }

        // ========== 6.2.5 不充分的封装 ==========

        // [GB/T34946-6.2.5.1] 违反信任边界 🟡 MEDIUM
        public void TrustBoundaryViolation(HttpRequest req, HttpSessionState session)
        {
            string username = req["username"];  // 不可信数据
            session["username"] = username;  // 直接存入session，未验证
        }

        // ========== 6.2.6 安全功能 ==========

        // [GB/T34946-6.2.6.1] 明文存储口令 🔴 CRITICAL
        public void PlaintextPasswordStorage(string password)
        {
            string sql = "INSERT INTO users (password) VALUES ('" + password + "')";  // 明文存储
            using (SqlConnection conn = new SqlConnection("connection_string"))
            {
                SqlCommand cmd = new SqlCommand(sql, conn);
                conn.Open();
                cmd.ExecuteNonQuery();
            }
        }

        // [GB/T34946-6.2.6.2] 存储可恢复的口令 🔴 CRITICAL
        public void RecoverablePasswordStorage(string password)
        {
            // AES对称加密存储口令（可逆）
            Aes aes = Aes.Create();
            aes.Key = Encoding.UTF8.GetBytes("fixedKey12345678");  // 固定密钥
            byte[] encrypted = aes.CreateEncryptor().TransformFinalBlock(
                Encoding.UTF8.GetBytes(password), 0, password.Length);
            // 存储encrypted到数据库
        }

        // [GB/T34946-6.2.6.3] 口令硬编码 🔴 CRITICAL
        private const string HARDCODED_PASSWORD = "admin123";  // 硬编码口令
        private const string DB_PASSWORD = "Server=localhost;Password=hardcoded_pass";  // 硬编码数据库密码
        
        public bool CheckHardcodedPassword(string input)
        {
            return HARDCODED_PASSWORD == input;  // 硬编码比对
        }

        // [GB/T34946-6.2.6.4] 依赖Referer字段进行身份鉴别 🟠 HIGH
        public bool RefererAuthentication(HttpRequest req)
        {
            string referer = req.Headers["referer"];  // 依赖referer进行身份鉴别
            return referer != null && referer.Contains("trusted-domain.com");
        }

        // [GB/T34946-6.2.6.5] Cookie中的敏感信息明文存储 🟠 HIGH
        public void SensitiveDataInCookie(HttpResponse resp)
        {
            HttpCookie cookie = new HttpCookie("creditCard", "1234-5678-9012-3456");  // 明文敏感信息
            resp.Cookies.Add(cookie);
        }

        // [GB/T34946-6.2.6.6] 敏感信息明文传输 🔴 CRITICAL
        public void PlaintextTransmission(string password)
        {
            // HTTP明文传输敏感信息（未使用HTTPS）
            WebClient client = new WebClient();
            client.DownloadString("http://api.example.com/login?password=" + password);
        }

        // [GB/T34946-6.2.6.7] 使用已破解或危险的加密算法 🟠 HIGH
        public void WeakEncryptionAlgorithm(string data)
        {
            DES des = DES.Create();  // DES已被破解
            des.Key = Encoding.UTF8.GetBytes("12345678");
            byte[] encrypted = des.CreateEncryptor().TransformFinalBlock(
                Encoding.UTF8.GetBytes(data), 0, data.Length);
        }

        // [GB/T34946-6.2.6.8] 可逆的散列算法 🟠 HIGH
        public string ReversibleHashAlgorithm(string password)
        {
            using (SHA1 sha1 = SHA1.Create())  // SHA-1已被破解
            {
                byte[] hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(password));
                return Convert.ToBase64String(hash);
            }
        }

        // [GB/T34946-6.2.6.9] 密码分组链接模式未使用随机初始化矢量 🟡 MEDIUM
        public void CbcWithoutRandomIV(string data)
        {
            byte[] fixedIV = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};  // 固定IV
            Aes aes = Aes.Create();
            aes.Key = Encoding.UTF8.GetBytes("1234567890abcdef");
            aes.IV = fixedIV;  // 使用固定IV
            byte[] encrypted = aes.CreateEncryptor().TransformFinalBlock(
                Encoding.UTF8.GetBytes(data), 0, data.Length);
        }

        // [GB/T34946-6.2.6.10] 不充分的随机数 🟠 HIGH
        public void InsufficientRandomness()
        {
            Random random = new Random();  // 不安全的伪随机数生成器
            byte[] iv = new byte[16];
            random.NextBytes(iv);  // 用于安全场景
        }

        // [GB/T34946-6.2.6.11] 安全关键的行为依赖反向域名解析 🟡 MEDIUM
        public bool ReverseDnsTrust(string ipAddress)
        {
            IPHostEntry host = Dns.GetHostEntry(ipAddress);
            return host.HostName.EndsWith("trusted.com");  // 依赖反向DNS解析进行信任判断
        }

        // [GB/T34946-6.2.6.12] 没有要求使用强口令 🟡 MEDIUM
        public bool WeakPasswordPolicy(string password)
        {
            // 仅检查长度，未检查复杂度
            return password.Length >= 4;
        }

        // [GB/T34946-6.2.6.13] 没有对口令域进行掩饰 🟢 LOW
        public void PasswordFieldNotMasked()
        {
            // GUI中口令输入框未设置掩码（示例）
            // TextBox passwordField = new TextBox();  // 应使用PasswordChar属性
        }

        // [GB/T34946-6.2.6.14] 依赖未经验证和完整性检查的Cookie 🟠 HIGH
        public bool UnverifiedCookieAuth(HttpRequest req)
        {
            HttpCookie cookie = req.Cookies["isAdmin"];
            if (cookie != null)
            {
                return cookie.Value == "true";  // Cookie未验证，可伪造
            }
            return false;
        }

        // [GB/T34946-6.2.6.15] 通过用户控制的SQL关键字绕过授权 🟠 HIGH
        public void SqlKeywordBypass(string orderBy)
        {
            string sql = "SELECT * FROM products ORDER BY " + orderBy;  // ORDER BY由用户控制
            using (SqlConnection conn = new SqlConnection("connection_string"))
            {
                SqlCommand cmd = new SqlCommand(sql, conn);
                conn.Open();
                cmd.ExecuteNonQuery();
            }
        }

        // [GB/T34946-6.2.6.16] HTTPS会话中的敏感cookie没有设置安全属性 🟡 MEDIUM
        public void CookieWithoutSecureAttribute(HttpResponse resp)
        {
            HttpCookie sessionCookie = new HttpCookie("sessionId", "abc123");
            // 未设置Secure属性
            resp.Cookies.Add(sessionCookie);
        }

        // [GB/T34946-6.2.6.17] 未使用盐值计算散列值 🟠 HIGH
        public string HashWithoutSalt(string password)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));  // 未使用盐值
                return Convert.ToBase64String(hash);
            }
        }

        // [GB/T34946-6.2.6.18] RSA算法未使用最优非对称加密填充 🟠 HIGH
        public void RsaWithoutOAEP(string data)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);
            byte[] encrypted = rsa.Encrypt(Encoding.UTF8.GetBytes(data), false);  // false表示使用PKCS1填充
        }

        // ========== 6.2.7 时间和方法状态 ==========

        // [GB/T34946-6.2.7.1] 会话固定 🟠 HIGH
        public void SessionFixation(HttpRequest req, HttpSessionState session)
        {
            string username = req["username"];
            session["user"] = username;  // 登录前未创建新session，使用原有session ID
        }

        // [GB/T34946-6.2.7.2] 会话永不过期 🟡 MEDIUM
        public void SessionNeverTimeout(HttpSessionState session)
        {
            session.Timeout = int.MaxValue;  // 设置为永不过期
        }

        // ========== 6.2.8 Web问题 ==========

        // [GB/T34946-6.2.8.1] 跨站脚本（XSS） 🟠 HIGH
        public void CrossSiteScripting(string name, HttpResponse resp)
        {
            resp.Write("Hello " + name);  // 直接输出，未转义
        }

        // [GB/T34946-6.2.8.2] 跨站请求伪造（CSRF） 🟠 HIGH
        public ActionResult CsrfVulnerability(string to, decimal amount)
        {
            // 没有CSRF token验证
            return new ContentResult { Content = "Transferred " + amount + " to " + to };
        }

        // [GB/T34946-6.2.8.3] HTTP响应拆分 🟠 HIGH
        public void HttpResponseSplitting(string userInput, HttpResponse resp)
        {
            resp.AddHeader("X-Custom", userInput);  // userInput可能包含\r\n
        }

        // [GB/T34946-6.2.8.4] 开放重定向 🟡 MEDIUM
        public void OpenRedirect(string url, HttpResponse resp)
        {
            resp.Redirect(url);  // url来自用户输入，未验证
        }

        // [GB/T34946-6.2.8.5] 依赖外部提供的文件的名称或扩展名 🟠 HIGH
        public void FileNameExtensionTrust(string filename, byte[] content)
        {
            if (filename.EndsWith(".jpg"))  // 仅检查扩展名，未检查文件内容
            {
                File.WriteAllBytes("/uploads/" + filename, content);
            }
        }

        // ========== 6.2.9 用户界面错误 ==========

        // [GB/T34946-6.2.9.1] 点击劫持 🟡 MEDIUM
        public void Clickjacking(HttpResponse resp)
        {
            // 未设置X-Frame-Options头
            resp.Write("<html><body>Sensitive content</body></html>");
        }

        // ========== 辅助方法 ==========

        private void ProcessItem(int index) { }
    }
}