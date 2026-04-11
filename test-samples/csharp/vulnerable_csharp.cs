using System;
using System.Diagnostics;
using System.Data.SqlClient;
using System.IO;
using System.Web;
using System.Web.Mvc;

/**
 * C#代码安全测试样例
 * 覆盖 GB/T 34946-2017 所有章节
 */

namespace VulnerableApp
{
    // ========== 第10章 错误处理 ==========

    // [10.1] 空catch块
    public class ErrorHandling
    {
        public void EmptyCatchBlock()
        {
            try
            {
                int.Parse("abc");
            }
            catch (Exception)
            {
                // 空catch块，静默忽略
            }
        }

        // [10.2] 错误信息泄露
        public void ExposeErrorDetails(Exception ex)
        {
            Response.Write("Error: " + ex.ToString());  // 泄露详细信息
            Response.Write("StackTrace: " + ex.StackTrace);
        }
    }

    // ========== 第11章 代码质量 ==========

    public class CodeQuality
    {
        // [11.1] 空指针解引用
        public string NullPointerRisk(Dictionary<string, string> config)
        {
            return config["key"].ToLower();  // NPE风险
        }

        // [11.2] 资源未关闭
        public void ResourceLeak()
        {
            SqlConnection conn = new SqlConnection("Server=localhost;Database=test;User=sa;Password=pass");
            conn.Open();
            SqlCommand cmd = new SqlCommand("SELECT * FROM users", conn);
            SqlDataReader reader = cmd.ExecuteReader();
            // 没有using或finally关闭连接
        }
    }

    // ========== 第12章 封装 ==========

    public class Encapsulation
    {
        // [12.1] 不安全反序列化
        public object UnsafeDeserialization(byte[] data)
        {
            System.Runtime.Serialization.Formatters.Binary.BinaryFormatter bf =
                new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            return bf.Deserialize(new MemoryStream(data));  // 反序列化RCE
        }

        // [12.2] 动态代码执行
        public object DynamicCodeExecution(string code)
        {
            return Microsoft.CSharp.CSharpCodeProvider.CreateProvider("C#")
                .CompileAssemblyFromSource(
                    new System.CodeDom.Compiler.CompilerParameters(),
                    code);  // 动态编译执行
        }
    }

    // ========== 第14章 Web安全 ==========

    public class WebSecurity : Controller
    {
        // [14.1] XSS漏洞
        public ActionResult XssVulnerability(string name)
        {
            return Content("Hello " + name);  // 直接输出，未转义
        }

        // [14.2] SQL注入
        public void SqlInjection(string userId)
        {
            string sql = "SELECT * FROM users WHERE id = " + userId;  // SQL注入
            using (SqlConnection conn = new SqlConnection("connection_string"))
            {
                SqlCommand cmd = new SqlCommand(sql, conn);
                conn.Open();
                cmd.ExecuteNonQuery();
            }
        }

        // [14.3] 命令注入
        public void CommandInjection(string filename)
        {
            Process.Start("cmd.exe", "/c type " + filename);  // 命令注入
        }

        // [14.4] LDAP注入
        public void LdapInjection(string username)
        {
            string ldapQuery = "(uid=" + username + ")";  // LDAP注入
        }

        // [14.5] 路径遍历
        public void PathTraversal(string filename)
        {
            string path = Path.Combine("/var/www/uploads/", filename);
            string content = File.ReadAllText(path);  // 路径遍历
        }
    }

    // ========== 第15章 数据保护 ==========

    public class DataProtection
    {
        // [15.1] 硬编码密钥
        private const string AES_KEY = "1234567890abcdef";  // 硬编码密钥

        // [15.2] 敏感数据日志
        public void LogSensitiveData(string password)
        {
            Console.WriteLine("Password reset: " + password);  // 密码日志
        }

        // [15.3] ViewState未加密
        public void UnencryptedViewState()
        {
            // ViewState.EnableViewStateMac = false;
            // ViewStateEncryptionMode = ViewStateEncryptionMode.Never;
        }
    }

    // ========== 第16章 线程安全 ==========

    public class ThreadSafety
    {
        private int counter = 0;
        private static int staticCounter = 0;

        // [16.1] 竞态条件
        public void RaceCondition()
        {
            int temp = counter;
            // 其他线程可能修改counter
            counter = temp + 1;
        }

        // [16.2] 非线程安全单例
        private static ThreadSafety instance;

        public static ThreadSafety GetInstance()
        {
            if (instance == null)  // 竞态条件
            {
                instance = new ThreadSafety();
            }
            return instance;
        }
    }

    // ========== 第17章 XML注入 ==========

    public class XmlInjection
    {
        // [17.1] XXE
        public void XxeVulnerability(string xml)
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xml);  // XXE
        }
    }

    // ========== 第18章 日志输出 ==========

    public class Logging
    {
        // [18.1] 日志注入
        public void LogInjection(string userInput)
        {
            Console.WriteLine("User input: " + userInput);  // 日志注入
        }
    }

    // ========== 第19章 CSRF ==========

    public class CsrfVulnerability : Controller
    {
        // [19.1] CSRF
        public ActionResult TransferMoney(string to, decimal amount)
        {
            // 没有CSRF token验证
            return Content("Transferred " + amount + " to " + to);
        }
    }
}
