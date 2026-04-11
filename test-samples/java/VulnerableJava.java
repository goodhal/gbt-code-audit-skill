package com.test.vulnerabilities;

import java.io.*;
import java.sql.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.regex.Pattern;

/**
 * Java代码安全测试样例
 * 覆盖 GB/T 34944-2017 所有章节
 */
public class VulnerableJava {

    // ========== 第10章 错误处理 ==========

    // [10.1] 空catch块 - 静默忽略异常
    public void emptyCatchBlock() {
        try {
            Integer.parseInt("abc");
        } catch (Exception e) {
            // 空catch块，静默忽略
        }
    }

    // [10.1] 只打印不处理
    public void printStackOnly() {
        try {
            FileInputStream fis = new FileInputStream("config.txt");
        } catch (IOException e) {
            e.printStackTrace();  // 只打印，不向上传递或记录
        }
    }

    // [10.2] 错误信息泄露
    public void exposeErrorDetails(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try {
            int id = Integer.parseInt(req.getParameter("id"));
        } catch (Exception e) {
            resp.getWriter().write("Error: " + e.toString());  // 泄露异常详情
            resp.getWriter().write("Stack: " + Arrays.toString(e.getStackTrace()));
        }
    }

    // ========== 第11章 代码质量 ==========

    // [11.1] 空指针解引用
    public String nullPointerRisk() {
        Map<String, String> map = getConfig();
        return map.get("key").toLowerCase();  // NPE风险
    }

    // [11.2] 资源未关闭
    public void resourceLeak() {
        Connection conn = null;
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost/test", "root", "pass");
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT * FROM users");
            // 没有finally块关闭资源
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // ========== 第12章 封装 ==========

    // [12.1] 不安全反序列化
    public Object unsafeDeserialization(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();  // RCE风险
    }

    // [12.2] 反射注入
    public Object reflectionInjection(String className, String methodName) throws Exception {
        Class<?> clazz = Class.forName(className);  // 动态加载任意类
        Object obj = clazz.getDeclaredConstructor().newInstance();
        java.lang.reflect.Method method = clazz.getMethod(methodName);
        return method.invoke(obj);
    }

    // ========== 第14章 Web安全 ==========

    // [14.1] XSS漏洞
    public void xssVulnerability(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        resp.getWriter().write("Hello " + name);  // 直接输出，未转义
    }

    // [14.2] SQL注入
    public List<User> sqlInjection(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test", "root", "pass");
        String sql = "SELECT * FROM users WHERE id = " + userId;  // SQL注入
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        // 处理结果...
        return new ArrayList<>();
    }

    // [14.3] 命令注入
    public void commandInjection(String filename) throws IOException {
        Runtime rt = Runtime.getRuntime();
        Process proc = rt.exec("cat " + filename);  // 命令注入
    }

    // ========== 第15章 数据保护 ==========

    // [15.1] 硬编码密钥
    private static final String AES_KEY = "1234567890abcdef";  // 硬编码密钥

    public String decryptWithHardcodedKey(String data) throws Exception {
        // 使用硬编码密钥
        javax.crypto.spec.SecretKeySpec key = new javax.crypto.spec.SecretKeySpec(AES_KEY.getBytes(), "AES");
        return "decrypted";
    }

    // [15.2] 敏感数据日志泄露
    public void logSensitiveData(String password) {
        System.out.println("Password reset for user: " + password);  // 密码日志泄露
    }

    // ========== 第16章 线程安全 ==========

    // [16.1] 竞态条件
    private int counter = 0;

    public void raceCondition() {
        int temp = counter;  // 读取
        // 其他线程可能修改counter
        counter = temp + 1;  // 写入
    }

    // [16.2] 不安全的单例
    private static VulnerableJava instance;

    public static VulnerableJava getInstance() {
        if (instance == null) {  // 竞态条件
            instance = new VulnerableJava();
        }
        return instance;
    }

    // ========== 第17章 SQL注入 (MyBatis ${} 注入) ==========

    // [17.1] MyBatis ${} 注入
    public List<User> mybatisInjection(String tableName, String orderBy) {
        // 模拟MyBatis ${}注入
        String sql = "SELECT * FROM " + tableName + " ORDER BY " + orderBy;
        return new ArrayList<>();
    }

    // ========== 第19章 代码注入 ==========

    // [19.1] Groovy动态代码执行
    public Object groovyInjection(String script) {
        // 模拟Groovy脚本注入
        return "eval(" + script + ")";
    }

    // [19.2] SpEL表达式注入
    public Object spelInjection(String expression) {
        // 模拟SpEL注入
        return "#{ " + expression + " }";
    }

    // ========== 第20章 日志输出 ==========

    // [20.1] 日志注入
    public void logInjection(String userInput) {
        System.out.println("User input: " + userInput);  // 日志注入
    }

    // ========== 辅助方法 ==========

    private Map<String, String> getConfig() {
        return null;
    }

    private static class User {
        public String id;
        public String name;
    }
}
