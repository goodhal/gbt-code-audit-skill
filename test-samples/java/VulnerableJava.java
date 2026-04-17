package com.test.vulnerabilities;

import java.io.*;
import java.sql.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.regex.Pattern;
import javax.xml.xpath.*;

/**
 * Java代码安全测试样例
 * 覆盖 GB/T 34944-2017 所有规则
 * 规则编号对应标准章节
 * 简化版本：移除Servlet依赖以便编译
 */
public class VulnerableJava {

    // ========== 6.2.1 行为问题 ==========

    // [GB/T34944-6.2.1.1] 不可控的内存分配 🟠 HIGH
    public void uncontrolledMemoryAllocation(int size) {
        byte[] data = new byte[size];  // size来自用户输入，无上限检查
    }

    // ========== 6.2.2 路径错误 ==========

    // [GB/T34944-6.2.2.1] 不可信的搜索路径 🟡 MEDIUM
    public void untrustedSearchPath(String command) throws Exception {
        Runtime.getRuntime().exec(command);  // command可能包含不受控路径
    }

    // ========== 6.2.3 数据处理 ==========

    // [GB/T34944-6.2.3.1] 相对路径遍历 🟠 HIGH
    public void relativePathTraversal(String filename) throws IOException {
        File file = new File("/var/www/uploads/" + filename);  // filename可能包含../
        FileInputStream fis = new FileInputStream(file);
    }

    // [GB/T34944-6.2.3.2] 绝对路径遍历 🟠 HIGH
    public void absolutePathTraversal(String path) throws IOException {
        File file = new File(path);  // 直接使用用户输入作为绝对路径
        FileInputStream fis = new FileInputStream(file);
    }

    // [GB/T34944-6.2.3.3] 命令注入 🔴 CRITICAL
    public void commandInjection(String filename) throws IOException {
        Runtime.getRuntime().exec("cat " + filename);  // 命令拼接
        ProcessBuilder pb = new ProcessBuilder("ls", "-la", filename);
        pb.start();
    }

    // [GB/T34944-6.2.3.4] SQL注入 🔴 CRITICAL
    public void sqlInjection(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test", "root", "pass");
        String sql = "SELECT * FROM users WHERE id = " + userId;  // SQL拼接
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
    }

    // [GB/T34944-6.2.3.5] 代码注入 🔴 CRITICAL
    public void codeInjection(String script) throws Exception {
        javax.script.ScriptEngine engine = 
            new javax.script.ScriptEngineManager().getEngineByName("javascript");
        engine.eval(script);  // 动态执行用户输入的代码
    }

    // [GB/T34944-6.2.3.6] 进程控制 🟠 HIGH
    public void processControl(String libraryPath) {
        System.load(libraryPath);  // 加载用户指定的动态库
    }

    // [GB/T34944-6.2.3.7] 信息通过错误消息泄露 🟡 MEDIUM
    public void infoLeakViaErrorMsg(String input) throws IOException {
        try {
            int id = Integer.parseInt(input);
        } catch (Exception e) {
            System.out.println("Error: " + e.toString());  // 泄露异常详情
            System.out.println("Stack: " + Arrays.toString(e.getStackTrace()));
        }
    }

    // [GB/T34944-6.2.3.8] 信息通过服务器日志文件泄露 🟡 MEDIUM
    public void infoLeakViaServerLog(String password) {
        System.out.println("User login with password: " + password);  // 密码写入日志
    }

    // [GB/T34944-6.2.3.9] 信息通过调试日志文件泄露 🟡 MEDIUM
    public void infoLeakViaDebugLog(String token) {
        System.out.println("DEBUG: Token value: " + token);  // 调试日志包含敏感信息
    }

    // [GB/T34944-6.2.3.10] 信息通过持久cookie泄露 🟡 MEDIUM
    // 简化示例：模拟Cookie操作
    public void infoLeakViaPersistentCookie(String username) {
        String cookieValue = "username=" + username;  // 敏感信息存入Cookie
        System.out.println("Set-Cookie: " + cookieValue + "; Max-Age=1209600");
    }

    // [GB/T34944-6.2.3.11] 未检查的输入作为循环条件 🟡 MEDIUM
    public void uncheckedLoopCondition(int count) {
        for (int i = 0; i < count; i++) {  // count来自用户输入，无上限检查
            processItem(i);
        }
    }

    // [GB/T34944-6.2.3.12] XPath注入 🟠 HIGH
    public void xpathInjection(String userInput) throws Exception {
        XPathFactory xpathFactory = XPathFactory.newInstance();
        XPath xpath = xpathFactory.newXPath();
        String expression = "/users/user[name='" + userInput + "']";  // XPath拼接
        XPathExpression expr = xpath.compile(expression);
    }

    // ========== 6.2.4 处理程序错误 ==========

    // [GB/T34944-6.2.4.1] 未限制危险类型文件的上传 🟠 HIGH
    public void unrestrictedFileUpload(String filename, byte[] content) throws IOException {
        FileOutputStream fos = new FileOutputStream("/uploads/" + filename);  // 未检查文件类型
        fos.write(content);
    }

    // ========== 6.2.5 不充分的封装 ==========

    // [GB/T34944-6.2.5.1] 可序列化的类包含敏感数据 🟡 MEDIUM
    public class SensitiveClass implements java.io.Serializable {
        private String password;  // 敏感字段未加transient
        private String username;
        
        public SensitiveClass(String username, String password) {
            this.username = username;
            this.password = password;
        }
    }

    // [GB/T34944-6.2.5.2] 违反信任边界 🟠 HIGH
    public void trustBoundaryViolation(String username, Map<String, Object> session) {
        // 不可信数据直接存入session，未验证
        session.put("username", username);
    }

    // ========== 6.2.6 安全功能 ==========

    // [GB/T34944-6.2.6.1] 明文存储口令 🔴 CRITICAL
    public void plaintextPasswordStorage(String password) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test", "root", "pass");
        String sql = "INSERT INTO users (password) VALUES ('" + password + "')";  // 明文存储
        Statement stmt = conn.createStatement();
        stmt.execute(sql);
    }

    // [GB/T34944-6.2.6.2] 存储可恢复的口令 🔴 CRITICAL
    public void recoverablePasswordStorage(String password) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec("fixedKey12345678".getBytes(), "AES"));
        byte[] encrypted = cipher.doFinal(password.getBytes());
        // 存储encrypted到数据库（可逆）
    }

    // [GB/T34944-6.2.6.3] 口令硬编码 🔴 CRITICAL
    private static final String HARDCODED_PASSWORD = "admin123";  // 硬编码口令
    private static final String DB_PASSWORD = "root_pass";  // 硬编码数据库密码
    
    public boolean checkPassword(String input) {
        return HARDCODED_PASSWORD.equals(input);  // 硬编码比对
    }

    // [GB/T34944-6.2.6.4] 依赖referer字段进行身份鉴别 🟠 HIGH
    public boolean refererAuthentication(String referer) {
        return referer != null && referer.contains("trusted-domain.com");  // 依赖referer进行身份鉴别
    }

    // [GB/T34944-6.2.6.5] Cookie中的敏感信息明文存储 🟠 HIGH
    public void sensitiveDataInCookie() {
        String cookieValue = "creditCard=1234-5678-9012-3456";  // 明文敏感信息
        System.out.println("Set-Cookie: " + cookieValue);
    }

    // [GB/T34944-6.2.6.6] 敏感信息明文传输 🔴 CRITICAL
    public void plaintextTransmission(String password) throws Exception {
        // HTTP明文传输敏感信息（未使用HTTPS）
        java.net.URL url = new java.net.URL("http://api.example.com/login?password=" + password);
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
    }

    // [GB/T34944-6.2.6.7] 使用已破解或危险的加密算法 🟠 HIGH
    public void weakEncryptionAlgorithm(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");  // DES已被破解
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec("12345678".getBytes(), "DES"));
        byte[] encrypted = cipher.doFinal(data.getBytes());
    }

    // [GB/T34944-6.2.6.8] 可逆的散列算法 🟠 HIGH
    public String reversibleHashAlgorithm(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");  // SHA-1已被破解
        byte[] hash = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }

    // [GB/T34944-6.2.6.9] 密码分组链接模式未使用随机初始化矢量 🟠 HIGH
    public void cbcWithoutRandomIV(String data) throws Exception {
        byte[] fixedIV = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};  // 固定IV
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, 
            new SecretKeySpec("1234567890abcdef".getBytes(), "AES"),
            new IvParameterSpec(fixedIV));
        byte[] encrypted = cipher.doFinal(data.getBytes());
    }

    // [GB/T34944-6.2.6.10] 不充分的随机数 🟠 HIGH
    public void insufficientRandomness() {
        Random random = new Random();  // 不安全的伪随机数生成器
        byte[] iv = new byte[16];
        random.nextBytes(iv);  // 用于安全场景
    }

    // [GB/T34944-6.2.6.11] 安全关键的行为依赖反向域名解析 🟡 MEDIUM
    public boolean reverseDnsTrust(String ipAddress) throws Exception {
        String hostname = java.net.InetAddress.getByName(ipAddress).getCanonicalHostName();
        return hostname.endsWith("trusted.com");  // 依赖反向DNS解析进行信任判断
    }

    // [GB/T34944-6.2.6.12] 关键参数篡改 🟠 HIGH
    public void criticalParameterTampering(String price, String quantity) {
        // 价格和数量参数来自用户输入，直接使用
        double total = Double.parseDouble(price) * Integer.parseInt(quantity);
    }

    // [GB/T34944-6.2.6.13] 没有要求使用强口令 🟡 MEDIUM
    public void weakPasswordPolicy(String password) {
        // 未检查口令复杂度
        if (password.length() >= 4) {  // 仅检查长度，未检查复杂度
            storePassword(password);
        }
    }

    // [GB/T34944-6.2.6.14] 没有对口令域进行掩饰 🟢 LOW
    public void passwordFieldNotMasked() {
        // GUI中口令输入框未设置掩码（示例）
        // JTextField passwordField = new JTextField();  // 应使用JPasswordField
    }

    // [GB/T34944-6.2.6.15] 依赖未经验证和完整性检查的cookie 🟠 HIGH
    public boolean unverifiedCookieAuth(String cookieValue) {
        return "true".equals(cookieValue);  // Cookie未验证，可伪造
    }

    // [GB/T34944-6.2.6.16] 通过用户控制的SQL关键字绕过授权 🟠 HIGH
    public void sqlKeywordBypass(String orderBy) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test", "root", "pass");
        String sql = "SELECT * FROM products ORDER BY " + orderBy;  // ORDER BY由用户控制
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
    }

    // [GB/T34944-6.2.6.17] HTTPS会话中的敏感cookie没有设置安全性 🟠 HIGH
    public void cookieWithoutSecureAttribute() {
        String sessionCookie = "sessionId=abc123";  // 未设置secure属性
        System.out.println("Set-Cookie: " + sessionCookie);
    }

    // [GB/T34944-6.2.6.18] 未使用盐值计算散列值 🟠 HIGH
    public String hashWithoutSalt(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(password.getBytes());  // 未使用盐值
        return Base64.getEncoder().encodeToString(hash);
    }

    // ========== 6.2.7 时间和状态 ==========

    // [GB/T34944-6.2.7.1] 会话固定 🟠 HIGH
    public void sessionFixation(String username, Map<String, Object> session) {
        // 登录前未创建新session，使用原有session ID
        session.put("user", username);
    }

    // [GB/T34944-6.2.7.2] 会话永不超时 🟡 MEDIUM
    public void sessionNeverTimeout(Map<String, Object> sessionConfig) {
        sessionConfig.put("timeout", -1);  // 设置为永不过期
    }

    // ========== 辅助方法 ==========

    private void processItem(int index) {}
    private void storePassword(String password) {}
}