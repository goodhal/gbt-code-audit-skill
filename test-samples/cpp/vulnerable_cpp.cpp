/**
 * C/C++代码安全测试样例
 * 覆盖 GB/T 34943-2017 所有规则
 * 规则编号对应标准章节
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <pthread.h>
#include <windows.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/evp.h>

// ========== 6.2.1 行为问题 ==========

// [GB/T34943-6.2.1.1] 不可控的内存分配 🟠 HIGH
void uncontrolledMemoryAllocation(int size) {
    char* buffer = malloc(size * sizeof(char));  // size来自用户输入，无上限检查
    if (buffer != NULL) {
        free(buffer);
    }
}

// ========== 6.2.2 路径错误 ==========

// [GB/T34943-6.2.2.1] 不可信的搜索路径 🟡 MEDIUM
void untrustedSearchPath(const char* command) {
    system(command);  // PATH可能被依赖，DLL/SO劫持风险
}

// ========== 6.2.3 数据处理 ==========

// [GB/T34943-6.2.3.1] 相对路径遍历 🟠 HIGH
void relativePathTraversal(const char* filename) {
    char path[512];
    sprintf(path, "/var/www/uploads/%s", filename);  // filename可能包含../
    FILE* fp = fopen(path, "r");
    if (fp != NULL) fclose(fp);
}

// [GB/T34943-6.2.3.2] 绝对路径遍历 🟠 HIGH
void absolutePathTraversal(const char* path) {
    FILE* fp = fopen(path, "r");  // 直接使用用户输入作为绝对路径
    if (fp != NULL) fclose(fp);
}

// [GB/T34943-6.2.3.3] 命令注入 🔴 CRITICAL
void commandInjection(const char* filename) {
    char cmd[512];
    sprintf(cmd, "cat %s", filename);  // 命令拼接
    system(cmd);
    
    sprintf(cmd, "ls -la %s", filename);
    popen(cmd, "r");  // popen同样危险
}

// [GB/T34943-6.2.3.4] SQL注入 🔴 CRITICAL
int sqlInjection(sqlite3* db, const char* userId) {
    char sql[512];
    sprintf(sql, "SELECT * FROM users WHERE id = %s", userId);  // SQL拼接
    sqlite3_stmt* stmt;
    return sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
}

// [GB/T34943-6.2.3.5] 进程控制 🟠 HIGH
void processControl(const char* libraryPath) {
    HMODULE hLib = LoadLibrary(libraryPath);  // 加载用户指定的DLL
    if (hLib != NULL) FreeLibrary(hLib);
    
    void* handle = dlopen(libraryPath, RTLD_NOW);  // Linux下加载用户指定的SO
    if (handle != NULL) dlclose(handle);
}

// [GB/T34943-6.2.3.6] 缓冲区溢出 - 栈溢出 🔴 CRITICAL
void bufferOverflowStack() {
    char buf[64];
    char input[256];
    scanf("%s", input);  // 未限制长度
    strcpy(buf, input);  // 无边界检查，栈溢出
    
    gets(buf);  // gets函数已被废弃，极度危险
}

// [GB/T34943-6.2.3.7] 格式化字符串漏洞 🟠 HIGH
void formatStringVulnerability(const char* userInput) {
    printf(userInput);  // userInput可能包含%n等格式控制字符
    
    char buf[256];
    sprintf(buf, userInput);  // 同样危险
}

// [GB/T34943-6.2.3.8] 整数溢出 🟠 HIGH
void integerOverflow(unsigned int count) {
    unsigned int size = count * 4;  // count来自用户输入，可能溢出
    char* buffer = malloc(size);  // 溢出后分配空间不够
    if (buffer != NULL) free(buffer);
}

// [GB/T34943-6.2.3.9] 信息通过错误消息泄露 🟡 MEDIUM
void infoLeakViaErrorMsg(const char* path) {
    char msg[512];
    sprintf(msg, "File %s does not exist!", path);  // 泄露完整路径
    printf("%s\n", msg);
}

// [GB/T34943-6.2.3.10] 信息通过服务器日志文件泄露 🟡 MEDIUM
void infoLeakViaServerLog(const char* username, const char* password) {
    char log[512];
    sprintf(log, "User %s login with password %s", username, password);  // 密码写入日志
    write_log(log);
}

// [GB/T34943-6.2.3.11] 信息通过调试日志文件泄露 🟡 MEDIUM
void infoLeakViaDebugLog(const char* sensitiveData) {
    CCLOG("Debug: %s", sensitiveData);  // 调试日志包含敏感信息
}

// [GB/T34943-6.2.3.12] 未检查的输入作为循环条件 🟡 MEDIUM
void uncheckedLoopCondition(int count) {
    if (count > 0) {
        for (int i = 0; i < count; i++) {  // count来自用户输入，无上限检查
            processItem(i);
        }
    }
}

// [GB/T34943-6.2.3.13] 通过用户控制的SQL关键字绕过授权 🟠 HIGH
void sqlKeywordBypass(sqlite3* db, const char* orderBy) {
    char sql[512];
    sprintf(sql, "SELECT * FROM products ORDER BY %s", orderBy);  // ORDER BY由用户控制
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
}

// [GB/T34943-6.2.3.14] 未使用盐值计算散列值 🟠 HIGH
void hashWithoutSalt(const char* password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password, strlen(password), hash);  // 未使用盐值
    // 存储hash到数据库
}

// ========== 6.2.4 错误的API协议实现 ==========

// [GB/T34943-6.2.4.1] 堆检查 🟠 HIGH
void heapInspection(char* sensitiveBuffer, size_t newSize) {
    // realloc调整含敏感数据的内存前未清空
    char* newBuffer = realloc(sensitiveBuffer, newSize);  // 原数据可能残留在堆中
}

// [GB/T34943-6.2.4.2] 敏感信息存储于上锁不正确的内存空间 🟡 MEDIUM
void sensitiveDataInUnlockedMemory(const char* password) {
    char* buffer = malloc(50 * sizeof(char));
    strcpy(buffer, password);  // 密码指向的内存未被锁定
    // 未使用VirtualLock锁定内存
    free(buffer);
}

// ========== 6.2.5 不充分的封装 ==========

// [GB/T34943-6.2.5.1] 公有函数返回私有数组 🟢 LOW
char* publicFunctionReturnsPrivateArray() {
    static char secret[64] = "sensitive_data";
    return secret;  // 直接返回私有数组的指针引用
}

// ========== 6.2.7 安全功能 ==========

// [GB/T34943-6.2.7.1] 明文存储口令 🔴 CRITICAL
void plaintextPasswordStorage(const char* password) {
    // 口令以明文存入数据库
    store_password(password);
}

// [GB/T34943-6.2.7.2] 存储可恢复的口令 🔴 CRITICAL
void recoverablePasswordStorage(const char* password) {
    // AES对称加密存储口令（可逆）
    AES_KEY aesKey;
    AES_set_encrypt_key((unsigned char*)"fixedKey1234567", 128, &aesKey);
    unsigned char encrypted[16];
    AES_encrypt((unsigned char*)password, encrypted, &aesKey);
    store_password((char*)encrypted);  // 可逆加密存储
}

// [GB/T34943-6.2.7.3] 口令硬编码 🔴 CRITICAL
const char* HARDCODED_PASSWORD = "jfk64k3h6g65w63";  // 硬编码口令

int checkHardcodedPassword(const char* input) {
    return strcmp(input, HARDCODED_PASSWORD) == 0;  // 硬编码比对
}

// [GB/T34943-6.2.7.4] 敏感信息明文传输 🔴 CRITICAL
void plaintextTransmission(const char* address) {
    send_message(address);  // 传输address未进行加密
}

// [GB/T34943-6.2.7.5] 使用已破解或危险的加密算法 🟠 HIGH
void weakEncryptionAlgorithm(const char* data) {
    DES_cblock key;
    DES_key_schedule schedule;
    DES_set_key_unchecked(&key, &schedule);  // DES已被破解
    
    unsigned char encrypted[8];
    DES_ecb_encrypt((DES_cblock*)data, &encrypted, &schedule, DES_ENCRYPT);
}

// [GB/T34943-6.2.7.6] 可逆的散列算法 🟠 HIGH
void reversibleHashAlgorithm(const char* input) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)input, strlen(input), hash);  // SHA-1已被破解
}

// [GB/T34943-6.2.7.7] 密码分组链接模式未使用随机初始化矢量 🟠 HIGH
void cbcWithoutRandomIV(const char* data) {
    unsigned char fixedIV[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};  // 固定IV
    AES_KEY aesKey;
    AES_set_encrypt_key((unsigned char*)"1234567890abcdef", 128, &aesKey);
    unsigned char encrypted[64];
    AES_cbc_encrypt((unsigned char*)data, encrypted, strlen(data), &aesKey, fixedIV, AES_ENCRYPT);
}

// [GB/T34943-6.2.7.8] 不充分的随机数 🟠 HIGH
void insufficientRandomness() {
    unsigned char iv[8];
    for (int i = 0; i < 8; i++) {
        iv[i] = rand() % 256;  // 使用不充分的伪随机数生成器
    }
}

// [GB/T34943-6.2.7.9] 安全关键的行为依赖反向域名解析 🟡 MEDIUM
int reverseDnsTrust(const char* ipAddress) {
    struct hostent* host = gethostbyaddr(ipAddress, strlen(ipAddress), AF_INET);
    if (host != NULL && strstr(host->h_name, "trusted.com") != NULL) {
        return 1;  // 依赖反向DNS解析进行信任判断
    }
    return 0;
}

// [GB/T34943-6.2.7.10] 没有要求使用强口令 🟡 MEDIUM
int weakPasswordPolicy(const char* password) {
    // 仅检查长度，未检查复杂度
    return strlen(password) >= 4;
}

// [GB/T34943-6.2.7.11] 没有对口令域进行掩饰 🟢 LOW
void passwordFieldNotMasked() {
    char password[64];
    printf("Please enter the password:\n");
    scanf("%s", password);  // 未使用掩码显示
}

// [GB/T34943-6.2.7.12] 通过用户控制的SQL关键字绕过授权 🟠 HIGH
// 同6.2.3.13，此处为重复条目

// [GB/T34943-6.2.7.13] 未使用盐值计算散列值 🟠 HIGH
// 同6.2.3.14，此处为重复条目

// [GB/T34943-6.2.7.14] RSA算法未使用最优非对称加密填充 🟠 HIGH
void rsaWithoutOAEP() {
    RSA* rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    unsigned char encrypted[256];
    int len = RSA_public_encrypt(32, (unsigned char*)"test", encrypted, rsa, RSA_PKCS1_PADDING);  // 使用PKCS1填充
    RSA_free(rsa);
}

// ========== 6.2.8 Web问题 ==========

// [GB/T34943-6.2.8.1] 跨站脚本 🟠 HIGH
void crossSiteScripting(const char* name) {
    char html[512];
    sprintf(html, "<html><body>Hello %s</body></html>", name);  // 输入未验证直接写入HTML
    write_html(html, "index.html");
}

// ========== 辅助函数 ==========

void write_log(const char* msg) { printf("[LOG] %s\n", msg); }
void CCLOG(const char* fmt, const char* data) { printf("[DEBUG] %s: %s\n", fmt, data); }
void processItem(int index) { printf("Processing item %d\n", index); }
void store_password(const char* password) { printf("Storing password: %s\n", password); }
void send_message(const char* msg) { printf("Sending: %s\n", msg); }
void write_html(const char* html, const char* filename) { printf("Writing HTML to %s\n", filename); }

int main() {
    printf("GB/T 34943-2017 C/C++ Vulnerability Test Samples\n");
    return 0;
}