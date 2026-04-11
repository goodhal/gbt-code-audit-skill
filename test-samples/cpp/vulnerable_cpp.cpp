#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

/**
 * C/C++代码安全测试样例
 * 覆盖 GB/T 34943-2017 所有章节
 */

// ========== 第10章 错误处理 ==========

// [10.1] 错误未检查
int uncheckedError() {
    FILE* fp = fopen("config.txt", "r");
    // 没有检查fp是否为NULL
    char buffer[256];
    fgets(buffer, sizeof(buffer), fp);  // 如果打开失败，fp为NULL
    fclose(fp);
    return 0;
}

// [10.2] 缓冲区溢出
void bufferOverflow() {
    char buf[64];
    strcpy(buf, "This string is much longer than 64 bytes and will overflow the buffer");
    printf("%s\n", buf);
}

// [10.3] 格式化字符串
void formatString() {
    char input[256];
    scanf("%s", input);
    printf(input);  // 格式化字符串漏洞
}

// ========== 第11章 代码质量 ==========

// [11.1] 空指针解引用
char* nullPointer() {
    char* ptr = NULL;
    return ptr;  // 返回NULL
}

// [11.2] 使用未初始化内存
void uninitializedMemory() {
    int x;
    printf("%d\n", x);  // 使用未初始化变量
}

// ========== 第12章 内存管理 ==========

// [12.1] 内存泄漏
void memoryLeak() {
    char* buffer = malloc(1024);
    // 没有free(buffer)
}

// [12.2] 双重释放
void doubleFree() {
    char* ptr = malloc(100);
    free(ptr);
    free(ptr);  // 双重释放
}

// [12.3] 释放后使用
void useAfterFree() {
    char* ptr = malloc(100);
    strcpy(ptr, "test");
    free(ptr);
    printf("%s\n", ptr);  // 释放后使用
}

// ========== 第13章 整数安全 ==========

// [13.1] 整数溢出
int integerOverflow() {
    int x = 2147483647;
    return x + 1;  // 整数溢出
}

// [13.2] 整数符号问题
int signError(unsigned int size) {
    if (size < 0) {  // 无符号永远不为负
        return -1;
    }
    return 0;
}

// ========== 第14章 SQL注入 ==========

// [14.1] SQL注入
int sqlInjection(sqlite3* db, const char* userId) {
    char sql[512];
    sprintf(sql, "SELECT * FROM users WHERE id = %s", userId);  // SQL注入
    return 0;
}

// ========== 第15章 命令注入 ==========

// [15.1] 命令注入
void commandInjection(const char* filename) {
    char cmd[512];
    sprintf(cmd, "cat %s", filename);
    system(cmd);  // 命令注入
}

// ========== 第16章 路径遍历 ==========

// [16.1] 路径遍历
void pathTraversal(const char* filename) {
    char path[512];
    sprintf(path, "/var/www/uploads/%s", filename);
    FILE* fp = fopen(path, "r");  // 路径遍历
}

// ========== 第17章 数据保护 ==========

// [17.1] 硬编码密钥
const char* HARDCODED_KEY = "MySecretAESKey123";  // 硬编码密钥

// [17.2] 敏感数据日志
void logSensitive(const char* password) {
    printf("User login with password: %s\n", password);  // 密码日志
}

// ========== 第18章 线程安全 ==========

// [18.1] 竞态条件
int counter = 0;

void* raceCondition(void* arg) {
    int temp = counter;  // 读取
    // 其他线程可能修改counter
    counter = temp + 1;  // 写入
    return NULL;
}

// [18.2] 共享资源未加锁
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void unsafeSharedResource() {
    // 没有lock mutex
    counter++;
    // 没有unlock mutex
}

// ========== 辅助函数 ==========

int main() {
    return 0;
}
