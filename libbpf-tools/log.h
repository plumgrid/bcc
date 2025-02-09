#ifndef MY_LOG_H
#define MY_LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// 定义日志级别
typedef enum {
    DEBUG,
    INFO,
    WARNING,
    ERROR
} LogLevel;

// 全局变量，用于配置日志输出
static FILE *log_file = NULL;
static LogLevel log_level = INFO;

// 设置日志文件
void set_log_file(const char *filename) {
    if (log_file != NULL) {
        fclose(log_file);
    }
    log_file = fopen(filename, "a+");
    if (log_file == NULL) {
        fprintf(stderr, "log file initializa, Failed to open log file.\n");
        exit(EXIT_FAILURE);
    }
}

// 设置日志级别
void set_log_level(LogLevel level) {
    log_level = level;
}

// 获取当前时间字符串
char* get_current_time() {
    static char time_str[20];
    time_t now = time(NULL);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return time_str;
}

// 日志记录函数
void log_message(LogLevel level, const char *message, int line, const char *func) {
    if (level >= log_level) {
        const char *level_str;
        switch (level) {
            case DEBUG:
                level_str = "DEBUG";
                break;
            case INFO:
                level_str = "INFO";
                break;
            case WARNING:
                level_str = "WARNING";
                break;
            case ERROR:
                level_str = "ERROR";
                break;
            default:
                level_str = "UNKNOWN";
                break;
        }
        fprintf(log_file, "[%s] [%s:%d] [%s] %s\n", get_current_time(), func, line, level_str, message);
        fflush(log_file);
    }
}

#define LOG_DEBUG(msg) log_message(DEBUG, msg, __LINE__, __func__);
#define LOG_INFO(msg) log_message(INFO, msg, __LINE__, __func__);
#define LOG_WARNING(msg) log_message(WARNING, msg, __LINE__, __func__);
#define LOG_ERROR(msg) log_message(ERROR, msg, __LINE__, __func__);

#endif // MY_LOG_H