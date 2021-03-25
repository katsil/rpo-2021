#include <jni.h>
#include <string>
#include <android/log.h>

#define LOG_INFO(...) __android_log_print(ANDROID_LOG_INFO, "lr1lebedev_ndk", __VA_ARGS__)

#include <spdlog/spdlog.h>
#include "spdlog/sinks/android_sink.h"

#define SLOG_INFO(...) android_logger->info( __VA_ARGS__ )
auto android_logger = spdlog::android_logger_mt( "android", "lr1lebedev_ndk");

extern "C" JNIEXPORT jstring  /*extern "C" jstring*/
Java_ru_iu3_lr1_1lebedev_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    LOG_INFO("Hello from system log %d", 2021);
    SLOG_INFO("Hello from spdlog {}", 2021);
    return env->NewStringUTF(hello.c_str());
}