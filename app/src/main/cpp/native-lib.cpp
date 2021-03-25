#include <jni.h>
#include <string>

extern "C" JNIEXPORT jstring JNICALL
Java_ru_iu3_lr1_1lebedev_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}