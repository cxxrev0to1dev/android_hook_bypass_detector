# android_hook_bypass_detector

#include <jni.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <EGL/egl.h>
#include <GLES/gl.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <malloc.h>
#include <string.h>
#include<android/log.h>
#include <dlfcn.h>
#include <hookzz.h>
#include <pthread.h>

#include "hookzz.h"


#define TAG "HuErr"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,TAG ,__VA_ARGS__) // 定义LOGD类型
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG ,__VA_ARGS__) // 定义LOGI类型
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,TAG ,__VA_ARGS__) // 定义LOGW类型
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,TAG ,__VA_ARGS__) // 定义LOGE类型
#define LOGF(...) __android_log_print(ANDROID_LOG_FATAL,TAG ,__VA_ARGS__) // 定义LOGF类型


void dumpreg(RegState *rs)
{
    LOGD("[dumpreg] r0:%x r1:%x r2:%x r3:%x r4:%x r5:%x r6:%x r7:%x r8:%x r9:%x r10:%x r11:%x r12:%x",
         rs->general.regs.r0,rs->general.regs.r1,rs->general.regs.r2,rs->general.regs.r3,rs->general.regs.r4,
         rs->general.regs.r5,rs->general.regs.r6,rs->general.regs.r7,rs->general.regs.r8,rs->general.regs.r9,
         rs->general.regs.r10,rs->general.regs.r11,rs->general.regs.r12);
}



void pre_open_call(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info)
{
    //LOGD("调用之前++++++++++++++++++++++++++++++++\n");
    LOGD("filepath:%s\n",rs->general.regs.r0);
}


void post_open_call(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info)
{
    //LOGD("调用之后++++++++++++++++++++++++++++++++\n");
}

typedef int (*OPENPTR)(const char *pathname, int flags);
int (*orig_open)(const char *pathname, int flags);
OPENPTR openfun = NULL;
char* packages = "package:com.yulong.android.settings\n";
//char* packages = "22222\n";


int fake_open(const char *pathname, int flags) {
    LOGD("call fake_open");

    //匹配打开字符串文件
    if(!strstr(pathname,"/shs_temp.txt"))
    {
        return orig_open(pathname,flags);
    }

    //这里加了权限，不然原来的只读打不开
    int fd = orig_open(pathname,flags|O_RDWR);

    if(fd != -1)
    {
        ftruncate(fd,0);
        lseek(fd,0,SEEK_SET);
        write(fd,packages,strlen(packages));
        
    }

    LOGD("call fake_open end");
    return fd;
}


/*
__attribute__((constructor)) void testhookfw()
{
    LOGD("testhookfw....\n");

    void* libcfp = dlopen("libc.so", 1);
    if(libcfp == NULL)
    {
        LOGD("dlopen libc error\n");
        return;
    }

    OPENPTR openfun = (OPENPTR)dlsym(libcfp,"open");
    if(openfun == NULL)
    {
        LOGD("dlsym openfun error\n");
        return;
    }


    ZzEnableDebugMode();
    //ZzHookPrePost((void *)openfun, pre_open_call,post_open_call);
    ZzHook((void *)openfun, (void *)fake_open, (void **)&orig_open, pre_open_call, post_open_call, false);

    LOGD("testhookfw....end...\n");
    return;
}
//*/

//pm list packages

typedef int (*SYSTEMPTR)(const char *p);
int (*orig_system)(const char *p);
//SYSTEMPTR systemfun = NULL;




void pre_system_call(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info)
{
    //LOGD("调用之前++++++++++++++++++++++++++++++++\n");
    LOGD("pm list:%s\n",rs->general.regs.r0);
}


void post_system_call(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info)
{
    //LOGD("调用之后++++++++++++++++++++++++++++++++\n");
}


int fake_system(const char *pm) {
    LOGD("call fake_open");

    //匹配打开字符串文件
    if(!strstr(pm,"pm list packages"))
    {
        return orig_system(pm);
    }

    //这里加了权限，不然原来的只读打不开
    int ret = orig_system(pm);

    int fd = open("/sdcard/shs_temp.txt",O_RDWR);
    ftruncate(fd,0);
    lseek(fd,0,SEEK_SET);
    write(fd,packages,strlen(packages));

    LOGD("call fake_open end");
    return ret;
}

__attribute__((constructor)) void testhookfw()
{
    LOGD("testhookfw....\n");

    void* libcfp = dlopen("libc.so", 1);
    if(libcfp == NULL)
    {
        LOGD("dlopen libc error\n");
        return;
    }

    OPENPTR systemfun = (OPENPTR)dlsym(libcfp,"system");
    if(systemfun == NULL)
    {
        LOGD("dlsym systemfun error\n");
        return;
    }


    ZzEnableDebugMode();
    //ZzHookPrePost((void *)openfun, pre_open_call,post_open_call);
    ZzHook((void *)systemfun, (void *)fake_system, (void **)&orig_system, pre_system_call, post_system_call, false);

    LOGD("testhookfw....end...\n");
    return;
}
