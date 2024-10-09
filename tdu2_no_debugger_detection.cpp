#include <windows.h>

// https://github.com/TsudaKageyu/minhook
#include "MinHook.h"

// pthread
#include <pthread.h>

// unix-ish
#include <fcntl.h>

// std
#include <stdio.h>

static pthread_mutex_t log_mutex;
int log_fd = -1;

int init_logging(){
	pthread_mutex_init(&log_mutex, NULL);
	log_fd = open("./tdu2_no_debugger_detection.txt", O_WRONLY | O_CREAT | O_TRUNC | O_BINARY);
	return 0;
}

int write_data_to_fd(int fd, char *buffer, int len){
	int bytes_written = 0;
	while(bytes_written < len){
		int bytes_written_this_cycle = write(fd, &buffer[bytes_written], len - bytes_written);
		if(bytes_written_this_cycle < 0){
			return bytes_written_this_cycle;
		}
		bytes_written += bytes_written_this_cycle;
	}
	return bytes_written;
}

#define LOG(...){ \
	pthread_mutex_lock(&log_mutex); \
	if(log_fd >= 0){ \
		char _log_buffer[1024]; \
		int _log_len = sprintf(_log_buffer, __VA_ARGS__); \
		write_data_to_fd(log_fd, _log_buffer, _log_len); \
	} \
	pthread_mutex_unlock(&log_mutex); \
}

#if 0
#define LOG_VERBOSE(...) LOG(__VA_ARGS__)
#else
#define LOG_VERBOSE(...)
#endif
WINBOOL (WINAPI *IsDebuggerPresentOrig) (VOID);
WINBOOL WINAPI IsDebuggerPresentPatched (VOID){
	static int honest = 4;
	WINBOOL ret = IsDebuggerPresentOrig();
	LOG_VERBOSE("%s: %s, ", __func__, IsDebuggerPresentOrig()? "debugger is present" : "debugger is not present");
	if(ret && honest){
		LOG_VERBOSE("not overriding, honest: %d\n");
		honest--;
		return ret;
	}else{
		LOG_VERBOSE("overriding\n");
		return false;
	}
	return ret;
}

int hook_functions(){
	LOG("hook_functions begin\n");

	int ret = 0;
	/*
	HMODULE handle = LoadLibraryA("Kernel32.dll");
	if(handle == NULL){
		LOG("Failed loading Kernel32.dll\n");
		return -1;
	}
	LOG("Kernel32.dll loaded\n");
	*/

	ret = MH_Initialize();
	if(ret != MH_OK){
		LOG("Failed initializing MinHook, %d\n", ret);
		return -1;
	}

	LPVOID target;
	ret = MH_CreateHookApiEx(L"Kernel32.dll", "IsDebuggerPresent", (LPVOID)&IsDebuggerPresentPatched, (void**)&IsDebuggerPresentOrig, &target);
	if(ret != MH_OK){
		LOG("Failed hooking Kernel32.dll IsDebuggerPresent, %d\n", ret);
		return -1;
	}
	ret = MH_EnableHook(target);
	if(ret != MH_OK){
		LOG("Failed enabling Kernel32.dll IsDebuggerPresent hook");
		return -1;
	}

	return 0;
}

// entrypoint
__attribute__((constructor))
int init(){
	if(init_logging() != 0){
		LOG("pthread mutex init failed for logger, terminating process :(\n");
		exit(1);
	}
	LOG("log initialized\n");
	if(hook_functions() != 0){
		LOG("hooking failed, terminating process :(\n");
		exit(1);
	}
	LOG("done hooking functions\n");
	return 0;
}
