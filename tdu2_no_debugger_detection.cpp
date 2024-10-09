#include <windows.h>
#include <debugapi.h>

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
	log_fd = open("./tdu2_no_debugger_detection_log.txt", O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 00644);
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

#define STR(s) #s

WINBOOL (WINAPI *IsDebuggerPresent_orig) (VOID);
WINBOOL WINAPI IsDebuggerPresent_patched (VOID){
	static int honest = 4;
	WINBOOL ret = IsDebuggerPresent_orig();
	LOG_VERBOSE("%s: %s, ", __func__, ret? "debugger is present" : "debugger is not present");
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

typedef WINBOOL (WINAPI *CHECK_REMOTE_DEBUGGER_PRESENT) (HANDLE, PBOOL);
CHECK_REMOTE_DEBUGGER_PRESENT CheckRemoteDebuggerPresent_orig = NULL;
WINBOOL WINAPI CheckRemoteDebuggerPresent_patched (HANDLE process_handle, PBOOL debugger_present){
	WINBOOL ret = CheckRemoteDebuggerPresent_orig(process_handle, debugger_present);
	LOG_VERBOSE("%s: process handle 0x%08lx, debugger_present 0x%08lx (%s), ret %s\n", __func__, process_handle, debugger_present, *debugger_present? "true":"false", ret? "true":"false");
	*debugger_present = 0;
	return ret;
}

int hook_functions(){
	LOG("hook_functions begin\n");

	int ret = 0;

	ret = MH_Initialize();
	if(ret != MH_OK){
		LOG("Failed initializing MinHook, %d\n", ret);
		return -1;
	}

	#define CREATE_ENABLE_HOOK(target, replacement, trampoline){ \
		int ret = MH_CreateHook((LPVOID)&target, (LPVOID)&replacement, (LPVOID *)&trampoline); \
		if(ret != MH_OK){ \
			LOG("Failed creating hook for %s, %d\n", STR(target), ret); \
			return -1; \
		} \
		ret = MH_EnableHook((LPVOID)&target); \
		if(ret != MH_OK){ \
			LOG("Failed enabling hook for %s, %d\n", STR(target), ret); \
			return -1; \
		} \
	}

	CREATE_ENABLE_HOOK(IsDebuggerPresent, IsDebuggerPresent_patched, IsDebuggerPresent_orig);
	CREATE_ENABLE_HOOK(CheckRemoteDebuggerPresent, CheckRemoteDebuggerPresent_patched, CheckRemoteDebuggerPresent_orig);

	#undef CREATE_ENABLE_HOOK

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
