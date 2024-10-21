#include "windows.h"
#include "stdio.h"

#define EXPORT __declspec(dllexport)
HANDLE hModule;
EXPORT BOOL PIHookEnable();
EXPORT BOOL PIHookDisable();
BOOL PIHook(BOOL enable);
VOID GetSyscallName(FARPROC SyscallRet);
extern void hookedCallback();
extern NTSTATUS NtSetInformationProcess();

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) ((NTSTATUS) (status) >= 0)
#endif
#define ProcessInstrumentationCallback 0x28
typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, *PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

EXPORT BOOL PIHookEnable() {
    return PIHook(TRUE);
}
EXPORT BOOL PIHookDisable() {
    return PIHook(FALSE);
}

BOOL PIHook(BOOL enable) {
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION InstrumentationCallbackInfo;
    InstrumentationCallbackInfo.Version  = 0;
    InstrumentationCallbackInfo.Reserved = 0;
    InstrumentationCallbackInfo.Callback = NULL;
    if (enable) {
        InstrumentationCallbackInfo.Callback = hookedCallback;
    }
    if (NT_SUCCESS(NtSetInformationProcess((HANDLE)-1, ProcessInstrumentationCallback, &InstrumentationCallbackInfo, sizeof(InstrumentationCallbackInfo)))) {
        return TRUE;
    }
    return FALSE;
}

VOID GetSyscallName(FARPROC SyscallRet) {
    PIHook(FALSE);
    FARPROC funcPtr = SyscallRet - 0x14;
    BYTE* baseAddress = (BYTE*)hModule;
    char* functionName = NULL;
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddress;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        goto cleanUp;
    }
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddress + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        goto cleanUp;
    }
    IMAGE_OPTIONAL_HEADER* optionalHeader = &ntHeaders->OptionalHeader;
    IMAGE_DATA_DIRECTORY* exportDataDir = &optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDataDir->VirtualAddress == 0) {
        goto cleanUp;
    }
    IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)(baseAddress + exportDataDir->VirtualAddress);
    DWORD* funcAddressArray = (DWORD*)(baseAddress + exportDirectory->AddressOfFunctions);
    DWORD* nameArray = (DWORD*)(baseAddress + exportDirectory->AddressOfNames);
    WORD* ordinalArray = (WORD*)(baseAddress + exportDirectory->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exportDirectory->NumberOfFunctions; i++) {
        FARPROC currentFunction = (FARPROC)(baseAddress + funcAddressArray[i]);
        if (currentFunction == funcPtr) {
            for (DWORD j = 0; j < exportDirectory->NumberOfNames; j++) {
                if (ordinalArray[j] == i) {
                    functionName = (char*)(baseAddress + nameArray[j]);
                    goto cleanUp;
                }
            }
        }
    }
cleanUp:
    if (functionName) {
        printf("[PI-TRACKER] %s (%p)\n", functionName, funcPtr);
    }
    PIHook(TRUE);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason){
	case DLL_PROCESS_ATTACH: {
        hModule = GetModuleHandleA("ntdll");
        PIHookEnable();
		break;
	}
	case DLL_PROCESS_DETACH:
        PIHookDisable();
        break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}