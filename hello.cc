#include <nan.h>

using v8::FunctionTemplate;
using v8::Object;
using v8::String;
using Nan::GetFunction;
using Nan::New;
using Nan::Set;


#include "windows.h"
#include "winternl.h"
#include "string"

typedef NTSTATUS(WINAPI* NtQueryInformationProcessFake)(HANDLE, DWORD, PVOID, ULONG, PULONG);
NtQueryInformationProcessFake ntQ = NULL;

std::string TCharToChar(const wchar_t* tchar)
{

	int iLength;
	iLength = WideCharToMultiByte(CP_ACP, 0, tchar, -1, NULL, 0, NULL, NULL);
	auto buffer = std::string();
	buffer.resize(iLength * 2 + 1);
	WideCharToMultiByte(CP_ACP, 0, tchar, -1, (char*)buffer.data(), iLength, NULL, NULL);
	return buffer;
}

std::string get_process_cmd(int pid)
{
	std::string result = "";
	HANDLE hproc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (INVALID_HANDLE_VALUE != hproc) {
		HANDLE hnewdup = NULL;
		PEB peb;
		RTL_USER_PROCESS_PARAMETERS upps;
		HMODULE hm = LoadLibraryA("Ntdll.dll");

		ntQ = (NtQueryInformationProcessFake)GetProcAddress(hm, "NtQueryInformationProcess");
		if (DuplicateHandle(GetCurrentProcess(), hproc, GetCurrentProcess(), &hnewdup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
			PROCESS_BASIC_INFORMATION pbi;
			NTSTATUS isok = ntQ(hnewdup, 0/*ProcessBasicInformation*/, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), 0);
			if (NT_SUCCESS(isok)) {
				std::wstring temp;
				if (ReadProcessMemory(hnewdup, pbi.PebBaseAddress, &peb, sizeof(PEB), 0))
					if (ReadProcessMemory(hnewdup, peb.ProcessParameters, &upps, sizeof(RTL_USER_PROCESS_PARAMETERS), 0)) {
						temp.resize(upps.CommandLine.Length + 1);
						ReadProcessMemory(hnewdup, upps.CommandLine.Buffer, (LPVOID)temp.data(), upps.CommandLine.Length, 0);
						result = TCharToChar(temp.data());
					}
			}
			CloseHandle(hnewdup);
		}
		CloseHandle(hproc);
	}
	return result;
}

// Simple synchronous access to the `Estimate()` function
NAN_METHOD(CalculateSync) {
	// expect a number as the first argument
	unsigned long pid;
	auto hwnd = FindWindowA("RCLIENT", "League of Legends");
	GetWindowThreadProcessId(hwnd, &pid);
	info.GetReturnValue().Set(Nan::New(get_process_cmd(pid).data()).ToLocalChecked());
}



NAN_MODULE_INIT(InitAll) {
	Set(target, New<String>("get_cmd").ToLocalChecked(),
		GetFunction(New<FunctionTemplate>(CalculateSync)).ToLocalChecked());
}

NODE_MODULE(module, InitAll)
