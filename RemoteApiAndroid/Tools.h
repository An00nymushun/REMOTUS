#pragma once
#include "RemoteApiAndroid.h"

struct Module64
{
	char* BaseName;
	int BaseNameLength;
	void(*CallBack)(LONG, LONG, int);
};

struct Pattern64
{
	BYTE* Bytes;
	char* Mask;
	int Length;
	void(*CallBack)(BYTE*, LONG, int, int);
};


//bool GetModuleByName64(char* moduleName, Module64* module);

bool PatternScan64(LONG startAddress, int scanRange, Pattern64* patternArray, int patternCount);

bool ModuleScan64(Module64* moduleArray, int moduleCount, UINT filterFlags = /*LIST_MODULES_ALL*/3);


inline bool QueryMemoryInfo64(LONG address, MEMORY_BASIC_INFORMATION64** memoryBasicInfoPtr)
{
	return RemoteCalls->VirtualQueryEx(TargetHandle, address, memoryBasicInfoPtr) != 0;
}
inline bool QueryMemoryInfo64(LONG address, MEMORY_BASIC_INFORMATION64* memoryBasicInfo)
{
	return RemoteCalls->VirtualQueryEx(TargetHandle, address, memoryBasicInfo) != 0;
}
inline bool ReadBytes(LONG address, BYTE** readBufferPtr, int size)
{
	return RemoteCalls->ReadProcessMemory(TargetHandle, address, readBufferPtr, size);
}
inline bool ReadBytes(LONG address, BYTE* readBuffer, int size)
{
	return RemoteCalls->ReadProcessMemory(TargetHandle, address, readBuffer, size);
}

template<typename T>
inline T Read(LONG address)
{
	BYTE* readBufferPtr;
	if (!RemoteCalls->ReadProcessMemory(TargetHandle, address, &readBufferPtr, sizeof(T))) return T();
	return *(T*)readBufferPtr;
}

template<typename T>
inline bool Read(LONG address, T* value)
{
	BYTE* readBufferPtr;
	if (!RemoteCalls->ReadProcessMemory(TargetHandle, address, &readBufferPtr, sizeof(T))) return false;
	*value = *(T*)readBufferPtr;
	return true;
}

template<typename T>
inline bool Write(LONG address, T value)
{
	return RemoteCalls->WriteProcessMemory(TargetHandle, address, (POINTER)&value, sizeof(T));
}