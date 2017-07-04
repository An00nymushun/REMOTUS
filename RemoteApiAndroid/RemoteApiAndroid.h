#pragma once
#include "Shellcode.h"

#define DEBUG_TAG "NDK_RemoteApiAndroid"
#define PORT 0xD1CC
#define TIMEOUT 10
#define BUFSIZE 4096
#define TARGETPROCESSNAME "csgo.exe"
#define SMALLMSGSIZE 512
#define BIGMSGSIZE 4096
#define DEFAULTMSGSIZE SMALLMSGSIZE


enum ERRORCODE
{
	SUCCESS = 0,
	SOCKET_FAIL = 1,
	REUSEADDR_FAIL = 2,
	SNDTIMEO_FAIL = 3,
	BIND_FAIL = 4,

	RECV_FAIL = 5,
	RCVTIMEO_FAIL = 6,
	LOGIN_FAIL = 7,
	PROTOCOL_FAIL = 8,
	PROCESSORTYPE_FAIL = 9,
	SHELLCODE_FAIL = 10,
	SEND_FAIL = 11,
	CALL_FAIL = 12,
	HANDLE_FAIL = 13,
	ACCESS_FAIL = 14,
	MODULE_FAIL = 15,
	PATTERN_FAIL = 16,
	RESULT_FAIL = 17,
	SHELLCODERECV_FAIL = 18,
	PROCESS_FAIL = 19,
	TESTFAIL = 20
};



#define MAX_MODULE_NAME32 255
#define MAX_PATH 260


#define PAGE_EXECUTE_READ		0x20
#define PAGE_EXECUTE_READWRITE	0x40
#define PAGE_EXECUTE_WRITECOPY	0x80

#define TH32CS_SNAPMODULE 0x00000008

#define INVALID_HANDLE_VALUE (-1)



#pragma pack(push, 1) //manual alignment
#define PAD4(i) BYTE _pad##i[4];

struct MEMORY_BASIC_INFORMATION64 {
	LONG BaseAddress;
	LONG AllocationBase;
	UINT AllocationProtect;
	PAD4(1);
	LONG RegionSize;
	UINT State;
	UINT Protect;
	UINT Type;
	PAD4(2);
};

struct MODULEINFO64 {
	LONG lpBaseOfDll;
	UINT SizeOfImage;
	PAD4();
	LONG EntryPoint;
};

struct MODULEENTRY3264 {
	UINT dwSize;
	UINT th32ModuleID;
	UINT th32ProcessID;
	UINT GlblcntUsage;
	UINT ProccntUsage;
	PAD4(1);
	LONG modBaseAddr;
	UINT modBaseSize;
	PAD4(2);
	LONG hModule;
	char szModule[MAX_MODULE_NAME32 + 1];
	char szExePath[MAX_PATH];
	PAD4(3);
};

#undef PAD4
#pragma pack(pop)





enum ShellcodeType
{
	Win32 = 0,
	Win64 = 1
};


#define CSTRWITHSIZE(s) s,sizeof(s)
#define STRWITHSIZE(s) s,STRSIZE(s)
#define ARRAYWITHCOUNT(a) a,ARRAYCOUNT(a)


#define EV0REMOTE_PROTOCOLVERSION 1
#pragma pack(push, 1)
struct EV0REMOTE_LOGIN
{
public:
	USHORT Ev0remoteProtocol;
	//USHORT ProtocolVersion : 12;
	//BYTE ProcessorType : 4;
	LONG Address;
	LONG Kernel32;
	LONG GetProcAddr;

	inline ShellcodeType GetProcessorType()
	{
		return (ShellcodeType)(Ev0remoteProtocol >> 12);
	}
	inline USHORT GetProtocolVersion()
	{
		return (Ev0remoteProtocol & (unsigned short)0x0fff);
	}
};
#pragma pack(pop)

class ShellcodeMacro64
{
	LONG kernel32;
	LONG getProcAddress;
	LONG send;
	LONG recv;
	LONG socket;

public:
	int MsgSize;

	ShellcodeMacro64() { }
	ShellcodeMacro64(LONG kernel32, LONG getProcAddress, LONG send, LONG recv, LONG socket, int msgSize = DEFAULTMSGSIZE)
	{
		this->kernel32 = kernel32;
		this->getProcAddress = getProcAddress;
		this->send = send;
		this->recv = recv;
		this->socket = socket;

		this->MsgSize = msgSize;
	}

	void Send(Shellcode64* shellcodeBuilder, FakeObject* fakeObject, int size)
	{
		shellcodeBuilder
			//->MovInt64Register9(0)
			->ZeroRegister9()
			->MovInt32Register8(size)
			->MovFakePointerRegisterD(fakeObject)
			->MovInt64RegisterC(socket)
			->FakePushBytes(32)
			->CallFar(send)
			->FakePopBytes(32);
	}
	void Send(Shellcode64* shellcodeBuilder, LateValue<LONG>* bufferAddress, int size)
	{
		shellcodeBuilder
			//->MovInt64Register9(0)
			->ZeroRegister9()
			->MovInt32Register8(size)
			->MovLateInt64RegisterD(bufferAddress)
			->MovInt64RegisterC(socket)
			->FakePushBytes(32)
			->CallFar(send)
			->FakePopBytes(32);
	}
	void Send(Shellcode64* shellcodeBuilder, LateValue<LONG>* bufferAddress, LateValue<int>* size)
	{
		shellcodeBuilder
			//->MovInt64Register9(0)
			->ZeroRegister9()
			->MovLateInt32Register8(size)
			->MovLateInt64RegisterD(bufferAddress)
			->MovInt64RegisterC(socket)
			->FakePushBytes(32)
			->CallFar(send)
			->FakePopBytes(32);
	}
	void Recv(Shellcode64* shellcodeBuilder)
	{
		LONG memoryAddress = shellcodeBuilder->RemoteAddress;
		//int bufferlen = shellcodeBuilder->MaxSize;

		shellcodeBuilder
			//->MovInt64Register9(0)
			//->ZeroRegister9()
			->MovInt32Register9(/*MSG_WAITALL*/8)
			->MovInt32Register8(/*bufferlen*/MsgSize)
			->MovInt64RegisterD(memoryAddress)
			->MovInt64RegisterC(socket)
			//->FakePushBytes(32)

			->PushInt64(memoryAddress)
			->JmpFar(recv);
	}
	void Recv(Shellcode64* shellcodeBuilder, LateValue<int>* msgSize)
	{
		LONG memoryAddress = shellcodeBuilder->RemoteAddress;

		shellcodeBuilder
			->MovInt32Register9(/*MSG_WAITALL*/8)
			->MovLateInt32Register8(msgSize)
			->MovInt64RegisterD(memoryAddress)
			->MovInt64RegisterC(socket)
			//->FakePushBytes(32)

			->PushInt64(memoryAddress)
			->JmpFar(recv);
	}
	Shellcode Complete(Shellcode64* shellcodeBuilder, FakeObject* fakeObjectToSend, int sizeToSend)
	{
		Send(shellcodeBuilder, fakeObjectToSend, sizeToSend);
		Recv(shellcodeBuilder);
		return shellcodeBuilder->Complete();
	}
	Shellcode Complete(Shellcode64* shellcodeBuilder, LateValue<LONG>* bufferToSend, int sizeToSend)
	{
		Send(shellcodeBuilder, bufferToSend, sizeToSend);
		Recv(shellcodeBuilder);
		return shellcodeBuilder->Complete();
	}
	Shellcode Complete(Shellcode64* shellcodeBuilder, LateValue<LONG>* bufferToSend, LateValue<int>* sizeToSend)
	{
		Send(shellcodeBuilder, bufferToSend, sizeToSend);
		Recv(shellcodeBuilder);
		return shellcodeBuilder->Complete();
	}
	Shellcode Complete(Shellcode64* shellcodeBuilder, LateValue<LONG>* bufferToSend, LateValue<int>* sizeToSend, LateValue<int>* sizeToRecv)
	{
		Send(shellcodeBuilder, bufferToSend, sizeToSend);
		Recv(shellcodeBuilder, sizeToRecv);
		return shellcodeBuilder->Complete();
	}
	Shellcode SafeComplete(Shellcode64* shellcodeBuilder, LONG rtlFillMemory, FakeObject* fakeObjectToSend, int sizeToSend)
	{
		Send(shellcodeBuilder, fakeObjectToSend, sizeToSend);
		Call<false, LONG, int, BYTE>(shellcodeBuilder, rtlFillMemory, shellcodeBuilder->RemoteAddress, shellcodeBuilder->GetCurrentCodeSize(), (BYTE)0xCC);
		Recv(shellcodeBuilder);
		return shellcodeBuilder->Complete();
	}
	Shellcode SafeComplete(Shellcode64* shellcodeBuilder, LONG rtlFillMemory, LateValue<LONG>* bufferToSend, int sizeToSend)
	{
		Send(shellcodeBuilder, bufferToSend, sizeToSend);
		Call<false, LONG, int, BYTE>(shellcodeBuilder, rtlFillMemory, shellcodeBuilder->RemoteAddress, shellcodeBuilder->GetCurrentCodeSize(), (BYTE)0xCC);
		Recv(shellcodeBuilder);
		return shellcodeBuilder->Complete();
	}
	Shellcode SafeComplete(Shellcode64* shellcodeBuilder, LONG rtlFillMemory, LateValue<LONG>* bufferToSend, int sizeToSend, LateValue<int>* sizeToRecv)
	{
		Send(shellcodeBuilder, bufferToSend, sizeToSend);
		Call<false, LONG, int, BYTE>(shellcodeBuilder, rtlFillMemory, shellcodeBuilder->RemoteAddress, shellcodeBuilder->GetCurrentCodeSize(), (BYTE)0xCC);
		Recv(shellcodeBuilder, sizeToRecv);
		return shellcodeBuilder->Complete();
	}
	Shellcode SafeComplete(Shellcode64* shellcodeBuilder, LONG rtlFillMemory, LateValue<LONG>* bufferToSend, LateValue<int>* sizeToSend)
	{
		Send(shellcodeBuilder, bufferToSend, sizeToSend);
		Call<false, LONG, int, BYTE>(shellcodeBuilder, rtlFillMemory, shellcodeBuilder->RemoteAddress, shellcodeBuilder->GetCurrentCodeSize(), (BYTE)0xCC);
		Recv(shellcodeBuilder);
		return shellcodeBuilder->Complete();
	}
	Shellcode SafeComplete(Shellcode64* shellcodeBuilder, LONG rtlFillMemory, LateValue<LONG>* bufferToSend, LateValue<int>* sizeToSend, LateValue<int>* sizeToRecv)
	{
		Send(shellcodeBuilder, bufferToSend, sizeToSend);
		Call<false, LONG, int, BYTE>(shellcodeBuilder, rtlFillMemory, shellcodeBuilder->RemoteAddress, shellcodeBuilder->GetCurrentCodeSize(), (BYTE)0xCC);
		Recv(shellcodeBuilder, sizeToRecv);
		return shellcodeBuilder->Complete();
	}

	template<bool STACKSAFE>
	inline void Call(Shellcode64* shellcodeBuilder, LONG funcAddress)
	{
		if (STACKSAFE)
		{
			shellcodeBuilder
				->FakePushBytes(32)
				->CallFar(funcAddress)
				->FakePopBytes(32);
		}
		else
		{
			shellcodeBuilder->CallFar(funcAddress);
		}
	}

	template<bool STACKSAFE, typename T1>
	inline void Call(Shellcode64* shellcodeBuilder, LONG funcAddress, T1 p1, int s1 = 0)
	{
		if (p1 == NULL)
			shellcodeBuilder->ZeroRegisterC();
		else if (is_pointer<T1>::value)
			shellcodeBuilder->MovFakePointerRegisterC(shellcodeBuilder->NewFakeObject((POINTER)p1, s1));
		else if(sizeof(T1) <= 4)
			shellcodeBuilder->MovInt32RegisterC(reinterpret_cast<int&>(p1));
		else
			shellcodeBuilder->MovInt64RegisterC((LONG)p1);

		Call<STACKSAFE>(shellcodeBuilder, funcAddress);
	}

	template<bool STACKSAFE, typename T1, typename T2>
	inline void Call(Shellcode64* shellcodeBuilder, LONG funcAddress, T1 p1, T2 p2, int s1 = 0, int s2 = 0)
	{
		if (p2 == NULL)
			shellcodeBuilder->ZeroRegisterD();
		else if (is_pointer<T2>::value)
			shellcodeBuilder->MovFakePointerRegisterD(shellcodeBuilder->NewFakeObject((POINTER)p2, s2));
		else if (sizeof(T2) <= 4)
			shellcodeBuilder->MovInt32RegisterD(reinterpret_cast<int&>(p2));
		else
			shellcodeBuilder->MovInt64RegisterD((LONG)p2);

		Call<STACKSAFE, T1>(shellcodeBuilder, funcAddress, p1, s1);
	}

	template<bool STACKSAFE, typename T1, typename T2, typename T3>
	inline void Call(Shellcode64* shellcodeBuilder, LONG funcAddress, T1 p1, T2 p2, T3 p3, int s1 = 0, int s2 = 0, int s3 = 0)
	{
		if (p3 == NULL)
			shellcodeBuilder->ZeroRegister8();
		else if (is_pointer<T3>::value)
			shellcodeBuilder->MovFakePointerRegister8(shellcodeBuilder->NewFakeObject((POINTER)p3, s3));
		else if (sizeof(T3) <= 4)
			shellcodeBuilder->MovInt32Register8(reinterpret_cast<int&>(p3));
		else
			shellcodeBuilder->MovInt64Register8((LONG)p3);

		Call<STACKSAFE, T1, T2>(shellcodeBuilder, funcAddress, p1, p2, s1, s2);
	}

	template<bool STACKSAFE, typename T1, typename T2, typename T3, typename T4>
	inline void Call(Shellcode64* shellcodeBuilder, LONG funcAddress, T1 p1, T2 p2, T3 p3, T4 p4, int s1 = 0, int s2 = 0, int s3 = 0, int s4 = 0)
	{
		if (p4 == NULL)
			shellcodeBuilder->ZeroRegister9();
		else if (is_pointer<T4>::value)
			shellcodeBuilder->MovFakePointerRegister9(shellcodeBuilder->NewFakeObject((POINTER)p4, s4));
		else if (sizeof(T4) <= 4)
			shellcodeBuilder->MovInt32Register9(reinterpret_cast<int&>(p4));
		else
			shellcodeBuilder->MovInt64Register9((LONG)p4);

		Call<STACKSAFE, T1, T2, T3>(shellcodeBuilder, funcAddress, p1, p2, p3, s1, s2, s3);
	}



	//void Call(Shellcode64 shellcodeBuilder, bool stacksafe, LONG funcAddress, params object[] parameters)
	//{
	//	int paramc = parameters.Length;

	//	object param;
	//	switch (paramc)
	//	{
	//	default:
	//		stacksafe = true;
	//		int i = paramc - 1;
	//		do
	//		{
	//			param = parameters[i];
	//			if (param.GetType().IsArray || Marshal.SizeOf(param) > 8)
	//				shellcodeBuilder->PushFakePointer(shellcodeBuilder->NewFakeObject(param));
	//			else
	//				shellcodeBuilder->PushInt64(Convert.ToInt64(param));

	//			i--;
	//		} while (i >= 4);
	//		/*fallthrough*/
	//	case 4:
	//		param = parameters[3];
	//		if (param.GetType().IsArray || Marshal.SizeOf(param) > 8)
	//			shellcodeBuilder->MovFakePointerRegister9(shellcodeBuilder->NewFakeObject(param));
	//		else
	//			shellcodeBuilder->MovInt64Register9(Convert.ToInt64(param));
	//		/*fallthrough*/
	//	case 3:
	//		param = parameters[2];
	//		if (param.GetType().IsArray || Marshal.SizeOf(param) > 8)
	//			shellcodeBuilder->MovFakePointerRegister8(shellcodeBuilder->NewFakeObject(param));
	//		else
	//			shellcodeBuilder->MovInt64Register8(Convert.ToInt64(param));
	//		/*fallthrough*/
	//	case 2:
	//		param = parameters[1];
	//		if (param.GetType().IsArray || Marshal.SizeOf(param) > 8)
	//			shellcodeBuilder->MovFakePointerRegisterD(shellcodeBuilder->NewFakeObject(param));
	//		else
	//			shellcodeBuilder->MovInt64RegisterD(Convert.ToInt64(param));
	//		/*fallthrough*/
	//	case 1:
	//		param = parameters[0];
	//		if (param.GetType().IsArray || Marshal.SizeOf(param) > 8)
	//			shellcodeBuilder->MovFakePointerRegisterC(shellcodeBuilder->NewFakeObject(param));
	//		else
	//			shellcodeBuilder->MovInt64RegisterC(Convert.ToInt64(param));
	//		break;
	//	case 0:
	//		break;
	//	}

	//}

	template<bool STACKSAFE, int PARAMCOUNT>
	inline LateValue<LONG>* LateCall(Shellcode64* shellcodeBuilder, LONG funcAddress)
	{
		LateValue<LONG>* parameters = new LateValue<LONG>[PARAMCOUNT];
		bool stacksafe = STACKSAFE;
		int pushedparambytes = 0;

		switch ((int)PARAMCOUNT)
		{
		default:
		{
			stacksafe = true;
			pushedparambytes = (PARAMCOUNT - 4) * 8;
			int i = PARAMCOUNT - 1;
			do
			{
				shellcodeBuilder->PushLateInt64(&parameters[i]);

				i--;
			} while (i >= 4);
		}
		/*fallthrough*/
		case 4:
			shellcodeBuilder->MovLateInt64Register9(&parameters[3]);
			/*fallthrough*/
		case 3:
			shellcodeBuilder->MovLateInt64Register8(&parameters[2]);
			/*fallthrough*/
		case 2:
			shellcodeBuilder->MovLateInt64RegisterD(&parameters[1]);
			/*fallthrough*/
		case 1:
			shellcodeBuilder->MovLateInt64RegisterC(&parameters[0]);
			break;
		case 0:
			break;
		}

		if (stacksafe)
		{
			shellcodeBuilder
				->FakePushBytes(32)
				->CallFar(funcAddress)
				->FakePopBytes(32 + pushedparambytes);
		}
		else
		{
			shellcodeBuilder->CallFar(funcAddress);
		}

		return parameters;
	}

	template<bool STACKSAFE>
	void GetProcAddress(Shellcode64* shellcodeBuilder, LONG module, char* procName, int procNameLen, FakeObject* result)
	{
		Call<STACKSAFE, LONG, char*>(shellcodeBuilder, getProcAddress, module, procName, 0, procNameLen);
		shellcodeBuilder->MovRegisterAFakePointer(result);
	}
	template<bool STACKSAFE>
	FakeObject* GetProcAddress(Shellcode64* shellcodeBuilder, LONG module, char* procName, int procNameLen)
	{
		FakeObject* result = shellcodeBuilder->NewFakeObject((POINTER)NULL, 0);
		GetProcAddress<STACKSAFE>(shellcodeBuilder, module, procName, procNameLen, result);
		return result;
	}

	template<bool STACKSAFE>
	void GetProcAddressK32(Shellcode64* shellcodeBuilder, char* procName, int procNameLen, FakeObject result)
	{
		GetProcAddress<STACKSAFE>(shellcodeBuilder, kernel32, procName, procNameLen, result);
	}
	template<bool STACKSAFE>
	FakeObject* GetProcAddressK32(Shellcode64* shellcodeBuilder, char* procName, int procNameLen)
	{
		return GetProcAddress<STACKSAFE>(shellcodeBuilder, kernel32, procName, procNameLen);
	}

};

#define CLEARMSG 0

#define REMOTE_RetrieveBytes 1
#define REMOTE_GetLastError 1
#define REMOTE_ExitThread 1
#define REMOTE_GetCurrentProcessId 1
#define REMOTE_GetProcessId 1
#define REMOTE_GetModuleBaseNameA 1
#define REMOTE_ReadProcessMemory 1
#define REMOTE_WriteProcessMemory 1
#define REMOTE_VirtualQueryEx 1
//#define REMOTE_CreateToolhelp32Snapshot 1
//#define REMOTE_Module32First 1
//#define REMOTE_Module32Next 1
#define REMOTE_CloseHandle 1
#define REMOTE_EnumProcessModulesEx 1
#define REMOTE_GetModuleInformation 1
#define REMOTE_OpenProcess 1
#define REMOTE_EnumProcesses 1
#define REMOTE_LocalAlloc 1
#define REMOTE_LocalFree 1

//#define REMOTE_malloc 1
//#define REMOTE_free 1

#define REMOTE_NtQuerySystemInformation 1
#define REMOTE_NtQueryObject 1
//#define REMOTE_NtReadVirtualMemory 1 TODO!
//#define REMOTE_NtWriteVirtualMemory 1 TODO!
//#define REMOTE_GetModuleHandleA 1
//#define REMOTE_GetProcAddress 1
//#define REMOTE_RtlFillMemory 1

//#define REMOTE_FindWindowA 1
//#define REMOTE_GetWindowThreadProcessId 1


class RemoteCalls64
{
#define GETPROCADDRESSK32(procName) GetProcAddressK32(CSTRWITHSIZE(procName))
#define GETMODULEHANDLEA(moduleName) GetModuleHandleA(CSTRWITHSIZE(moduleName))
#define GETPROCADDRESS(moduleHandle, procName) GetProcAddress(moduleHandle, CSTRWITHSIZE(procName))

#if REMOTE_SetCursorPos | REMOTE_MessageBoxA | REMOTE_FindWindowA
#define REMOTE_USER32 1
#endif
#if REMOTE_malloc | REMOTE_free
#define REMOTE_UCRTBASE 1
#endif
#if REMOTE_NtQuerySystemInformation | REMOTE_NtQueryObject
#define REMOTE_NTDLL 1
#endif

#if REMOTE_USER32 | REMOTE_UCRTBASE | REMOTE_NTDLL
#if !REMOTE_GetModuleHandleA
#define REMOTE_GetModuleHandleA 1
#endif
#if !REMOTE_GetProcAddress
#define REMOTE_GetProcAddress 1
#endif
#endif

	BYTE* buffer;
	int bufferSize;
	int socket;
	Shellcode64* shellcodeBuilder;
	ShellcodeMacro64* macro;

	LONG rtlFillMemory;

public:
	int Errorcode = 0;
private:


	inline bool sendShellcode(Shellcode shellcode)
	{
		//sendto(socket, shellcode.Buffer, shellcode.Size, 0, (sockaddr*)&clientAddress, clientAddressLength);
		bool success = send(socket, shellcode.Buffer, /*shellcode.Size*/macro->MsgSize, 0);
		if (success) return true;
		Errorcode = SEND_FAIL;
		return false;
	}
	inline bool runShellcode(Shellcode shellcode, int responseLength)
	{
		bool success = sendShellcode(shellcode);
		if (!success)
			return false;
		//return recvfrom(socket, buffer, bufferSize, 0, (sockaddr*)&clientAddress, &clientAddressLength);
		int result = recv(socket, buffer, /*bufferSize*/responseLength, MSG_WAITALL);
		//if (result == responseLength)
		//	return true;

		if (result == -1)
		{
			Errorcode = RECV_FAIL;
			return false;
		}

		//int size = result;
		//do
		//{
		//	int result = recv(socket, buffer + size, bufferSize - size, 0);

		//	if (result == -1)
		//	{
		//		Errorcode = RECV_FAIL;
		//		return false;
		//	}
		//	
		//	size += result;
		//} while (size < responseLength);

		return true;
	}

	LONG getProcAddressK32Unsafe(char* procName, int procNameLen)
	{
		shellcodeBuilder->Reset();
		FakeObject* result = macro->GetProcAddressK32<false>(shellcodeBuilder, procName, procNameLen);
		Shellcode shellcode = macro->Complete(shellcodeBuilder, result, 8);
		if (!runShellcode(shellcode, 8)) return 0;

		return *(LONG*)buffer;
	}

	LONG GetProcAddressK32(char* procName, int procNameLen)
	{
		shellcodeBuilder->Reset();
		FakeObject* result = macro->GetProcAddressK32<false>(shellcodeBuilder, procName, procNameLen);
		Shellcode shellcode = macro->SafeComplete(shellcodeBuilder, rtlFillMemory, result, 8);
		if (!runShellcode(shellcode, 8)) return 0;

		return *(LONG*)buffer;
	}

#if CLEARMSG

	inline int _returnCallStart()
	{
		int lastShellcodeSize = shellcodeBuilder->GetCurrentCodeSize();
		shellcodeBuilder->Reset();
		return lastShellcodeSize;
	}

	template<typename T>
	inline T _returnCallEnd(int lastShellcodeSize)
	{
		LateValue<LONG> result, sendBuffer;
		shellcodeBuilder->MovRegisterALatePointer(&result);
		Shellcode shellcode = macro->SafeComplete(shellcodeBuilder, rtlFillMemory, &sendBuffer, sizeof(T));
		LONG bufferAddress = shellcode.GetEndAddress();
		result.Insert(bufferAddress);
		sendBuffer.Insert(bufferAddress);

		if(lastShellcodeSize > shellcode.Size)
			memset(shellcode.GetEndPointer(), 0x00, lastShellcodeSize - shellcode.Size)

		if (!runShellcode(shellcode, sizeof(T))) return (T)0;

		return *(T*)buffer;
	}

#define returnCallStart() int lastShellcodeSize = _returnCallStart()
#define returnCallEnd() _returnCallEnd(lastShellcodeSize)

#else
	inline void returnCallStart()
	{
		shellcodeBuilder->Reset();
		//return shellcodeBuilder->NewFakeObject((POINTER)NULL, 0);
	}

	template<typename T>
	inline T returnCallEnd()
	{
		LateValue<LONG> result, sendBuffer;
		shellcodeBuilder->MovRegisterALatePointer(&result);
		Shellcode shellcode = macro->SafeComplete(shellcodeBuilder, rtlFillMemory, &sendBuffer, sizeof(T));
		LONG bufferAddress = shellcode.GetEndAddress();
		result.Insert(bufferAddress);
		sendBuffer.Insert(bufferAddress);
		if (!runShellcode(shellcode, sizeof(T))) return (T)0;

		return *(T*)buffer;
	}
#endif

	template<typename R>
	inline R returnCall(LONG funcAddress)
	{
		returnCallStart();
		macro->Call<false>(shellcodeBuilder, funcAddress);
		return returnCallEnd<R>();
	}
	template<typename R, typename T1>
	inline R returnCall(LONG funcAddress, T1 p1, int s1 = 0)
	{
		returnCallStart();
		macro->Call<false, T1>(shellcodeBuilder, funcAddress, p1, s1);
		return returnCallEnd<R>();
	}
	template<typename R, typename T1, typename T2>
	inline R returnCall(LONG funcAddress, T1 p1, T2 p2, int s1 = 0, int s2 = 0)
	{
		returnCallStart();
		macro->Call<false, T1, T2>(shellcodeBuilder, funcAddress, p1, p2, s1, s2);
		return returnCallEnd<R>();
	}
	template<typename R, typename T1, typename T2, typename T3>
	inline R returnCall(LONG funcAddress, T1 p1, T2 p2, T3 p3, int s1 = 0, int s2 = 0, int s3 = 0)
	{
		returnCallStart();
		macro->Call<false, T1, T2, T3>(shellcodeBuilder, funcAddress, p1, p2, p3, s1, s2, s3);
		return returnCallEnd<R>();
	}
	template<typename R, typename T1, typename T2, typename T3, typename T4>
	inline R returnCall(LONG funcAddress, T1 p1, T2 p2, T3 p3, T4 p4, int s1 = 0, int s2 = 0, int s3 = 0, int s4 = 0)
	{
		returnCallStart();
		macro->Call<false, T1, T2, T3, T4>(shellcodeBuilder, funcAddress, p1, p2, p3, p4, s1, s2, s3, s4);
		return returnCallEnd<R>();
	}

	inline void voidCallStart()
	{
		shellcodeBuilder->Reset();
	}
	inline void voidCallEnd()
	{
		macro->Call<false, LONG, int, BYTE>(shellcodeBuilder, rtlFillMemory, shellcodeBuilder->GetCurrentEntryPoint(), shellcodeBuilder->GetCurrentCodeSize(), (BYTE)0xCC);
		macro->Recv(shellcodeBuilder);
		sendShellcode(shellcodeBuilder->Complete());
	}

	void voidCall(LONG funcAddress)
	{
		voidCallStart();
		macro->Call<false>(shellcodeBuilder, funcAddress);
		voidCallEnd();
	}
	template<typename T1>
	inline void voidCall(LONG funcAddress, T1 p1, int s1 = 0)
	{
		voidCallStart();
		macro->Call<false, T1>(shellcodeBuilder, funcAddress, p1, s1);
		voidCallEnd();
	}
public:


#if REMOTE_GetProcAddress
	LONG GetProcAddress(LONG moduleHandle, char* procName, int procNameLen)
	{
		shellcodeBuilder->Reset();
		FakeObject* result = macro->GetProcAddress<false>(shellcodeBuilder, moduleHandle, procName, procNameLen);
		Shellcode shellcode = macro->SafeComplete(shellcodeBuilder, rtlFillMemory, result, 8);
		if(!runShellcode(shellcode, 8)) return 0;

		return *(LONG*)buffer;
	}
	LONG GetProcAddress(LONG moduleHandle, char* procName)
	{
		return GetProcAddress(moduleHandle, procName, strlen(procName) + 1);
	}
#endif // REMOTE_GetProcAddress

#if REMOTE_GetModuleHandleA
private:
	LONG getModuleHandleA;
public:
	LONG GetModuleHandleA(char* moduleName, int moduleNameSize)
	{
		return returnCall<LONG, char*>(getModuleHandleA, moduleName, moduleNameSize);
	}
	LONG GetModuleHandleA(char* moduleName)
	{
		return returnCall<LONG, char*>(getModuleHandleA, moduleName, strlen(moduleName) + 1);
	}
#endif // REMOTE_GetModuleHandleA

#if REMOTE_GetLastError
private:
	LONG getLastError;
public:
	UINT GetLastError()
	{
		return returnCall<UINT>(getLastError);
	}
#endif // REMOTE_GetLastError

#if REMOTE_Beep
private:
	LONG beep;
public:
	bool Beep(UINT frequency, UINT duration)
	{
		return int64Call<UINT, UINT>(beep, frequency, duration) != 0;
	}
#endif // REMOTE_Beep

#if REMOTE_GetCurrentProcessId
private:
	LONG getCurrentProcessId;
public:
	UINT GetCurrentProcessId()
	{
		return returnCall<UINT>(getCurrentProcessId);
	}
#endif // REMOTE_GetCurrentProcessId

#if REMOTE_GetProcessId
private:
	LONG getProcessId;
public:
	UINT GetProcessId(LONG processHandle)
	{
		return returnCall<UINT, LONG>(getProcessId, processHandle);
	}
#endif // REMOTE_GetProcessId

#if REMOTE_GetModuleBaseNameA
private:
	LONG getModuleBaseNameA;
public:
	//use small buffersize
	UINT GetModuleBaseNameA(LONG processHandle, LONG moduleHandle, char** baseNamePtr, UINT size)
	{
		shellcodeBuilder->Reset();
		LateValue<LONG> sendBuffer, result;
		LateValue<LONG>* parameters = macro->LateCall<false, 4>(shellcodeBuilder, getModuleBaseNameA);
		shellcodeBuilder->MovRegisterALatePointer(&result);
		int sendSize = 8 + size;
		Shellcode shellcode = macro->SafeComplete(shellcodeBuilder, rtlFillMemory, &sendBuffer, sendSize);

		LONG bufferAddress = shellcode.GetEndAddress();
		sendBuffer.Insert(bufferAddress);
		result.Insert(bufferAddress);
		parameters[0].Insert(processHandle);
		parameters[1].Insert(moduleHandle);
		parameters[2].Insert(bufferAddress + 8);
		parameters[3].Insert(size);

		delete[] parameters;

		if (!runShellcode(shellcode, sendSize)) return 0;

		UINT returnLength = *(UINT*)buffer;
		*baseNamePtr = (char*)(buffer + 8);
		return returnLength;
	}
	//use small buffersize
	UINT GetModuleBaseNameA(LONG processHandle, LONG moduleHandle, char* baseName, UINT size)
	{

		char* nameBufferPtr;
		UINT returnLength = GetModuleBaseNameA(processHandle, moduleHandle, &nameBufferPtr, size);
		memcpy(baseName, nameBufferPtr, returnLength + 1); //+null terminator
		return returnLength;
	}
#endif // GetModuleBaseNameA

#if REMOTE_ExitThread
private:
	LONG exitThread;
public:
	void ExitThread(UINT exitCode)
	{
		shellcodeBuilder->Reset();
		macro->Call<false, UINT>(shellcodeBuilder, exitThread, exitCode);
		Shellcode shellcode = shellcodeBuilder->Complete();
		sendShellcode(shellcode);
	}
#endif // REMOTE_ExitThread	

#if REMOTE_ReadProcessMemory
private:
	LONG readProcessMemory;
	Shellcode rProcMem;
	LateValue<int> rpmBufSize, rpmNextRecvSize;
	LateValue<LONG> rpmProc, rpmAddr, rpmSize;
	inline bool initReadProcessMemory()
	{
		readProcessMemory = GETPROCADDRESSK32("ReadProcessMemory");
		if(readProcessMemory == NULL) return false;

		const int rpmBuflen = 512;
		POINTER rpmBuffer = new BYTE[rpmBuflen];

		Shellcode64 tmpBuilder = Shellcode64(rpmBuffer, rpmBuflen, shellcodeBuilder->RemoteAddress);
		LateValue<LONG> rpmBufAddr/*, result*/;
		LateValue<LONG>* parameters = macro->LateCall<false, 5>(&tmpBuilder, readProcessMemory);
		//shellcodeBuilder->MovRegisterALatePointer(out result);
		rProcMem = macro->SafeComplete(&tmpBuilder, rtlFillMemory, &rpmBufAddr, &rpmBufSize, &rpmNextRecvSize);
		LONG bufferAddress = rProcMem.GetEndAddress();
		rpmProc = parameters[0];
		rpmAddr = parameters[1];
		parameters[2].Insert(bufferAddress + /*16*/8);
		rpmSize = parameters[3];
		parameters[4].Insert(bufferAddress /*+ 8*/);

		delete[] parameters;
		//result.Insert(bufferAddress);
		rpmBufAddr.Insert(bufferAddress);
		return true;
	}
	inline void freeReadProcessMemory()
	{
		delete[] rProcMem.Buffer;
	}
public:
	inline bool ReadProcessMemory(LONG processHandle, LONG baseAddress, BYTE** readBufferPtr, LONG size)
	{
		rpmNextRecvSize.Insert(macro->MsgSize);

		rpmProc.Insert(processHandle);
		rpmAddr.Insert(baseAddress);
		rpmSize.Insert(size);

		int sendSize = /*16*/8 + size;
		rpmBufSize.Insert(sendSize);
		if (!runShellcode(rProcMem, sendSize)) return false;

		LONG bytesRead = *(LONG*)buffer;
		if (bytesRead == 0) return false;
		*readBufferPtr = buffer + 8;
		return true;
	}
	inline bool ReadProcessMemory(LONG processHandle, LONG baseAddress, BYTE** readBufferPtr, LONG size, LONG* numberOfBytesRead)
	{
		rpmNextRecvSize.Insert(macro->MsgSize);

		rpmProc.Insert(processHandle);
		rpmAddr.Insert(baseAddress);
		rpmSize.Insert(size);

		int sendSize = /*16*/8 + size;
		rpmBufSize.Insert(sendSize);
		if (!runShellcode(rProcMem, sendSize))
		{
			if (numberOfBytesRead != NULL) *numberOfBytesRead = 0;
			return false;
		}
		LONG bytesRead = *(LONG*)buffer;
		if (numberOfBytesRead != NULL) *numberOfBytesRead = bytesRead;
		if (bytesRead == 0) return false;
		*readBufferPtr = buffer + 8;
		return true;
	}
	inline bool ReadProcessMemory(LONG processHandle, LONG baseAddress, BYTE* readBuffer, LONG size, LONG* numberOfBytesRead)
	{
		BYTE* readBufferPtr;
		bool success = ReadProcessMemory(processHandle, baseAddress, &readBufferPtr, size, numberOfBytesRead);
		if (!success) return false;
		memcpy(readBuffer, readBufferPtr, *numberOfBytesRead);
		return true;
	}
	inline bool ReadProcessMemory(LONG processHandle, LONG baseAddress, BYTE* readBuffer, LONG size)
	{
		BYTE* readBufferPtr;
		LONG numberOfBytesRead;
		bool success = ReadProcessMemory(processHandle, baseAddress, &readBufferPtr, size, &numberOfBytesRead);
		if (!success) return false;
		memcpy(readBuffer, readBufferPtr, numberOfBytesRead);
		return true;
	}
#endif // REMOTE_ReadProcessMemory

#if REMOTE_WriteProcessMemory
private:
	LONG writeProcessMemory;
	Shellcode wProcMem;
	int wProcMemSize;
	LateValue<int> wpmNextRecvSize;
	LateValue<LONG> wpmProc, wpmAddr, wpmSize;
	POINTER wProcMemEnd;
	inline bool initWriteProcessMemory()
	{
		writeProcessMemory = GETPROCADDRESSK32("WriteProcessMemory");
		if (writeProcessMemory == NULL) return false;

		const int wpmBuflen = 4096;
		POINTER wpmBuffer = new BYTE[wpmBuflen];

		Shellcode64 tmpBuilder = Shellcode64(wpmBuffer, wpmBuflen, shellcodeBuilder->RemoteAddress);
		LateValue<LONG> wpmBufAddr/*, result*/;
		LateValue<LONG>* parameters = macro->LateCall<false, 5>(&tmpBuilder, writeProcessMemory);
		//shellcodeBuilder->MovRegisterALatePointer(out result);
		wProcMem = macro->SafeComplete(&tmpBuilder, rtlFillMemory, &wpmBufAddr, 8, &wpmNextRecvSize);
		LONG bufferAddress = wProcMem.GetEndAddress();
		wpmProc = parameters[0];
		wpmAddr = parameters[1];
		parameters[2].Insert(bufferAddress);
		wpmSize = parameters[3];
		parameters[4].Insert(bufferAddress);

		delete[] parameters;
		//result.Insert(bufferAddress);
		wpmBufAddr.Insert(bufferAddress);
		wProcMemEnd = wProcMem.GetEndPointer();
		wProcMemSize = wProcMem.Size;
		return true;
	}
	inline void freeWriteProcessMemory()
	{
		delete[] wProcMem.Buffer;
	}
public:
	inline bool WriteProcessMemory(LONG processHandle, LONG baseAddress, BYTE* writeBuffer, LONG size, LONG* numberOfBytesWritten)
	{
		wpmNextRecvSize.Insert(macro->MsgSize);

		wpmProc.Insert(processHandle);
		wpmAddr.Insert(baseAddress);
		wpmSize.Insert(size);

		memcpy(wProcMemEnd, writeBuffer, size);
		if (!runShellcode(wProcMem, 8)) return false;

		LONG bytesWritten = *(LONG*)buffer;
		if (bytesWritten == 0) return false;
		*numberOfBytesWritten = bytesWritten;
		return true;
	}
	inline bool WriteProcessMemory(LONG processHandle, LONG baseAddress, BYTE* writeBuffer, LONG size)
	{
		wpmNextRecvSize.Insert(macro->MsgSize);

		wpmProc.Insert(processHandle);
		wpmAddr.Insert(baseAddress);
		wpmSize.Insert(size);

		memcpy(wProcMemEnd, writeBuffer, size);
		wProcMem.Size = wProcMemSize + size;
		if (!runShellcode(wProcMem, 8)) return false;

		LONG bytesWritten = *(LONG*)buffer;
		if (bytesWritten == 0) return false;

		return true;
	}
#endif // REMOTE_WriteProcessMemory

#if REMOTE_VirtualQueryEx
private:
	LONG virtualQueryEx;
public:
	//use minimum bufferLength
	LONG VirtualQueryEx(LONG processHandle, LONG address, MEMORY_BASIC_INFORMATION64** memoryInfoPtr)
	{
		shellcodeBuilder->Reset();
		LateValue<LONG> sendBuffer, result;
		LateValue<LONG>* parameters = macro->LateCall<false, 4>(shellcodeBuilder, virtualQueryEx);
		shellcodeBuilder->MovRegisterALatePointer(&result);
		int memoryInfoSize = sizeof(MEMORY_BASIC_INFORMATION64);
		int sendSize = memoryInfoSize + 8;
		Shellcode shellcode = macro->SafeComplete(shellcodeBuilder, rtlFillMemory, &sendBuffer, sendSize);

		LONG bufferAddress = Shellcode::Align(shellcode.GetEndAddress(), 4);
		sendBuffer.Insert(bufferAddress);
		result.Insert(bufferAddress + memoryInfoSize);
		parameters[0].Insert(processHandle);
		parameters[1].Insert(address);
		parameters[2].Insert(bufferAddress);
		parameters[3].Insert(memoryInfoSize);

		delete[] parameters;

		if (!runShellcode(shellcode, sendSize)) return 0;

		*memoryInfoPtr = (MEMORY_BASIC_INFORMATION64*)buffer;
		return *(LONG*)(buffer + memoryInfoSize);
	}
	LONG VirtualQueryEx(LONG processHandle, LONG address, MEMORY_BASIC_INFORMATION64* memoryInfo, LONG bufferLength = sizeof(MEMORY_BASIC_INFORMATION64))
	{
		MEMORY_BASIC_INFORMATION64* memoryInfoPtr;
		LONG returnLength = VirtualQueryEx(processHandle, address, &memoryInfoPtr);
		memcpy(memoryInfo, memoryInfoPtr, returnLength);
		return returnLength;
	}
#endif // REMOTE_VirtualQueryEx

#if REMOTE_CreateToolhelp32Snapshot
private:
	LONG createToolhelp32Snapshot;
public:
	LONG CreateToolhelp32Snapshot(UINT flags, UINT processId)
	{
		return returnCall<LONG, UINT, UINT>(createToolhelp32Snapshot, flags, processId);
	}
#endif // REMOTE_CreateToolhelp32Snapshot

#if REMOTE_Module32First
private:
	LONG module32First;
public:
	bool Module32First(LONG snapshotHandle, MODULEENTRY3264** moduleEntryPtr)
	{
		FakeObject* moduleEntry; //might need alignment
		LateValue<LONG> result;
		const UINT moduleEntrySize = sizeof(MODULEENTRY3264);
		shellcodeBuilder->Reset()
			->MovInt64RegisterC(snapshotHandle)
			->NewFakeObject<UINT>((UINT*)&moduleEntrySize, &moduleEntry)
			->MovFakePointerRegisterD(moduleEntry)
			->CallFar(module32First)
			->MovRegisterALatePointer(&result);
		int sendSize = (int)moduleEntrySize + /*8*/1;
		Shellcode shellcode = macro->SafeComplete(shellcodeBuilder, rtlFillMemory, moduleEntry, sendSize);

		result.Insert(shellcode.GetEndAddress() + moduleEntrySize - sizeof(UINT));


		int recvLen = runShellcode(shellcode);
		if (recvLen != sendSize) return false;
		bool success = *(bool*)(buffer + moduleEntrySize);
		if (!success) return false;

		*moduleEntryPtr = (MODULEENTRY3264*)buffer;
		return true;
	}
	bool Module32First(LONG snapshotHandle, MODULEENTRY3264* moduleEntry)
	{
		MODULEENTRY3264* moduleEntryPtr;
		bool success = Module32First(snapshotHandle, &moduleEntryPtr);
		if (!success) return false;
		memcpy(moduleEntry, moduleEntryPtr, sizeof(MODULEENTRY3264));
		return true;
	}
#endif // REMOTE_Module32First

#if REMOTE_Module32Next
private:
	LONG module32Next;
public:
	bool Module32Next(LONG snapshotHandle, MODULEENTRY3264** moduleEntryPtr)
	{
		//note: setting size isn't necessary here
		LateValue<LONG> moduleEntry, result, sendBuffer;
		const UINT moduleEntrySize = sizeof(MODULEENTRY3264);
		shellcodeBuilder->Reset()
			->MovInt64RegisterC(snapshotHandle)
			->MovLateInt64RegisterD(&moduleEntry)  //might need alignment
			->CallFar(module32Next)
			->MovRegisterALatePointer(&result);
		int sendSize = (int)moduleEntrySize + /*8*/1;
		Shellcode shellcode = macro->SafeComplete(shellcodeBuilder, rtlFillMemory, &sendBuffer, sendSize);

		LONG bufferAddress = shellcode.GetEndAddress();
		sendBuffer.Insert(bufferAddress);
		moduleEntry.Insert(bufferAddress);
		result.Insert(bufferAddress + moduleEntrySize);


		int recvLen = runShellcode(shellcode);
		if (recvLen != sendSize) return false;
		bool success = *(bool*)(buffer + moduleEntrySize);
		if (!success) return false;

		*moduleEntryPtr = (MODULEENTRY3264*)buffer;
		return true;
	}
	bool Module32Next(LONG snapshotHandle, MODULEENTRY3264* moduleEntry)
	{
		MODULEENTRY3264* moduleEntryPtr;
		bool success = Module32Next(snapshotHandle, &moduleEntryPtr);
		if (!success) return false;
		memcpy(moduleEntry, moduleEntryPtr, sizeof(MODULEENTRY3264));
		return true;
	}
#endif // REMOTE_Module32First

#if REMOTE_CloseHandle
private:
	LONG closeHandle;
public:
	bool CloseHandle(LONG objectHandle)
	{
		return returnCall<bool, LONG>(closeHandle, objectHandle);
	}
#endif // REMOTE_CloseHandle

#if REMOTE_EnumProcessModulesEx
private:
	LONG enumProcessModulesEx;
public:
	//use small buffer size
	bool EnumProcessModulesEx(LONG processHandle, LONG** moduleArrayPtr, UINT moduleArraySize, UINT* neededSize, UINT filterFlag)
	{
		shellcodeBuilder->Reset();
		LateValue<LONG> sendBuffer, result;
		LateValue<LONG>* parameters = macro->LateCall<false, 5>(shellcodeBuilder, enumProcessModulesEx);
		shellcodeBuilder->MovRegisterALatePointer(&result);
		int sendSize = 16 + (int)moduleArraySize;
		Shellcode shellcode = macro->SafeComplete(shellcodeBuilder, rtlFillMemory, &sendBuffer, sendSize);

		LONG bufferAddress = shellcode.GetEndAddress();
		sendBuffer.Insert(bufferAddress);
		result.Insert(bufferAddress);
		parameters[0].Insert(processHandle);
		parameters[1].Insert(bufferAddress + 16);
		parameters[2].Insert(moduleArraySize);
		parameters[3].Insert(bufferAddress + 8);
		parameters[4].Insert(filterFlag);

		delete[] parameters;

		if (!runShellcode(shellcode, sendSize))
		{
			*neededSize = 0;
			return false;
		}

		UINT needed = *(UINT*)(buffer + 8);
		*neededSize = needed;
		bool success = *(bool*)buffer;
		*moduleArrayPtr = (LONG*)(buffer + 16);
		return success;
	}
	bool EnumProcessModulesEx(LONG processHandle, LONG* moduleArray, UINT moduleArraySize, UINT* neededSize, UINT filterFlag)
	{
		LONG* moduleArrayPtr;
		bool success = EnumProcessModulesEx(processHandle, &moduleArrayPtr, moduleArraySize, neededSize, filterFlag);
		if (!success) return false;
		memcpy(moduleArray, moduleArrayPtr, *neededSize);
		return true;
	}
	bool EnumProcessModulesEx(LONG processHandle, LONG moduleArray, UINT moduleArraySize, UINT* neededSize, UINT filterFlag)
	{
		shellcodeBuilder->Reset();
		LateValue<LONG> sendBuffer, result;
		LateValue<LONG>* parameters = macro->LateCall<false, 5>(shellcodeBuilder, enumProcessModulesEx);
		shellcodeBuilder->MovRegisterALatePointer(&result);
		const int sendSize = 16;
		Shellcode shellcode = macro->SafeComplete(shellcodeBuilder, rtlFillMemory, &sendBuffer, sendSize);

		LONG bufferAddress = shellcode.GetEndAddress();
		sendBuffer.Insert(bufferAddress);
		result.Insert(bufferAddress);
		parameters[0].Insert(processHandle);
		parameters[1].Insert(moduleArray);
		parameters[2].Insert(moduleArraySize);
		parameters[3].Insert(bufferAddress + 8);
		parameters[4].Insert(filterFlag);

		delete[] parameters;

		if (!runShellcode(shellcode, sendSize))
		{
			*neededSize = 0;
			return false;
		}

		UINT needed = *(UINT*)(buffer + 8);
		*neededSize = needed;
		bool success = *(bool*)buffer;
		return success;
	}
#endif // REMOTE_EnumProcessModules

#if REMOTE_EnumProcesses
private:
	LONG enumProcesses;
public:
	//use small buffer size
	bool EnumProcesses(UINT** processIdArrayPtr, UINT processIdArraySize, UINT* returnSize)
	{
		shellcodeBuilder->Reset();
		LateValue<LONG> sendBuffer, result;
		LateValue<LONG>* parameters = macro->LateCall<false, 3>(shellcodeBuilder, enumProcesses);
		shellcodeBuilder->MovRegisterALatePointer(&result);
		int sendSize = 16 + (int)processIdArraySize;
		Shellcode shellcode = macro->SafeComplete(shellcodeBuilder, rtlFillMemory, &sendBuffer, sendSize);

		LONG bufferAddress = shellcode.GetEndAddress();
		parameters[0].Insert(bufferAddress + 16);
		parameters[1].Insert(processIdArraySize);
		parameters[2].Insert(bufferAddress + 8);
		delete[] parameters;
		sendBuffer.Insert(bufferAddress);
		result.Insert(bufferAddress);

		if (!runShellcode(shellcode, sendSize))
		{
			//*returnSize = 0;
			return false;
		}

		bool success = *(bool*)buffer;
		if (!success)
			return false;

		*returnSize = *(UINT*)(buffer + 8);
		*processIdArrayPtr = (UINT*)(buffer + 16);
		return true;
	}
	bool EnumProcesses(UINT* processIdArray, UINT processIdArraySize, UINT* returnSize)
	{
		UINT* processIdArrayPtr;
		bool success = EnumProcesses(&processIdArrayPtr, processIdArraySize, returnSize);
		if (!success) return false;
		memcpy(processIdArray, processIdArrayPtr, *returnSize);
		return true;
	}
	bool EnumProcesses(LONG processIdArray, UINT processIdArraySize, UINT* returnSize)
	{
		shellcodeBuilder->Reset();
		LateValue<LONG> sendBuffer, result;
		LateValue<LONG>* parameters = macro->LateCall<false, 3>(shellcodeBuilder, enumProcesses);
		shellcodeBuilder->MovRegisterALatePointer(&result);
		int sendSize = 16;
		Shellcode shellcode = macro->SafeComplete(shellcodeBuilder, rtlFillMemory, &sendBuffer, sendSize);

		LONG bufferAddress = shellcode.GetEndAddress();
		parameters[0].Insert(processIdArray);
		parameters[1].Insert(processIdArraySize);
		parameters[2].Insert(bufferAddress + 8);
		delete[] parameters;
		sendBuffer.Insert(bufferAddress);
		result.Insert(bufferAddress);

		if (!runShellcode(shellcode, sendSize))
			return false;

		bool success = *(bool*)buffer;
		if (!success)
			return false;

		*returnSize = *(UINT*)(buffer + 8);
		return true;
	}
#endif // REMOTE_EnumProcesses

#if REMOTE_GetModuleInformation
private:
	LONG getModuleInformation;
public:
	bool GetModuleInformation(LONG processHandle, LONG moduleHandle, MODULEINFO64** moduleInfoPtr)
	{
		shellcodeBuilder->Reset();
		LateValue<LONG> sendBuffer, result;
		LateValue<LONG>* parameters = macro->LateCall<false, 4>(shellcodeBuilder, getModuleInformation);
		shellcodeBuilder->MovRegisterALatePointer(&result);
		const int moduleInfoSize = sizeof(MODULEINFO64);
		int sendSize = moduleInfoSize + /*8*/1;
		Shellcode shellcode = macro->SafeComplete(shellcodeBuilder, rtlFillMemory, &sendBuffer, sendSize);

		LONG bufferAddress = shellcode.GetEndAddress();
		sendBuffer.Insert(bufferAddress);
		result.Insert(bufferAddress + moduleInfoSize);
		parameters[0].Insert(processHandle);
		parameters[1].Insert(moduleHandle);
		parameters[2].Insert(bufferAddress);
		parameters[3].Insert(moduleInfoSize);

		delete[] parameters;

		if (!runShellcode(shellcode, sendSize)) return false;

		bool success = *(bool*)(buffer + moduleInfoSize);
		*moduleInfoPtr = (MODULEINFO64*)buffer;
		return success;
	}
	bool GetModuleInformation(LONG processHandle, LONG moduleHandle, MODULEINFO64* moduleInfo, UINT moduleInfoSize)
	{
		MODULEINFO64* moduleInfoPtr;
		bool success = GetModuleInformation(processHandle, moduleHandle, &moduleInfoPtr);
		if (!success) return false;
		memcpy(moduleInfo, moduleInfoPtr, sizeof(MODULEINFO64));
		return true;
	}
#endif // REMOTE_GetModuleInformation

#if REMOTE_OpenProcess
private:
	LONG openProcess;
public:
	LONG OpenProcess(UINT desiredAccess, bool inheritHandle, UINT processId)
	{
		return returnCall<LONG, UINT, bool, UINT>(openProcess, desiredAccess, inheritHandle, processId);
	}
#endif // REMOTE_OpenProcess

#if REMOTE_LocalAlloc
private:
	LONG localAlloc;
public:
	LONG LocalAlloc(UINT flags, LONG bytes)
	{
		return returnCall<LONG, UINT, LONG>(localAlloc, flags, bytes);
	}
#endif // REMOTE_LocalAlloc

#if REMOTE_LocalFree
private:
	LONG localFree;
public:
	LONG LocalFree(LONG memory)
	{
		return returnCall<LONG, LONG>(localFree, memory);
	}
#endif // REMOTE_LocalFree


#if REMOTE_USER32
private:
	LONG user32;
#if REMOTE_SetCursorPos
	LONG setCursorPos;
public:
	bool SetCursorPos(int X, int Y)
	{
		return int64Call<int, int>(setCursorPos, X, Y) != 0;
	}
#endif // REMOTE_SetCursorPos

#if REMOTE_MessageBoxA
private:
	LONG messageBoxA;
public:
	int MessageBoxA(LONG windowHandle, char* text, char* title, UINT type)
	{
		int textSize, titleSize;
		if (text != NULL) textSize = strlen(text) + 1;
		else textSize = 0;
		if (title != NULL) titleSize = strlen(title) + 1;
		else titleSize = 0;
		return (int)int64Call<LONG, char*, char*, UINT>(messageBoxA, windowHandle, text, title, type, 0, textSize, titleSize);
	}
#endif // REMOTE_MessageBoxA

#if REMOTE_FindWindowA
private:
	LONG findWindowA;
public:
	LONG FindWindowA(char* className, int classNameSize, char* windowName, int windowNameSize)
	{
		return returnCall<LONG, char*, char*>(findWindowA, className, windowName, classNameSize, windowNameSize);
	}
	LONG FindWindowA(char* className, char* windowName)
	{
		int classNameSize, windowNameSize;
		if (className != NULL) classNameSize = strlen(className) + 1;
		else classNameSize = 0;
		if (windowName != NULL) windowNameSize = strlen(windowName) + 1;
		else windowNameSize = 0;
		return FindWindowA(className, classNameSize, windowName, windowNameSize);
	}
#endif // REMOTE_FindWindowA

#if REMOTE_GetWindowThreadProcessId
private:
	LONG getWindowThreadProcessId;
public:
	UINT GetWindowThreadProcessId(LONG windowHandle, UINT* processId)
	{
		shellcodeBuilder->Reset();
		LateValue<LONG> sendBuffer, result;
		LateValue<LONG>* parameters = macro->LateCall<false, 2>(shellcodeBuilder, getWindowThreadProcessId);
		shellcodeBuilder->MovRegisterALatePointer(&result);
		const int sendSize = 4 + 4; //intentional trampling
		Shellcode shellcode = macro->SafeComplete(shellcodeBuilder, rtlFillMemory, &sendBuffer, sendSize);

		LONG bufferAddress = shellcode.GetEndAddress();
		parameters[0].Insert(windowHandle);
		parameters[1].Insert(bufferAddress);
		delete[] parameters;
		result.Insert(bufferAddress + 4);
		sendBuffer.Insert(bufferAddress);

		if (!runShellcode(shellcode, sendSize)) return 0;

		*processId = *(UINT*)buffer;
		return *(UINT*)(buffer + 4);
	}
#endif // REMOTE_GetWindowThreadProcessId


#endif


#if REMOTE_UCRTBASE
private:
	LONG ucrtbase;
#if REMOTE_malloc
	LONG pmalloc;
public:
	LONG malloc(LONG size)
	{
		return returnCall<LONG, LONG>(pmalloc, size);
	}
#endif // REMOTE_malloc

#if REMOTE_free
private:
	LONG pfree;
public:
	void free(LONG ptr)
	{
		voidCall<LONG>(pfree, ptr);
	}
#endif // REMOTE_free

#endif // REMOTE_UCRTBASE


#if REMOTE_NTDLL
private:
	LONG ntdll;

#if REMOTE_NtQuerySystemInformation
	LONG ntQuerySystemInformation;
public:
	int NtQuerySystemInformation(int systemInformationClass, LONG systemInformationPtr, UINT systemInformationLength, UINT* returnLength)
	{
		LateValue<LONG> result, returnLen, sendBuffer;

		shellcodeBuilder
			->Reset()

			->MovInt64RegisterC(systemInformationClass)
			->MovInt64RegisterD(systemInformationPtr)
			->MovInt64Register8(systemInformationLength)
			->MovLateInt64Register9(&returnLen)
			->CallFar(ntQuerySystemInformation)

			->MovRegisterALatePointer(&result);

		Shellcode shellcode = macro->SafeComplete(shellcodeBuilder, rtlFillMemory, &sendBuffer, 8 * 2);

		LONG bufferAddress = shellcode.GetEndAddress();
		sendBuffer.Insert(bufferAddress);
		result.Insert(bufferAddress);
		returnLen.Insert(bufferAddress + 8);

		if (!runShellcode(shellcode, 8 * 2))
		{
			*returnLength = 0;
			return 0;
		}

		*returnLength = *(LONG*)(buffer + 8);
		return *(LONG*)buffer;
	}
#endif // REMOTE_NtQuerySystemInformation

#if REMOTE_NtQueryObject
private:
	LONG ntQueryObject;
public:
	int NtQueryObject(LONG handle, int objectInformationClass, BYTE** objectInformationPtr, UINT objectInformationLength, UINT* returnLength)
	{
		shellcodeBuilder->Reset();
		LateValue<LONG> sendBuffer, result;
		LateValue<LONG>* parameters = macro->LateCall<false, 5>(shellcodeBuilder, ntQueryObject);
		shellcodeBuilder->MovRegisterALatePointer(&result);
		int sendSize = 16 + (int)objectInformationLength;
		Shellcode shellcode = macro->SafeComplete(shellcodeBuilder, rtlFillMemory, &sendBuffer, sendSize);

		LONG bufferAddress = Shellcode::Align(shellcode.GetEndAddress(), 4);
		sendBuffer.Insert(bufferAddress);
		result.Insert(bufferAddress);
		parameters[0].Insert(handle);
		parameters[1].Insert(objectInformationClass);
		parameters[2].Insert(bufferAddress + 16);
		parameters[3].Insert(objectInformationLength);
		parameters[4].Insert(bufferAddress + 8);

		delete[] parameters;

		if (!runShellcode(shellcode, sendSize))
		{
			returnLength = 0;
			return 0;
		}

		UINT returnLen = *(UINT*)(buffer + 8);
		*returnLength = returnLen;
		*objectInformationPtr = buffer + 16;
		return *(int*)buffer;
	}
	int NtQueryObject(LONG handle, int objectInformationClass, BYTE* objectInformation, UINT objectInformationLength, UINT* returnLength)
	{
		BYTE* objectInformationPtr;
		int ntstatus = NtQueryObject(handle, objectInformationClass, &objectInformationPtr, objectInformationLength, returnLength);
		memcpy(objectInformation, objectInformationPtr, *returnLength);
		return ntstatus;
	}
#endif // REMOTE_NtQueryObject

#if REMOTE_NtReadVirtualMemory
private:
	LONG ntReadVirtualMemory;
	Shellcode rVirtMem;
	LateValue<int> rvmNextRecvSize;////////////////////////////////////////////////////////////////
	LateValue<LONG> rvmBufSize, rvmProc, rvmAddr, rvmSize;
	inline void initNtReadVirtualMemory()
	{
		ntReadVirtualMemory = GETPROCADDRESS(ntdll, "NtReadVirtualMemory");

		const int rvmBuflen = 512;
		POINTER rvmBuffer = new BYTE[rvmBuflen];

		Shellcode64 tmpBuilder = Shellcode64(rvmBuffer, rvmBuflen, shellcodeBuilder->RemoteAddress);
		LateValue<LONG> rvmBufAddr, result;
		LateValue<LONG>* parameters = macro->LateCall<false, 5>(&tmpBuilder, ntReadVirtualMemory);
		shellcodeBuilder->MovRegisterALatePointer(&result);
		rVirtMem = macro->SafeComplete(&tmpBuilder, rtlFillMemory, &rvmBufAddr, &rvmBufSize);
		LONG bufferAddress = rVirtMem.GetEndAddress();
		rvmProc = parameters[0];
		rvmAddr = parameters[1];
		parameters[2].Insert(bufferAddress + 8);
		rvmSize = parameters[3];
		parameters[4].Insert(NULL);

		delete[] parameters;
		result.Insert(bufferAddress);
		rvmBufAddr.Insert(bufferAddress);

	}
	inline void freeNtReadVirtualMemory()
	{
		delete[] rVirtMem.Buffer;
	}
public:
	inline int NtReadVirtualMemory(LONG processHandle, LONG baseAddress, BYTE** readBufferPtr, LONG size)
	{
		rvmProc.Insert(processHandle);
		rvmAddr.Insert(baseAddress);
		rvmSize.Insert(size);

		int sendSize = 8 + size;
		rvmBufSize.Insert(sendSize);
		int recvLen = runShellcode(rVirtMem);
		if (recvLen != sendSize) return false;

		*readBufferPtr = buffer + 8;
		return *(int*)buffer;
	}
	inline int NtReadVirtualMemory(LONG processHandle, LONG baseAddress, BYTE** readBufferPtr, LONG size, LONG* numberOfBytesRead)
	{
		rvmProc.Insert(processHandle);
		rvmAddr.Insert(baseAddress);
		rvmSize.Insert(size);

		int sendSize = 8 + size;
		rvmBufSize.Insert(sendSize);
		int recvLen = runShellcode(rVirtMem);
		if (recvLen != sendSize)
		{
			if (numberOfBytesRead != NULL) *numberOfBytesRead = 0;
			return -1;
		}
		int ntstaus = *(int*)buffer;
		if (ntstaus < 0)
		{
			if (numberOfBytesRead != NULL) *numberOfBytesRead = 0;
		}
		else
		{
			*readBufferPtr = buffer + 8;
			if (numberOfBytesRead != NULL) *numberOfBytesRead = size; //I guess?
		}
		return ntstaus;
	}
	inline int NtReadVirtualMemory(LONG processHandle, LONG baseAddress, BYTE* readBuffer, LONG size, LONG* numberOfBytesRead)
	{
		BYTE* readBufferPtr;
		int ntstatus = NtReadVirtualMemory(processHandle, baseAddress, &readBufferPtr, size);
		if (ntstatus >= 0)
			memcpy(readBuffer, readBufferPtr, size);
		return ntstatus;
	}
	inline int NtReadVirtualMemory(LONG processHandle, LONG baseAddress, BYTE* readBuffer, LONG size)
	{
		BYTE* readBufferPtr;
		int ntstatus = NtReadVirtualMemory(processHandle, baseAddress, &readBufferPtr, size);
		if (ntstatus >= 0)
			memcpy(readBuffer, readBufferPtr, size);
		return ntstatus;
	}
#endif // REMOTE_NtReadVirtualMemory

#if REMOTE_NtWriteVirtualMemory
private:
	LONG ntWriteVirtualMemory;
	Shellcode wVirtMem;
	int wVirtMemSize;
	LateValue<int> wvmNextRecvSize;////////////////////////////////////////////////////////////////
	LateValue<LONG> wvmProc, wvmAddr, wvmSize;
	POINTER wVirtMemEnd;
	inline void initNtWriteVirtualMemory()
	{
		ntWriteVirtualMemory = GETPROCADDRESS(ntdll, "NtWriteVirtualMemory");

		const int wvmBuflen = 4096;
		POINTER wvmBuffer = new BYTE[wvmBuflen];

		Shellcode64 tmpBuilder = Shellcode64(wvmBuffer, wvmBuflen, shellcodeBuilder->RemoteAddress);
		LateValue<LONG> wvmBufAddr, result;
		LateValue<LONG>* parameters = macro->LateCall<false, 5>(&tmpBuilder, ntWriteVirtualMemory);
		shellcodeBuilder->MovRegisterALatePointer(&result);
		wVirtMem = macro->SafeComplete(&tmpBuilder, rtlFillMemory, &wvmBufAddr, /*8*/4);
		LONG bufferAddress = wVirtMem.GetEndAddress();
		wvmProc = parameters[0];
		wvmAddr = parameters[1];
		parameters[2].Insert(bufferAddress);
		wvmSize = parameters[3];
		parameters[4].Insert(NULL);

		delete[] parameters;
		result.Insert(bufferAddress);
		wvmBufAddr.Insert(bufferAddress);
		wVirtMemEnd = wVirtMem.GetEndPointer();
		wVirtMemSize = wVirtMem.Size;
	}
	inline void freeNtWriteVirtualMemory()
	{
		delete[] wVirtMem.Buffer;
	}
public:
	inline int NtWriteVirtualMemory(LONG processHandle, LONG baseAddress, BYTE* writeBuffer, LONG size, LONG* numberOfBytesWritten)
	{
		wvmProc.Insert(processHandle);
		wvmAddr.Insert(baseAddress);
		wvmSize.Insert(size);

		memcpy(wVirtMemEnd, writeBuffer, size);
		wVirtMem.Size = wVirtMemSize + size;
		int recvLen = runShellcode(wVirtMem);
		if (recvLen != /*8*/4)
		{
			if (numberOfBytesWritten != NULL) *numberOfBytesWritten = 0;
			return -1;
		}
		int ntstaus = *(int*)buffer;
		if (ntstaus < 0)
		{
			if (numberOfBytesWritten != NULL) *numberOfBytesWritten = 0;
		}
		else
		{
			if (numberOfBytesWritten != NULL) *numberOfBytesWritten = size; //I guess?
		}
		return ntstaus;
	}
	inline int NtWriteVirtualMemory(LONG processHandle, LONG baseAddress, BYTE* writeBuffer, LONG size)
	{
		wvmProc.Insert(processHandle);
		wvmAddr.Insert(baseAddress);
		wvmSize.Insert(size);

		memcpy(wVirtMemEnd, writeBuffer, size);
		int recvLen = runShellcode(wVirtMem);
		if (recvLen != /*8*/4) return -1;
		
		return *(int*)buffer;
	}
#endif // REMOTE_NtWriteVirtualMemory


#endif // REMOTE_NTDLL


#if REMOTE_RetrieveBytes
private:
	Shellcode retrieveBytes;
	LateValue<LONG> retBytesAddr;
	LateValue<int> retBytesSize, retBytesNextRecvSize;
	inline void initRetrieveBytes()
	{
		const int retrieveBufLen = 256;
		POINTER retrieveBuffer = new BYTE[retrieveBufLen];

		Shellcode64 tmpBuilder = Shellcode64(retrieveBuffer, retrieveBufLen, shellcodeBuilder->RemoteAddress);

		retrieveBytes = macro->SafeComplete(&tmpBuilder, rtlFillMemory, &retBytesAddr, &retBytesSize, &retBytesNextRecvSize);
	}
	void freeRetrieveBytes()
	{
		delete[] retrieveBytes.Buffer;
	}

public:
	bool RetrieveBytes(LONG address, int length)
	{
		retBytesNextRecvSize.Insert(macro->MsgSize);

		retBytesAddr.Insert(address);
		retBytesSize.Insert(length);
		return runShellcode(retrieveBytes, length);
	}
#endif // REMOTE_RetrieveBytes

	void DebugBreak()
	{
		shellcodeBuilder->Reset();
		shellcodeBuilder->DebugBreak();
		Shellcode shellcode = shellcodeBuilder->Complete();
		sendShellcode(shellcode);
	}
	RemoteCalls64() {}
	RemoteCalls64(int socket, Shellcode64* shellcodeBuilder, ShellcodeMacro64* macro)
	{
		this->buffer = /*new BYTE[shellcodeBuilder->MaxSize]*/shellcodeBuilder->StartPointer;
		this->bufferSize = shellcodeBuilder->MaxSize;
		this->socket = socket;
		this->shellcodeBuilder = shellcodeBuilder;
		this->macro = macro;

		rtlFillMemory = getProcAddressK32Unsafe(CSTRWITHSIZE("RtlFillMemory"));
		if (rtlFillMemory == NULL) { Errorcode = 1; return;	}

#ifdef REMOTE_GetModuleHandleA
		getModuleHandleA = GETPROCADDRESSK32("GetModuleHandleA");
		if (getModuleHandleA == NULL) { Errorcode = 2; return; }
#endif

#if REMOTE_GetLastError
		getLastError = GETPROCADDRESSK32("GetLastError");
		if (getLastError == NULL) { Errorcode = 3; return; }
#endif
#if REMOTE_ExitThread
		exitThread = GETPROCADDRESSK32("ExitThread");
		if (exitThread == NULL) { Errorcode = 4; return; }
#endif
#if REMOTE_Beep
		beep = GETPROCADDRESSK32("Beep");
#endif
#if REMOTE_GetCurrentProcessId
		getCurrentProcessId = GETPROCADDRESSK32("GetCurrentProcessId");
		if (getCurrentProcessId == NULL) { Errorcode = 6; return; }
#endif
#if REMOTE_GetProcessId
		getProcessId = GETPROCADDRESSK32("GetProcessId");
		if (getProcessId == NULL) { Errorcode = 7; return; }
#endif
#if REMOTE_GetModuleBaseNameA
		getModuleBaseNameA = GETPROCADDRESSK32("K32GetModuleBaseNameA");
		if (getModuleBaseNameA == NULL) { Errorcode = 8; return; }
#endif
#if REMOTE_VirtualQueryEx
		virtualQueryEx = GETPROCADDRESSK32("VirtualQueryEx");
		if (virtualQueryEx == NULL) { Errorcode = 9; return; }
#endif
#if REMOTE_CreateToolhelp32Snapshot
		createToolhelp32Snapshot = GETPROCADDRESSK32("CreateToolhelp32Snapshot");
#endif
#if REMOTE_Module32First
		module32First = GETPROCADDRESSK32("Module32First");
#endif
#if REMOTE_Module32Next
		module32Next = GETPROCADDRESSK32("Module32Next");
#endif
#if REMOTE_CloseHandle
		closeHandle = GETPROCADDRESSK32("CloseHandle");
		if (closeHandle == NULL) { Errorcode = 10; return; }
#endif
#if REMOTE_EnumProcessModulesEx
		enumProcessModulesEx = GETPROCADDRESSK32("K32EnumProcessModulesEx");
		if (enumProcessModulesEx == NULL) { Errorcode = 11; return; }
#endif
#if REMOTE_EnumProcesses
		enumProcesses = GETPROCADDRESSK32("K32EnumProcesses");
		if (enumProcesses == NULL) { Errorcode = 12; return; }
#endif
#if REMOTE_GetModuleInformation
		getModuleInformation = GETPROCADDRESSK32("K32GetModuleInformation");
		if (getModuleInformation == NULL) { Errorcode = 13; return; }
#endif
#if REMOTE_OpenProcess
		openProcess = GETPROCADDRESSK32("OpenProcess");
		if (openProcess == NULL) { Errorcode = 14; return; }
#endif
#if REMOTE_LocalAlloc
		localAlloc = GETPROCADDRESSK32("LocalAlloc");
		if (localAlloc == NULL) { Errorcode = 15; return; }
#endif
#if REMOTE_LocalFree
		localFree = GETPROCADDRESSK32("LocalFree");
		if (localFree == NULL) { Errorcode = 16; return; }
#endif
#if REMOTE_ReadProcessMemory
		if(!initReadProcessMemory()) { Errorcode = 17; return; }
#endif
#if REMOTE_WriteProcessMemory
		if (!initWriteProcessMemory()) { Errorcode = 18; return; }
#endif


#if REMOTE_USER32
		user32 = GETMODULEHANDLEA("user32");
#if REMOTE_SetCursorPos
		setCursorPos = GETPROCADDRESS(user32, "SetCursorPos");
#endif
#if REMOTE_MessageBoxA
		messageBoxA = GETPROCADDRESS(user32, "MessageBoxA");
#endif
#if REMOTE_FindWindowA
		findWindowA = GETPROCADDRESS(user32, "FindWindowA");
#endif
#if REMOTE_GetWindowThreadProcessId
		getWindowThreadProcessId = GETPROCADDRESS(user32, "GetWindowThreadProcessId");
#endif
#endif // REMOTE_USER32


#if REMOTE_UCRTBASE
		ucrtbase = GETMODULEHANDLEA("ucrtbase");
#if REMOTE_malloc
		pmalloc = GETPROCADDRESS(ucrtbase, "malloc");
#endif
#if REMOTE_free
		pfree = GETPROCADDRESS(ucrtbase, "free");
#endif
#endif // REMOTE_UCRTBASE

#if REMOTE_NTDLL
		ntdll = GETMODULEHANDLEA("ntdll");
#if REMOTE_NtQuerySystemInformation
		ntQuerySystemInformation = GETPROCADDRESS(ntdll, "NtQuerySystemInformation");
#endif
#if REMOTE_NtQueryObject
		ntQueryObject = GETPROCADDRESS(ntdll, "NtQueryObject");
#endif
#if REMOTE_NtReadVirtualMemory
		initNtReadVirtualMemory();
#endif
#if REMOTE_NtWriteVirtualMemory
		initNtWriteVirtualMemory();
#endif
#endif // REMOTE_NTDLL

		initRetrieveBytes();
	}

	~RemoteCalls64()
	{
#if REMOTE_ReadProcessMemory
		freeReadProcessMemory();
#endif
#if REMOTE_WriteProcessMemory
		freeWriteProcessMemory();
#endif

#if REMOTE_NTDLL
#if REMOTE_NtReadVirtualMemory
		freeNtReadVirtualMemory();
#endif
#if REMOTE_NtWriteVirtualMemory
		freeNtWriteVirtualMemory();
#endif
#endif // REMOTE_NTDLL
		freeRetrieveBytes();
	}

#undef GETPROCADDRESSK32
};



#define JNIFUNC(func) JNIEXPORT JNICALL Java_com_REMOTUS_REMOTUS_##func


extern BYTE* Buffer;
const int BufferSize = 4096;
extern ShellcodeMacro64 Macro;
extern RemoteCalls64* RemoteCalls;
extern LONG TargetHandle;
extern UINT TargetId;