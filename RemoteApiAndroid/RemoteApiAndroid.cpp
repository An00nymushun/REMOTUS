#include "RemoteApiAndroid.h"
#include "Tools.h"

//#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "RemoteApiAndroid", __VA_ARGS__))
//#define LOGW(...) ((void)__android_log_print(ANDROID_LOG_WARN, "RemoteApiAndroid", __VA_ARGS__))
//
//extern "C" {
//	/* This trivial function returns the platform ABI for which this dynamic native library is compiled.*/
//	const char * RemoteApiAndroid::getPlatformABI()
//	{
//	#if defined(__arm__)
//	#if defined(__ARM_ARCH_7A__)
//	#if defined(__ARM_NEON__)
//		#define ABI "armeabi-v7a/NEON"
//	#else
//		#define ABI "armeabi-v7a"
//	#endif
//	#else
//		#define ABI "armeabi"
//	#endif
//	#elif defined(__i386__)
//		#define ABI "x86"
//	#else
//		#define ABI "unknown"
//	#endif
//		LOGI("This dynamic shared library is compiled with ABI: %s", ABI);
//		return "This native library is compiled with ABI: %s" ABI ".";
//	}
//
//	void RemoteApiAndroid()
//	{
//	}
//
//	RemoteApiAndroid::RemoteApiAndroid()
//	{
//	}
//
//	RemoteApiAndroid::~RemoteApiAndroid()
//	{
//	}
//}


int TcpSocket = 0;

BYTE* Buffer;
ShellcodeMacro64 Macro;
RemoteCalls64* RemoteCalls;
LONG TargetHandle;
UINT TargetId;



struct FullHandle64
{
	USHORT ObjectTypeIndex;
	LONG HandleValue;
	LONG ObjectPtr;
};

static inline bool checkHandle(POINTER handleInfo, UINT processId, List<FullHandle64>* handles)
{
	UINT handleProcId = *(UINT*)(handleInfo + 0x08);
	if (handleProcId != processId) return false;

	UINT grantedAccess = *(UINT*)(handleInfo + 0x18);
	if (grantedAccess != 0x1fffff && grantedAccess != 0x1478) return false;


	FullHandle64 handle;
	handle.ObjectTypeIndex = *(UINT*)(handleInfo + 0x1E);
	handle.HandleValue = *(UINT*)(handleInfo + 0x10);
	handle.ObjectPtr = *(UINT*)(handleInfo + 0x00);

	handles->Add(handle);

	return true;
}


#pragma pack(push, 1)
struct Color4f
{
	float R;
	float G;
	float B;
	float A;
};

struct GlowStruct
{
	int EntityAddress;
	Color4f Color;
	char unknown1[4];
	float unknown_float;
	float BloomAmount;
	float LocalPlayerIsZeropoint3;
	bool RenderWhenOccluded;
	bool RenderWhenUnoccluded;
	bool FullBloomRender;
	char unknown2[1];
	int FullBloomStencilTestValue;
	int unknown_int;
	int SplitScreenSlot;
	int NextFreeSlot;
};

struct EntityBase
{
	bool Dormant;
	BYTE _pad1[6];
	int Team;
	BYTE _pad2[8];
	int Health;
};

struct EntityListRecord
{
	int EntityPointer;
	BYTE _pad[12];
};
#pragma pack(pop)


EntityListRecord* EntityListBuffer;

struct PlayerCacheRecord
{
	int EntityPointer;
	int GlowPointer;
	BYTE NextRead;
};

PlayerCacheRecord* PlayerCache;

//const int DormantOffset = 0xE9;
//const int TeamOffset = 0xF0;
//const int HealthOffset = 0xFC;
//const int OriginOffset = 0x134;
const int EntityBaseOffset = 0xE9;


struct _LateOffsets
{
private:
	BYTE lateOffsetField;
private:
	template<int INDEX>
	inline bool getBit()
	{
		return (lateOffsetField & (1 << INDEX)) != 0;
	}

	template<int INDEX>
	inline void setBit()
	{
		lateOffsetField |= (1 << INDEX);
	}

	template<int INDEX>
	inline void clearBit()
	{
		lateOffsetField &= ~(1 << INDEX);;
	}

public:
	inline bool GetLocalPlayer() { return getBit<1>(); }
	inline void SetLocalPlayer() { setBit<1>(); }
	inline void ClearLocalPlayer() { clearBit<1>(); }
	//bool LocalPlayer : 1;
} LateOffsets;

int LocalPlayer;
int GlowBase;
int EntityList;
int GlowIndexOffset;

inline void LocalPlayerSigOffset(BYTE* buffer)
{
	LocalPlayer = (*(int*)buffer) + (*(BYTE*)(buffer + 15));
}
void LocalPlayerSigCallback(BYTE* buffer, LONG currentBlockAddress, int posInBlock, int bufferSize)
{
	if (posInBlock + 19 > bufferSize)
	{
		LocalPlayer = (int)currentBlockAddress + posInBlock + 3;
		//LateOffsets.LocalPlayer = true;
		LateOffsets.SetLocalPlayer();
	}
	else
	{
		LocalPlayerSigOffset(buffer + posInBlock + 3);
	}
}

void GlowBaseSigCallback(BYTE* buffer, LONG currentBlockAddress, int posInBlock, int bufferSize)
{
	GlowBase = *(int*)(buffer + posInBlock + 9);
}

void EntityListSigCallback(BYTE* buffer, LONG currentBlockAddress, int posInBlock, int bufferSize)
{
	EntityList = *(int*)(buffer + posInBlock + 1);
}

void GlowIndexSigCallback(BYTE* buffer, LONG currentBlockAddress, int posInBlock, int bufferSize)
{
	GlowIndexOffset = *(int*)(buffer + posInBlock + 8);
}

LONG ClientBaseAddress;
int ClientSize;
void ClientModuleCallback(LONG handle, LONG baseAddress, int size)
{
	ClientBaseAddress = baseAddress;
	ClientSize = size;
}


int destroy()
{
	close(TcpSocket);
	if (RemoteCalls != NULL) delete RemoteCalls;
	if (Buffer != NULL) delete[] Buffer;
	if (EntityListBuffer != NULL) delete EntityListBuffer;
	if (PlayerCache != NULL) delete PlayerCache;
	return SUCCESS;
}


extern "C" {
	jint JNIFUNC(Init)(JNIEnv* env, jobject t)
	{
		RemoteCalls = NULL;
		Buffer = NULL;
		EntityListBuffer = NULL;

		int tcpSocket = socket(PF_INET, /*SOCK_DGRAM*/SOCK_STREAM, 0);
		if (tcpSocket == -1) return SOCKET_FAIL;

		int errorcode;
		do {
			int result;
			
			int reuseaddr = 1;
			result = setsockopt(tcpSocket, SOL_SOCKET, SO_REUSEADDR, (void*)&reuseaddr, sizeof(int));
			if (result != 0) { errorcode = REUSEADDR_FAIL; break; }

			sockaddr_in serverAddress;

			serverAddress.sin_family = AF_INET;
			serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
			serverAddress.sin_port = htons((unsigned short)PORT);

			result = bind(tcpSocket, (sockaddr*)&serverAddress, sizeof(serverAddress));
			if (result != 0) { errorcode = BIND_FAIL; break; }


			Buffer = new BYTE[BUFSIZE];
			TcpSocket = tcpSocket;
			return SUCCESS;

		} while (false);

		close(tcpSocket);
		return errorcode;
	}

	jint JNIFUNC(Free)(JNIEnv* env, jobject t)
	{
		return destroy();
	}

	jint JNIFUNC(Exit)(JNIEnv* env, jobject t)
	{
		//close remote socket?
		RemoteCalls->ExitThread(0);
		return destroy();
	}

	jint JNIFUNC(Listen)(JNIEnv* env, jobject t)
	{
		listen(TcpSocket, 1);
		int clientSocket = accept(TcpSocket, 0, 0);
		POINTER buffer = Buffer;
		//sockaddr_in clientAddress = sockaddr_in();
		//int clientAddressLength = sizeof(clientAddress);
		//int numberOfBytesRecieved = recvfrom(udpSocket, buffer, BUFSIZE, 0, (sockaddr*)&clientAddress, &clientAddressLength);
		int numberOfBytesRecieved = recv(clientSocket, buffer, BufferSize, 0);
		if (numberOfBytesRecieved < 0) return RECV_FAIL;

		timeval timeout = { TIMEOUT, 0 };
		int result = setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, (void*)&timeout, sizeof(timeout));
		if (result != 0) return SNDTIMEO_FAIL;
		result = setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (void*)&timeout, sizeof(timeout));
		if (result != 0) return RCVTIMEO_FAIL;



		const int minLoginSize = sizeof(EV0REMOTE_LOGIN);


		while (numberOfBytesRecieved < minLoginSize)
		{
			int result = recv(clientSocket, buffer + numberOfBytesRecieved, BufferSize - numberOfBytesRecieved, 0);

			if (result == -1)
				return LOGIN_FAIL;

			numberOfBytesRecieved += result;
		}


		EV0REMOTE_LOGIN* loginMessage = (EV0REMOTE_LOGIN*)buffer;
		if (/*loginMessage->ProtocolVersion*/loginMessage->GetProtocolVersion() != EV0REMOTE_PROTOCOLVERSION)
			return PROTOCOL_FAIL;

		if (/*loginMessage->ProcessorType*/loginMessage->GetProcessorType() == Win64)
		{
			LONG getProcAddress = loginMessage->GetProcAddr;
			LONG kernel32 = loginMessage->Kernel32;
			LONG memoryAddress = loginMessage->Address;

			if (getProcAddress == 0 || kernel32 == 0 || memoryAddress == 0)
				return LOGIN_FAIL;

			//+ws2_32 module
			//+recv
			//+socket
			//+aligner
			//+shadow space

			//POINTER shellcodeBuffer = new BYTE[bufferlen];

			FakeObject* sendStr;
			Shellcode64* shellcodeBuilder = new Shellcode64(/*shellcodeBuffer*/buffer, BufferSize, memoryAddress);

			shellcodeBuilder
				->FakePopBytes(32 + 3 * 8)
				->PopRegisterC() //-ws2_32 module

				->FakePushBytes(4 * 8 + 32)

				->NewFakeObject((PTR)CSTRWITHSIZE("send"), &sendStr)
				->MovFakePointerRegisterD(sendStr)
				->CallFar(getProcAddress)

				->FakePopBytes(32 + 8)

				->PushRegisterA() //+send

				->FakePopBytes(8)
				->PopRegisterC() //socket
				->FakePushBytes(2 * 8)
				->MovRegisterSPtoD()

				//->MovInt64Register9(0)
				->ZeroRegister9()
				->MovInt64Register8(4 * 8)
				->FakePushBytes(32)
				->CallRegisterA()
				->FakePopBytes(32 + 8)

				->PopRegisterC() //socket
				->PopRegisterA() //recv

				//->MovInt64Register9(0)
				//->ZeroRegister9()
				//->MovInt64Register8(BufferSize)
				->MovInt32Register9(/*MSG_WAITALL*/8)
				->MovInt32Register8(/*BufferSize*/DEFAULTMSGSIZE)
				->MovInt64RegisterD(memoryAddress)
				->FakePushBytes(32 - 8)

				->PushInt64(memoryAddress)
				->JmpRegisterA();

			Shellcode shellcode = shellcodeBuilder->Complete();
			if (shellcode.Size == 0)
				return SHELLCODE_FAIL;

			//int socket = UdpSocket;
			//int sendLen = sendto(socket, shellcode.Buffer, shellcode.Size, 0, (sockaddr*)&clientAddress, clientAddressLength);
			int sendLen = send(clientSocket, shellcode.Buffer, /*shellcode.Size*/DEFAULTMSGSIZE, 0);
			if (sendLen != /*shellcode.Size*/DEFAULTMSGSIZE)
				return SEND_FAIL;

			//int recvLen = recvfrom(udpSocket, buffer, BufferSize, 0, (sockaddr*)&clientAddress, &clientAddressLength);
			int recvLen = recv(clientSocket, buffer, 8 * 4, MSG_WAITALL);
			//send, socket, recv, ws2_32
			if (recvLen == -1)
				return SHELLCODERECV_FAIL;

			LONG rsend = *(LONG*)buffer;
			LONG rsocket = *(LONG*)(buffer + 8);
			LONG rrecv = *(LONG*)(buffer + 16);

			if (rsend == 0 || rsocket == 0 || rrecv == 0)
				RESULT_FAIL;

			Macro = ShellcodeMacro64(kernel32, getProcAddress, rsend, rrecv, rsocket);

			RemoteCalls = new RemoteCalls64(clientSocket, shellcodeBuilder, &Macro);

			if (RemoteCalls->Errorcode != 0)
				return 100 + RemoteCalls->Errorcode;//////////////////////

			//for (int i = 0; i < 1000; i++)
			//{
			//    bool success = RemoteCalls->SetCursorPos(i, i);
			//}

			//bool success = RemoteCalls->SetCursorPos(100, 100);
			//if (!success)
			//	return CALL_FAIL;

			//RemoteCalls->MessageBoxA(0, null, null, 0);

			//success = RemoteCalls->Beep(750, 300);
			//if (!success)
			//	return CALL_FAIL;




			//if (targetHandle != NULL)
			//{
			//	int readLen = 2;
			//	POINTER readBuffer;
			//	bool success = RemoteCalls->ReadProcessMemory(targetHandle, 0x7ffeae2a0000, &readBuffer, readLen, NULL);
			//}


			//RemoteCalls->ExitThread(0);



		}
		else return PROCESSORTYPE_FAIL;


		return SUCCESS;
	}

#define return if(RemoteCalls->Errorcode != 0) return RemoteCalls->Errorcode; else return

	jint JNIFUNC(Attach)(JNIEnv* env, jobject t)
	{
		const char targetName[] = TARGETPROCESSNAME;

		//LONG windowHandle = RemoteCalls->FindWindowA(CSTRWITHSIZE("Valve001"), CSTRWITHSIZE("Counter-Strike: Global Offensive"));
		//if (windowHandle == NULL)
		//	return PROCESS_FAIL;


		UINT processId = RemoteCalls->GetCurrentProcessId();
		if (processId == 0)
			return CALL_FAIL;

		List<FullHandle64> stolenHandles = List<FullHandle64>(64);

		UINT buflen = 16 * 1024 * 1024;
		LONG buf = RemoteCalls->LocalAlloc(/*LMEM_FIXED*/0, buflen);
		if (buf == NULL)
			return CALL_FAIL;

		UINT needed;
		int ntstatus = RemoteCalls->NtQuerySystemInformation(0x40, buf, buflen, &needed);
		if (ntstatus < 0 || needed == 0)
		{
			RemoteCalls->LocalFree(buf);
			return CALL_FAIL;
		}


		BYTE* buffer = Buffer;
		const int handleInfoSize = /*0x18*/0x28;
		const int handleInfoPerBlock = /*0xAA*/0x66;
		const int handleBlockSize = handleInfoSize * handleInfoPerBlock;
		const int firstBlockSize = /*4*/16 + handleBlockSize;

		bool success = RemoteCalls->RetrieveBytes(buf, firstBlockSize);
		if (!success)
		{
			RemoteCalls->LocalFree(buf);
			return RECV_FAIL;
		}

		UINT handleCount = *(UINT*)buffer;

		UINT blockCount = handleCount / handleInfoPerBlock;
		UINT remainingHandles = handleCount % handleInfoPerBlock;
		POINTER handleInfoPtr = buffer + 16;

		if (blockCount == 0)
		{
			POINTER handleInfoPtrEnd = handleInfoPtr + remainingHandles * handleInfoSize;
			for (; handleInfoPtr < handleInfoPtrEnd; handleInfoPtr += handleInfoSize)
			{
				checkHandle(handleInfoPtr, processId, &stolenHandles);
			}
		}
		else
		{
			POINTER handleInfoPtrEnd = handleInfoPtr + handleBlockSize;
			for (; handleInfoPtr < handleInfoPtrEnd; handleInfoPtr += handleInfoSize)
			{
				checkHandle(handleInfoPtr, processId, &stolenHandles);
			}

			LONG firstBlock = buf + 16;
			LONG currentBlock = firstBlock + handleBlockSize;
			LONG blockEnd = firstBlock + handleBlockSize * blockCount;
			handleInfoPtrEnd = buffer + handleBlockSize;

			for (; currentBlock < blockEnd; currentBlock += handleBlockSize)
			{
				success = RemoteCalls->RetrieveBytes(currentBlock, handleBlockSize);
				if (!success)
				{
					RemoteCalls->LocalFree(buf);
					return RECV_FAIL;
				}

				handleInfoPtr = buffer;
				for (; handleInfoPtr < handleInfoPtrEnd; handleInfoPtr += handleInfoSize)
				{
					checkHandle(handleInfoPtr, processId, &stolenHandles);
				}
			}

			if (remainingHandles != 0)
			{
				int remainingSize = remainingHandles * handleInfoSize;
				success = RemoteCalls->RetrieveBytes(currentBlock, remainingSize);
				if (!success)
				{
					RemoteCalls->LocalFree(buf);
					return RECV_FAIL;
				}

				handleInfoPtr = buffer;
				handleInfoPtrEnd = handleInfoPtr + remainingSize;
				for (; handleInfoPtr < handleInfoPtrEnd; handleInfoPtr += handleInfoSize)
				{
					checkHandle(handleInfoPtr, processId, &stolenHandles);
				}
			}
		}

		RemoteCalls->LocalFree(buf);


		LONG targetHandle = NULL;

		const int objectTypeLength = 120;
		bool typefound = false;
		USHORT type = 0; //thread or process

		int stolenHandlesLength = stolenHandles.Length;
		for (int i = 0; i < stolenHandlesLength; i++)
		{
			FullHandle64 fullhandle = stolenHandles[i];

			if (typefound)
			{
				if (fullhandle.ObjectTypeIndex != type) continue;
			}
			else
			{
				UINT returnLen;
				POINTER objectTypeBuffer;
				ntstatus = RemoteCalls->NtQueryObject(fullhandle.HandleValue, /*ObjectTypeInformation*/2, &objectTypeBuffer, objectTypeLength, &returnLen);
				if (ntstatus < 0 || returnLen == 0)
				{
					continue;
					//TODO: check if fatal error
				}

				USHORT typeNameLen = *(USHORT*)objectTypeBuffer;
				if (typeNameLen == 7 * 2) //Process
				{
					typefound = true;
					type = fullhandle.ObjectTypeIndex;
				}
				else continue;
				//LONG typeNamePtr = BitConverter.ToInt64(objTypeBuf, 8) - 0xD80000;

				//byte[] typeNameBytes = RemoteCalls->RetrieveBytes(typeNamePtr, typeNameLen);
				//string typeName = Encoding.Unicode.GetString(typeNameBytes);
			}

			char* baseNameBuffer;
			const UINT maxNameLength = 32;
			UINT moduleNameLength = RemoteCalls->GetModuleBaseNameA(fullhandle.HandleValue, NULL, &baseNameBuffer, maxNameLength);
			if (moduleNameLength != STRSIZE(targetName)) continue;

			if (memcmp(baseNameBuffer, STRWITHSIZE(targetName)) == 0)
			{
				targetHandle = fullhandle.HandleValue;
				break;
			}
		}

		UINT targetId;

		if (targetHandle == NULL)
		{
			//UINT windowThreadId = RemoteCalls->GetWindowThreadProcessId(windowHandle, &targetId);
			//if(windowThreadId == 0)
			//	return ACCESS_FAIL;

			//targetHandle = RemoteCalls->OpenProcess(/*PROCESS_ALL_ACCESS*/0x1fffff, false, targetId);
			//if (targetHandle == NULL)
			//	return HANDLE_FAIL;

			UINT* processIdArrayPtr;
			UINT processIdArraySize;
			success = RemoteCalls->EnumProcesses(&processIdArrayPtr, 2048, &processIdArraySize);
			if (!success)
				return CALL_FAIL;

			UINT* processIdArray = (UINT*)malloc(processIdArraySize);			
			memcpy(processIdArray, processIdArrayPtr, processIdArraySize);

			UINT* currentProcessId = processIdArray;
			UINT* lastProcessId = (UINT*)((BYTE*)processIdArray + processIdArraySize) - 1;
			while (true)
			{
				UINT processId = *currentProcessId;
				if (processId != 0)
				{
					LONG processHandle = RemoteCalls->OpenProcess(/*PROCESS_ALL_ACCESS*/0x1fffff, false, processId);
					if (processHandle != NULL)
					{
						char* baseNameBuffer;
						const UINT maxNameLength = 32;
						UINT moduleNameLength = RemoteCalls->GetModuleBaseNameA(processHandle, NULL, &baseNameBuffer, maxNameLength);
						if (moduleNameLength == STRSIZE(targetName))
						{
							if (memcmp(baseNameBuffer, STRWITHSIZE(targetName)) == 0)
							{
								targetHandle = processHandle;
								break;
							}
						}

						RemoteCalls->CloseHandle(processHandle);
					}
				}

				if (currentProcessId == lastProcessId)
					break;

				currentProcessId++;
			}



			free(processIdArray);

			if(targetHandle == NULL)
				return PROCESS_FAIL;
		}
		else
		{
			targetId = RemoteCalls->GetProcessId(targetHandle);
			if (targetId == 0)
				return ACCESS_FAIL;
		}

		TargetHandle = targetHandle;
		TargetId = targetId;
		return SUCCESS;
	}


	jint JNIFUNC(Setup)(JNIEnv* env, jobject t)
	{
		for (int i = 0;; i++)
		{
			Module64 moduleArray[] = {
				{ STRWITHSIZE("client.dll"), &ClientModuleCallback }
			};

			if (ModuleScan64(ARRAYWITHCOUNT(moduleArray), /*LIST_MODULES_32BIT*/1))
				break;
			else
				sleep(1);

			if (i == 50) return MODULE_FAIL;
		}


		const char localPlayerSig[] = "\x8D\x34\x85\x00\x00\x00\x00\x89\x15\x00\x00\x00\x00\x8B\x41\x08\x8B\x48";
		const char localPlayerSigMask[] = "xxx????xx????xxxxx";

		const char glowBaseSig[] = "\xE8\x00\x00\x00\x00\x83\xC4\x04\xB8\x00\x00\x00\x00\xC3";
		const char glowBaseSigMask[] = "x????xxxx????x";

		const char entityListSig[] = "\xBB\x00\x00\x00\x00\x83\xFF\x01\x0F\x8C\x00\x00\x00\x00\x3B\xF8";
		const char entityListSigMask[] = "x????xxxxx????xx";

		const char glowIndexSig[] = "\xEB\x04\xC6\x45\xFF\x01\x8B\xB3\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8A\x5D\xFF\x8D\x14\xF5";
		const char glowIndexSigMask[] = "xxxxxxxx????x????xxxxxx";

		Pattern64 clientPatterns[] = {
			{ (BYTE*)localPlayerSig, (char*)STRWITHSIZE(localPlayerSigMask), &LocalPlayerSigCallback },
			{ (BYTE*)glowBaseSig, (char*)STRWITHSIZE(glowBaseSigMask), &GlowBaseSigCallback },
			{ (BYTE*)entityListSig, (char*)STRWITHSIZE(entityListSigMask), &EntityListSigCallback },
			{ (BYTE*)glowIndexSig, (char*)STRWITHSIZE(glowIndexSigMask), &GlowIndexSigCallback }
		};

		if (!PatternScan64(ClientBaseAddress, ClientSize, ARRAYWITHCOUNT(clientPatterns)))
			return PATTERN_FAIL;

		_LateOffsets lateOffsets = LateOffsets;

		if (lateOffsets.GetLocalPlayer())
		{
			BYTE* buffer;
			if (!ReadBytes(LocalPlayer, &buffer, 16))
				return ACCESS_FAIL;
			LocalPlayerSigOffset(buffer);
		}

		EntityListBuffer = new EntityListRecord[64];
		PlayerCache = new PlayerCacheRecord[64];

		return SUCCESS;
	}

	int GlowArray = NULL;
	jint JNIFUNC(Run)(JNIEnv* env, jobject t)
	{
		int localPlayer/* = Read<int>(LocalPlayer)*/;
		bool success = Read<int>(LocalPlayer, &localPlayer);
		if (!success) return ACCESS_FAIL;
		if (localPlayer == NULL) return 0;
		int glowArray = Read<int>(GlowBase);
		if (glowArray == NULL) return 0;

		bool rereadGlow;
		if (glowArray != GlowArray)
		{
			GlowArray = glowArray;
			rereadGlow = true;
		}
		else
		{
			rereadGlow = false;
		}



		EntityBase localPlayerBase = Read<EntityBase>(localPlayer + EntityBaseOffset);
		if (localPlayerBase.Team == 0) return 0;


		const Color4f colorEnemy = { 
			1.00f,
			0.41f,
			0.71f,
			0.60f
		};
		const Color4f colorEnemyLow = {
			1.00f,
			0.00f,
			0.30f,
			0.60f
		};

		EntityListRecord* entityList = EntityListBuffer;

		ReadBytes(EntityList, (BYTE*)entityList, 64 * sizeof(EntityListRecord));

		for (int i = 0; i < 64; i++)
		{
			int entityPointer = entityList[i].EntityPointer;
			if (entityPointer == NULL || entityPointer == localPlayer) continue;

			int entityGlowPointer;

			PlayerCacheRecord* cacheRecord = &PlayerCache[i];

			if (cacheRecord->EntityPointer != entityPointer || rereadGlow)
			{
				int entityGlowIndex = Read<int>(entityPointer + GlowIndexOffset);

				entityGlowPointer = glowArray + (entityGlowIndex * sizeof(GlowStruct));

				cacheRecord->EntityPointer = entityPointer;
				cacheRecord->GlowPointer = entityGlowPointer;
				cacheRecord->NextRead = 0;
			}
			else
			{
				BYTE nextRead = cacheRecord->NextRead;
				if (nextRead != 0)
				{
					cacheRecord->NextRead = nextRead - 1;
					continue;
				}

				entityGlowPointer = cacheRecord->GlowPointer;
			}


			EntityBase entityBase = Read<EntityBase>(entityPointer + EntityBaseOffset);
			if (entityBase.Health == 0 || entityBase.Team == 0 || entityBase.Team == localPlayerBase.Team)
			{
				cacheRecord->NextRead = 10;
				continue;
			}

			if (entityBase.Dormant) continue;

			//int entitySpotted = entityPointer + 0x939;
			//Write<bool>(entitySpotted, true);


			Color4f color;
			if (entityBase.Health < 25)
				color = colorEnemyLow;
			else
				color = colorEnemy;

			success = Write<Color4f>(entityGlowPointer + offsetof(GlowStruct, Color), color);
			if (!success)
				return ACCESS_FAIL;
			success = Write<bool>(entityGlowPointer + offsetof(GlowStruct, RenderWhenOccluded), true);
			if (!success)
				return ACCESS_FAIL;
		}


		return SUCCESS;
	}

#undef return
}