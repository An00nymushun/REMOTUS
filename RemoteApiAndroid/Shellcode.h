#pragma once
#include "List.h"

template <typename T>
class LateValue
{
protected:
	POINTER pointer;

	void insert(T value)
	{
#if __ARM_32BIT_STATE
		if (sizeof(T) > 4)
			memcpy(pointer, &value, sizeof(T));
		else
			*(T*)pointer = value;
#else
		*(T*)pointer = value;
#endif
	}

	typedef void (LateValue<T>::*InsertFunc)(T);

	InsertFunc insertptr;

public:
	
	LateValue() { }

	LateValue(POINTER pointer)
	{
		this->pointer = pointer;
		insertptr = &LateValue<T>::insert;
	}

	inline void Insert(T value)
	{
		(this->*insertptr)(value);
	}
};
class FakeObject
{
public:
	struct FakePointer
	{
		POINTER Pointer;
		BYTE Type;

		FakePointer(POINTER pointer, BYTE type)
		{
			Pointer = pointer;
			Type = type;
		}
		FakePointer(POINTER pointer)
		{
			Pointer = pointer;
			Type = 0;
		}
	};

	POINTER ValuePtr;
	int Size;
	List<FakePointer>* TargetPointers;
private:
	//BYTE type;

public:
	FakeObject(POINTER valuePtr, int size)
	{
		ValuePtr = valuePtr;
		Size = size;
		TargetPointers = new List<FakePointer>();
	}
	~FakeObject()
	{
		delete TargetPointers;
	}

	inline void AddTargetPointer(FakePointer targetPointer)
	{
		TargetPointers->Add(targetPointer);
	}
	inline void AddTargetPointer(POINTER pointer)
	{
		TargetPointers->Add(FakePointer(pointer));
	}
	inline void AddTargetPointer(POINTER pointer, BYTE type)
	{
		TargetPointers->Add(FakePointer(pointer, type));
	}
};

struct Shellcode
{
	BYTE* Buffer;
	LONG RemoteAddress;
	LONG EntryPoint;
	int Size;
	int BufferSize;

	Shellcode() { }
	Shellcode(BYTE* buffer, LONG remoteAddress, LONG entryPoint, int size, int bufferSize)
	{
		Buffer = buffer;
		RemoteAddress = remoteAddress;
		EntryPoint = entryPoint;
		Size = size;
		BufferSize = bufferSize;
	}


	inline LONG GetEndAddress()
	{
		return RemoteAddress + Size;
	}
	inline POINTER GetEndPointer()
	{
		return Buffer + Size;
	}

	//static byte[] AsciiCString(string s)
	//{
	//	byte[] bytes = new byte[s.Length + 1];
	//	Encoding.ASCII.GetBytes(s, 0, s.Length, bytes, 0);
	//	return bytes;
	//}

	static inline int Align(int value, int to)
	{
		int mask = to - 1;
		return (value + mask) & ~mask;
	}
	static inline LONG Align(LONG value, int to)
	{
		int mask = to - 1;
		return (value + mask) & ~mask;
	}
};



class Shellcode86
{
	POINTER currentPointer;
	int size;
	int entryPoint;
	List<FakeObject*>* fakeMemory;

public:
	int RemoteAddress;
	POINTER StartPointer;
	int MaxSize;

	Shellcode86(POINTER startPointer, int maxSize, int remoteAddress)
	{
		this->StartPointer = startPointer;
		this->currentPointer = startPointer;
		this->RemoteAddress = remoteAddress;
		this->entryPoint = remoteAddress;
		this->size = 0;
		this->MaxSize = maxSize;
		this->fakeMemory = new List<FakeObject*>();
	}
	~Shellcode86()
	{
		delete fakeMemory;
	}
	//Shellcode86(POINTER startPointer, int maxSize, POINTER remoteAddress)
	//{
	//	Shellcode86(startPointer, maxSize, (int)remoteAddress);
	//}

	Shellcode86* Reset()
	{
		this->currentPointer = StartPointer;
		this->entryPoint = RemoteAddress;
		this->size = 0;
		fakeMemory->Clear();

		return this;
	}

private:
	template<typename T>
	typename enable_if<!is_array<T>::value, bool>::type write(T value)
	{
		int valueSize;
		int newSize;

		valueSize = sizeof(value);

		newSize = size + valueSize;
		if (newSize > MaxSize) return false;
		
		*(T*)currentPointer = value;
		
		currentPointer += valueSize;
		size = newSize;

		return true;
	}
	template<typename T>
	typename enable_if<is_array<T>::value, bool>::type write(T value)
	{
		int valueSize;
		int newSize;

		valueSize = sizeof(value);

		newSize = size + valueSize;
		if (newSize > MaxSize) return false;
		
		memcpy(currentPointer, &value, valueSize);
		
		currentPointer += valueSize;
		size = newSize;

		return true;
	}
	bool write(POINTER valuePtr, int valueSize)
	{
		int newSize;

		newSize = size + valueSize;
		if (newSize > MaxSize) return false;

		memcpy(currentPointer, valuePtr, valueSize);

		currentPointer += valueSize;
		size = newSize;

		return true;
	}
	bool write(FakeObject* fakeObject)
	{
		return write(fakeObject->ValuePtr, fakeObject->Size);
	}
	template<typename T>
	inline void insert(POINTER pointer, T value)
	{
		*(T*)pointer = value;
	}

public:
	//no inherit
	int GetCurrentEntryPoint() { return entryPoint; }
	//no inherit
	int GetCurrentCodeSize() { return size; }
	//no inherit
	int GetCurrentCodePoint() { return RemoteAddress + size; }
	//no inherit
	Shellcode86* SetEntryPoint()
	{
		entryPoint = RemoteAddress + size;
		return this;
	}


	Shellcode86* DebugBreak()
	{
		write<BYTE>(0xCC);
		return this;
	}

	Shellcode86* PushRegisterA()
	{
		write<BYTE>(0x50);
		return this;
	}
	Shellcode86* PopRegisterA()
	{
		write<BYTE>(0x58);
		return this;
	}
	Shellcode86* PushRegisterC()
	{
		write<BYTE>(0x51);
		return this;
	}
	Shellcode86* PopRegisterC()
	{
		write<BYTE>(0x59);
		return this;
	}
	Shellcode86* PushRegisterD()
	{
		write<BYTE>(0x52);
		return this;
	}
	Shellcode86* PopRegisterD()
	{
		write<BYTE>(0x5A);
		return this;
	}
	Shellcode86* PushRegisterB()
	{
		write<BYTE>(0x53);
		return this;
	}
	Shellcode86* PopRegisterB()
	{
		write<BYTE>(0x5B);
		return this;
	}

	Shellcode86* CallRegisterA()
	{
		write<USHORT>(0xD0FF); //FF D0
		return this;
	}
	Shellcode86* JmpRegisterA()
	{
		write<USHORT>(0xE0FF); //FF E0
		return this;
	}

	Shellcode86* MovIntRegisterA(int value)
	{
		write<BYTE>(0xB8);
		write<int>(value);
		return this;
	}

	Shellcode86* PushByte(BYTE value)
	{
		write<BYTE>(0x6A);
		write<BYTE>(value);
		return this;
	}

	Shellcode86* PushInt(int value)
	{
		write<BYTE>(0x68);
		write<int>(value);
		return this;
	}
	//Shellcode86* PushInt(POINTER value) { return PushInt((int)value); }

	//no inherit
	Shellcode86* CallFar(int address)
	{
		LONG delta = (LONG)address - (RemoteAddress + size + sizeof(int));
		if ((ULONG)delta > UINT_MAX)
		{
			MovIntRegisterA(address);
			CallRegisterA();
		}
		else
		{
			write<BYTE>(0xE8);
			write<int>((int)delta);
		}
		return this;
	}
	//Shellcode86* CallFar(POINTER address) { return CallFar((int)address); }

	//no inherit
	Shellcode86* JumpFar(int address)
	{
		LONG delta = (LONG)address - (RemoteAddress + size + sizeof(int));
		if ((ULONG)delta > UINT_MAX)
		{
			MovIntRegisterA(address);
			JmpRegisterA();
		}
		else
		{
			write<BYTE>(0xE9);
			write<int>((int)delta);
		}
		return this;
	}
	//Shellcode86* JumpFar(POINTER address) { return JumpFar((int)address); }


	FakeObject* NewFakeObject(POINTER valuePtr, int size)
	{
		FakeObject* fakeObject = new FakeObject(valuePtr, size);
		fakeMemory->Add(fakeObject);
		return fakeObject;
	}
	template<typename T>
	FakeObject* NewFakeObject(T* valuePtr)
	{
		FakeObject* fakeObject = new FakeObject(valuePtr, sizeof(T));
		fakeMemory->Add(fakeObject);
		return fakeObject;
	}
	Shellcode86* NewFakeObject(POINTER valuePtr, int size, FakeObject** fakeObject)
	{
		*fakeObject = NewFakeObject(valuePtr, size);
		return this;
	}
	template<typename T>
	Shellcode86* NewFakeObject(T* value, FakeObject** fakeObject)
	{
		*fakeObject = NewFakeObject<T>(value);
		return this;
	}

	Shellcode86* PushFakePointer(FakeObject* fakeObject)
	{
		PushInt(0);
		fakeObject->AddTargetPointer(currentPointer - sizeof(int));
		return this;
	}


	//no inherit
	Shellcode Complete()
	{
		int fakeMemoryLength = fakeMemory->Length;
		for (int i = 0; i < fakeMemoryLength; i++)
		{
			FakeObject* fakeObject = (*fakeMemory)[i];
			int objectRemoteAddress = RemoteAddress + size;
			if (!write(fakeObject)) return Shellcode(0, 0, 0, 0, 0);
			int targetPointersLength = fakeObject->TargetPointers->Length;
			for (int j = 0; j < targetPointersLength; j++)
			{
				FakeObject::FakePointer targetPointer = (*fakeObject->TargetPointers)[j];
				insert<int>(targetPointer.Pointer, objectRemoteAddress);
			}
		}

		return Shellcode(StartPointer, RemoteAddress, entryPoint, size, MaxSize);
	}
};

class Shellcode64
{
	POINTER currentPointer;
	int size;
	LONG entryPoint;
	List<FakeObject*>* fakeMemory;

public:
	LONG RemoteAddress;
	POINTER StartPointer;
	int MaxSize;

	Shellcode64(POINTER startPointer, int maxSize, LONG remoteAddress)
	{
		this->StartPointer = startPointer;
		this->currentPointer = startPointer;
		this->RemoteAddress = remoteAddress;
		this->entryPoint = remoteAddress;
		this->size = 0;
		this->MaxSize = maxSize;
		this->fakeMemory = new List<FakeObject*>();
	}
	~Shellcode64()
	{
		delete this->fakeMemory;
	}
	//Shellcode64(POINTER startPointer, int maxSize, POINTER remoteAddress)
	//{
	//	Shellcode64(startPointer, maxSize, (LONG)remoteAddress);
	//}

	Shellcode64* Reset()
	{
		this->currentPointer = StartPointer;
		this->entryPoint = RemoteAddress;
		this->size = 0;
		fakeMemory->Clear();

		return this;
	}

private:
	template<typename T>
	typename enable_if<!is_array<T>::value, bool>::type write(T value)
	{
		int valueSize;
		int newSize;

		valueSize = sizeof(value);

		newSize = size + valueSize;
		if (newSize > MaxSize) return false;

#if __ARM_32BIT_STATE
		if (sizeof(T) > 4)
			memcpy(currentPointer, &value, sizeof(T));
		else
			*(T*)currentPointer = value;
#else
		*(T*)currentPointer = value;
#endif

		currentPointer += valueSize;
		size = newSize;

		return true;
	}
	template<typename T>
	typename enable_if<is_array<T>::value, bool>::type write(T value)
	{
		int valueSize;
		int newSize;

		valueSize = sizeof(T);

		newSize = size + valueSize;
		if (newSize > MaxSize) return false;

		memcpy(currentPointer, value, valueSize);

		currentPointer += valueSize;
		size = newSize;

		return true;
	}
	bool write(POINTER valuePtr, int valueSize)
	{
		int newSize;

		newSize = size + valueSize;
		if (newSize > MaxSize) return false;

		memcpy(currentPointer, valuePtr, valueSize);

		currentPointer += valueSize;
		size = newSize;

		return true;
	}
	bool write(FakeObject* fakeObject)
	{
		return write(fakeObject->ValuePtr, fakeObject->Size);
	}
	template<typename T>
	inline void insert(POINTER pointer, T value)
	{
#if __ARM_32BIT_STATE
		if (sizeof(T) > 4)
			memcpy(pointer, &value, sizeof(T));
		else
			*(T*)pointer = value;
#else
		*(T*)pointer = value;
#endif
	}

public:
	LONG GetCurrentEntryPoint() { return entryPoint; }
	int GetCurrentCodeSize() { return size; }
	LONG GetCurrentCodePoint() { return RemoteAddress + size; }
	Shellcode64* SetEntryPoint()
	{
		entryPoint = RemoteAddress + size;
		return this;
	}

	Shellcode64* DebugBreak()
	{
		write<BYTE>(0xCC);
		return this;
	}

	Shellcode64* PushRegisterA()
	{
		write<BYTE>(0x50);
		return this;
	}
	Shellcode64* PopRegisterA()
	{
		write<BYTE>(0x58);
		return this;
	}
	Shellcode64* PushRegisterC()
	{
		write<BYTE>(0x51);
		return this;
	}
	Shellcode64* PopRegisterC()
	{
		write<BYTE>(0x59);
		return this;
	}
	Shellcode64* PushRegisterD()
	{
		write<BYTE>(0x52);
		return this;
	}
	Shellcode64* PopRegisterD()
	{
		write<BYTE>(0x5A);
		return this;
	}
	Shellcode64* PushRegisterB()
	{
		write<BYTE>(0x53);
		return this;
	}
	Shellcode64* PopRegisterB()
	{
		write<BYTE>(0x5B);
		return this;
	}

	Shellcode64* CallRegisterA()
	{
		write<USHORT>(0xD0FF); //FF D0
		return this;
	}
	Shellcode64* JmpRegisterA()
	{
		write<USHORT>(0xE0FF); //FF E0
		return this;
	}

	Shellcode64* MovIntRegisterA(int value)
	{
		write<BYTE>(0xB8);
		write<int>(value);
		return this;
	}

	Shellcode64* PushByte(BYTE value)
	{
		write<BYTE>(0x6A);
		write<BYTE>(value);
		return this;
	}

	Shellcode64* PushInt(int value)
	{
		write<BYTE>(0x68);
		write<int>(value);
		return this;
	}
	//Shellcode64* PushInt(POINTER value) { return PushInt((int)value); }


	Shellcode64* ZeroRegisterA()
	{
		BYTE bytes[3] = { 0x48, 0x31, 0xC0 };
		write<BYTE[3]>(bytes);
		return this;
	}
	Shellcode64* ZeroRegisterC()
	{
		BYTE bytes[3] = { 0x48, 0x31, 0xC9 };
		write<BYTE[3]>(bytes);
		return this;
	}
	Shellcode64* ZeroRegisterD()
	{
		BYTE bytes[3] = { 0x48, 0x31, 0xD2 };
		write<BYTE[3]>(bytes);
		return this;
	}
	Shellcode64* ZeroRegister8()
	{
		BYTE bytes[3] = { 0x4D, 0x31, 0xC0 };
		write<BYTE[3]>(bytes);
		return this;
	}
	Shellcode64* ZeroRegister9()
	{
		BYTE bytes[3] = { 0x4D, 0x31, 0xC9 };
		write<BYTE[3]>(bytes);
		return this;
	}


	//public Shellcode64* MovIntRegister8(int value)
	//{
	//    write<byte>(0x49);
	//    write<USHORT>(0xC0C7); //49 C7 C0
	//    write<int>(value);
	//}
	Shellcode64* MovInt64RegisterA(LONG value)
	{
		write<USHORT>(0xB848); //48 B8
		write<LONG>(value);
		return this;
	}
	//Shellcode64 MovInt64RegisterA(POINTER value) { return MovInt64RegisterA((LONG)value); }

	Shellcode64* MovInt64RegisterC(LONG value)
	{
		write<USHORT>(0xB948); //48 B9
		write<LONG>(value);
		return this;
	}
	//Shellcode64 MovInt64RegisterC(POINTER value) { return MovInt64RegisterC((LONG)value); }
	LateValue<LONG> MovLateInt64RegisterC()
	{
		MovInt64RegisterC(0);
		return newLateInt64();
	}
	Shellcode64* MovLateInt64RegisterC(LateValue<LONG>* lateValue)
	{
		*lateValue = MovLateInt64RegisterC();
		return this;
	}
	Shellcode64* MovInt32RegisterC(int value)
	{
		BYTE bytes[3] = { 0x48, 0xC7, 0xC1 };
		write<BYTE[3]>(bytes);
		write<int>(value);
		return this;
	}

	Shellcode64* MovInt64RegisterD(LONG value)
	{
		write<USHORT>(0xBA48); //48 BA
		write<LONG>(value);
		return this;
	}
	//Shellcode64 MovInt64RegisterD(POINTER value) { return MovInt64RegisterD((LONG)value); }
	LateValue<LONG> MovLateInt64RegisterD()
	{
		MovInt64RegisterD(0);
		return newLateInt64();
	}
	Shellcode64* MovLateInt64RegisterD(LateValue<LONG>* lateValue)
	{
		*lateValue = MovLateInt64RegisterD();
		return this;
	}
	Shellcode64* MovInt32RegisterD(int value)
	{
		BYTE bytes[3] = { 0x48, 0xC7, 0xC2 };
		write<BYTE[3]>(bytes);
		write<int>(value);
		return this;
	}

	Shellcode64* MovInt64RegisterB(LONG value)
	{
		write<USHORT>(0xBB48); //48 BB
		write<LONG>(value);
		return this;
	}
	Shellcode64* MovInt64RegisterB(POINTER value) { return MovInt64RegisterB((LONG)value); }

	Shellcode64* MovInt64Register8(LONG value)
	{
		write<USHORT>(0xB849); //49 B8
		write<LONG>(value);
		return this;
	}
	LateValue<LONG> MovLateInt64Register8()
	{
		MovInt64Register8(0);
		return newLateInt64();
	}
	Shellcode64* MovLateInt64Register8(LateValue<LONG>* lateValue)
	{
		*lateValue = MovLateInt64Register8();
		return this;
	}
	Shellcode64* MovInt32Register8(int value)
	{
		BYTE bytes[3] = { 0x49, 0xC7, 0xC0 };
		write<BYTE[3]>(bytes);
		write<int>(value);
		return this;
	}
	LateValue<int> MovLateInt32Register8()
	{
		MovInt32Register8(0);
		return newLateInt32();
	}
	Shellcode64* MovLateInt32Register8(LateValue<int>* lateValue)
	{
		*lateValue = MovLateInt32Register8();
		return this;
	}

	Shellcode64* MovInt64Register9(LONG value)
	{
		write<USHORT>(0xB949); //49 B9
		write<LONG>(value);
		return this;
	}
	LateValue<LONG> MovLateInt64Register9()
	{
		MovInt64Register9(0);
		return newLateInt64();
	}
	Shellcode64* MovLateInt64Register9(LateValue<LONG>* lateValue)
	{
		*lateValue = MovLateInt64Register9();
		return this;
	}
	Shellcode64* MovInt32Register9(int value)
	{
		BYTE bytes[3] = { 0x49, 0xC7, 0xC1 };
		write<BYTE[3]>(bytes);
		write<int>(value);
		return this;
	}

	Shellcode64* MovRegisterAtoC()
	{
		//write<BYTE>(0x48);
		//write<USHORT>(0xC189); //48 89 C1
		BYTE bytes[3] = { 0x48, 0x89, 0xC1 };
		write<BYTE[3]>(bytes);
		return this;
	}
	Shellcode64* MovRegisterAtoD()
	{
		//write<BYTE>(0x48);
		//write<USHORT>(0xC289); //48 89 C2
		BYTE bytes[3] = { 0x48, 0x89, 0xC2 };
		write<BYTE[3]>(bytes);
		return this;
	}

	Shellcode64* MovRegisterSPtoD()
	{
		//write<BYTE>(0x48);
		//write<USHORT>(0xE289); //48 89 E2
		BYTE bytes[3] = { 0x48, 0x89, 0xE2 };
		write<BYTE[3]>(bytes);
		return this;
	}

	//public Shellcode64* MovRegisterAtoFSOffset(int offset)
	//{
	//    write<uint>(0x04894864);
	//    write<byte>(0x25); //64 48 89 04 25
	//    write<int>(offset);
	//    return this;
	//}
	//public Shellcode64* MovRegisterSPtoFSOffset(int offset)
	//{
	//    write<uint>(0x24894864);
	//    write<byte>(0x25); //64 48 89 24 25
	//    write<int>(offset);
	//    return this;
	//}
	//public Shellcode64* MovRegisterSPtoGSOffset(int offset)
	//{
	//    write<uint>(0x24894865);
	//    write<byte>(0x25); //65 48 89 24 25
	//    write<int>(offset);
	//    return this;
	//}

	void addFakePointer(FakeObject* fakeObject)
	{
		fakeObject->AddTargetPointer(currentPointer - sizeof(LONG));
	}
	LateValue<LONG> newLateInt64()
	{
		return LateValue<LONG>(currentPointer - 8);
	}
	LateValue<int> newLateInt32()
	{
		return LateValue<int>(currentPointer - 4);
	}
	Shellcode64* MovFakePointerRegisterC(FakeObject* fakeObject)
	{
		MovInt64RegisterC(0);
		addFakePointer(fakeObject);
		return this;
	}
	Shellcode64* MovFakePointerRegisterD(FakeObject* fakeObject)
	{
		MovInt64RegisterD(0);
		addFakePointer(fakeObject);
		return this;
	}
	Shellcode64* MovFakePointerRegister8(FakeObject* fakeObject)
	{
		MovInt64Register8(0);
		addFakePointer(fakeObject);
		return this;
	}
	Shellcode64* MovFakePointerRegister9(FakeObject* fakeObject)
	{
		MovInt64Register9(0);
		addFakePointer(fakeObject);
		return this;
	}
	Shellcode64* MovRegisterAPointer(LONG pointer)
	{
		write<USHORT>(0xA348); //48 A3
		write<LONG>(pointer);
		return this;
	}
	Shellcode64* MovRegisterAFakePointer(FakeObject* fakeObject)
	{
		MovRegisterAPointer(0);
		addFakePointer(fakeObject);
		return this;
	}
	LateValue<LONG> MovRegisterALatePointer()
	{
		MovRegisterAPointer(0);
		return newLateInt64();
	}
	Shellcode64* MovRegisterALatePointer(LateValue<LONG>* latePointer)
	{
		*latePointer = MovRegisterALatePointer();
		return this;
	}

	Shellcode64* PushInt64(LONG value)
	{
		int lo = (int)(value & 0xffffffff);
		int hi = (int)(value >> 32);
		PushInt(lo);
		write<uint>(0x042444C7); //C7 44 24 04
		write<int>(hi);
		return this;
	}
	//Shellcode64 PushInt64(POINTER value) { return PushInt64((LONG)value); }

	class LateInt64Push : public LateValue<LONG>
	{
	private:
		void insert(LONG value)
		{
			int lo = (int)(value & 0xffffffff);
			int hi = (int)(value >> 32);

			POINTER valuePtr = (POINTER)pointer;

			*(int*)valuePtr = lo;
			*(int*)(valuePtr + 8) = hi;
		}
	public:
		LateInt64Push(POINTER pointer)
		{
			this->pointer = pointer;
			this->insertptr = (InsertFunc)&LateInt64Push::insert;
		}
	};
	LateValue<LONG> PushLateInt64()
	{
		PushInt64(0);
		return LateInt64Push(currentPointer - 12);
	}
	Shellcode64* PushLateInt64(LateValue<LONG>* lateValue)
	{
		*lateValue = PushLateInt64();
		return this;
	}

	Shellcode64* PushFakePointer(FakeObject* fakeObject)
	{
		PushInt64(0);
		fakeObject->AddTargetPointer(currentPointer - 12, 1);
		return this;
	}

	Shellcode64* CallFar(LONG address)
	{
		LONG delta = address - (RemoteAddress + size + sizeof(int));
		if ((ULONG)delta > UINT_MAX)
		{
			MovInt64RegisterA(address);
			CallRegisterA();
		}
		else
		{
			write<BYTE>(0xE8);
			write<int>((int)delta);
		}

		return this;
	}
	//Shellcode64 CallFar(POINTER address) { return CallFar((LONG)address); }

	Shellcode64* JmpFar(LONG address)
	{
		LONG delta = address - (RemoteAddress + size + sizeof(int));
		if ((ULONG)delta > UINT_MAX)
		{
			MovInt64RegisterA(address);
			JmpRegisterA();
		}
		else
		{
			write<BYTE>(0xE9);
			write<int>((int)delta);
		}

		return this;
	}
	//Shellcode64 JmpFar(POINTER address) { return JmpFar((LONG)address); }

	FakeObject* NewFakeObject(POINTER valuePtr, int size)
	{
		FakeObject* fakeObject = new FakeObject(valuePtr, size);
		fakeMemory->Add(fakeObject);
		return fakeObject;
	}
	template<typename T>
	FakeObject* NewFakeObject(T* valuePtr)
	{
		FakeObject* fakeObject = new FakeObject((POINTER)valuePtr, sizeof(T));
		fakeMemory->Add(fakeObject);
		return fakeObject;
	}
	Shellcode64* NewFakeObject(POINTER valuePtr, int size, FakeObject** fakeObject)
	{
		*fakeObject = NewFakeObject(valuePtr, size);
		return this;
	}
	template<typename T>
	Shellcode64* NewFakeObject(T* valuePtr, FakeObject** fakeObject)
	{
		*fakeObject = NewFakeObject<T>(valuePtr);
		return this;
	}

	Shellcode64* FakePushBytes(BYTE count)
	{
		write<int>(0x00EC8348 | (count << 24)); //48 83 EC
		return this;
	}
	Shellcode64* FakePopBytes(BYTE count)
	{
		write<int>(0x00C48348 | (count << 24)); //48 83 C4
		return this;
	}

	Shellcode64* AlignStack()
	{
		write<UINT>(0xF0E48348); //48 83 E4 F0
		return this;
	}


	Shellcode Complete()
	{
		int fakeMemoryLength = fakeMemory->Length;
		for (int i = 0; i < fakeMemoryLength; i++)
		{
			FakeObject* fakeObject = (*fakeMemory)[i];
			ULONG objectRemoteAddress = RemoteAddress + size;
			if (!write(fakeObject)) return Shellcode(0, 0, 0, 0, 0);
			int lo = (int)(objectRemoteAddress & 0xffffffff);
			int hi = (int)(objectRemoteAddress >> 32);
			int targetPointersLength = fakeObject->TargetPointers->Length;
			for (int j = 0; j < targetPointersLength; j++)
			{
				FakeObject::FakePointer targetPointer = (*fakeObject->TargetPointers)[j];
				if (targetPointer.Type == 1)
				{
					insert<int>(targetPointer.Pointer, lo);
					insert<int>(targetPointer.Pointer + 8, hi);
				}
				else
				{
					insert<LONG>(targetPointer.Pointer, objectRemoteAddress);
				}
			}
		}

		return Shellcode(StartPointer, RemoteAddress, entryPoint, size, MaxSize);
	}
};