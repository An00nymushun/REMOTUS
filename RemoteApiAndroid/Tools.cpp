#include "Tools.h"





inline bool CheckPattern64(BYTE* buffer, int bufferSize, Pattern64* currentPattern, LONG currentBlockAddress)
{
	BYTE* pattern = currentPattern->Bytes;
	char* mask = currentPattern->Mask;
	int patternLength = currentPattern->Length;
	BYTE* pointerInBlock = buffer;
	BYTE* checkEnd = buffer + (bufferSize - patternLength);

	do
	{
		int posInPattern = 0;

		while (mask[posInPattern] == '?' || pointerInBlock[posInPattern] == pattern[posInPattern])
		{
			posInPattern++;
			if (posInPattern == patternLength)
			{
				currentPattern->CallBack(buffer, currentBlockAddress, pointerInBlock - buffer, bufferSize);
				return true;
			}
		}

		pointerInBlock++;
	} while (pointerInBlock <= checkEnd);

	return false;
}

bool PatternScan64(LONG startAddress, int scanRange, Pattern64* patternArray, int patternCount)
{
	const int bufferSize = BufferSize - 512; //

	LONG endAddress = startAddress + scanRange;
	MEMORY_BASIC_INFORMATION64* memoryInfo;
	LONG subscanStart = startAddress;
	int subscanRange;
	LONG nextRegionStart;
	Pattern64* firstPattern = patternArray;
	Pattern64* lastPattern = patternArray + (patternCount - 1);
	Pattern64* currentPattern;
	int maxPatternLength = patternArray[0].Length;
	int minPatternLength = patternArray[0].Length;

	currentPattern = lastPattern;
	for (; currentPattern > firstPattern; currentPattern--)
	{
		int patternLength = currentPattern->Length;
		if (patternLength > maxPatternLength)
			maxPatternLength = patternLength;
		else if(patternLength < minPatternLength)
			minPatternLength = patternLength;
	}

	int blockSize = bufferSize - (maxPatternLength - 1);

	while (true)
	{

		while (true)
		{
			if (subscanStart >= endAddress) return false;

			if (!QueryMemoryInfo64(subscanStart, &memoryInfo)) return false;

			if ((memoryInfo->Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0)
				break;

			subscanStart += memoryInfo->RegionSize;
		}

		nextRegionStart = subscanStart + memoryInfo->RegionSize;

		while (nextRegionStart < endAddress)
		{
			if (!QueryMemoryInfo64(nextRegionStart, &memoryInfo)) return false;

			if ((memoryInfo->Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) == 0)
				break;

			nextRegionStart += memoryInfo->RegionSize;
		}

		subscanRange = nextRegionStart - subscanStart;



		int numberOfBlocks = subscanRange / blockSize;
		int remainingBytes = subscanRange % blockSize;
		//int checkLimit = blockSize - minPatternLength;
		LONG currentBlockAddress = startAddress;
		BYTE* buffer = Buffer;


		for (int i = 0; i < numberOfBlocks; i++)
		{
			if (!ReadBytes(currentBlockAddress, buffer, bufferSize)) return false;


			for (currentPattern = firstPattern;; currentPattern++)
			{
				bool patternFound = CheckPattern64(buffer, bufferSize, currentPattern, currentBlockAddress);

				if (patternFound)
				{
					if (currentPattern == lastPattern)
					{
						if(currentPattern == firstPattern)
							return true;
					}
					else
					{
						*currentPattern = *lastPattern;
					}

					lastPattern--;
					break;
				}

				if (currentPattern == lastPattern)
					break;
			}


			currentBlockAddress += blockSize;
		}
		if (remainingBytes > 0)
		{
			if (!ReadBytes(currentBlockAddress, buffer, remainingBytes)) return false;


			for (currentPattern = firstPattern;; currentPattern++)
			{
				bool patternFound = CheckPattern64(buffer, remainingBytes, currentPattern, currentBlockAddress);

				if (patternFound)
				{
					if (currentPattern == lastPattern)
					{
						if (currentPattern == firstPattern)
							return true;
					}
					else
					{
						*currentPattern = *lastPattern;
					}

					lastPattern--;
					break;
				}

				if (currentPattern == lastPattern)
					break;
			}


		}

		
		subscanStart = nextRegionStart;
	}

	return false;
}



inline bool CheckModule64(char* baseName, int baseNameLength, Module64* currentModule, LONG moduleHandle)
{
	int targetBaseNameLength = currentModule->BaseNameLength;
	if (baseNameLength == targetBaseNameLength)
	{
		char* targetBaseName = currentModule->BaseName;
		if (memcmp(baseName, targetBaseName, baseNameLength) == 0)
		{
			MODULEINFO64* moduleInfo;
			if (!RemoteCalls->GetModuleInformation(TargetHandle, moduleHandle, &moduleInfo))
				return false;

			void(*callBack)(LONG, LONG, int) = currentModule->CallBack;
			callBack(moduleHandle, moduleInfo->lpBaseOfDll, moduleInfo->SizeOfImage);

			return true;
		}
	}

	return false;
}


bool ModuleScan64(Module64* moduleArray, int moduleCount, UINT filterFlags)
{
	LONG* currentHandle;
	LONG* lastHandle;
	UINT neededSize;
	char baseName[32];
	int baseNameLength;
	Module64* currentModule;
	Module64* firstModule;
	Module64* lastModule;

	LONG targetHandle = TargetHandle;
	LONG* handleArray;
	bool success = RemoteCalls->EnumProcessModulesEx(targetHandle, &handleArray, 2048, &neededSize, filterFlags);
	if (!success) return false;

	int handleArrayLength = neededSize / sizeof(LONG);

	LONG* localArray = new LONG[handleArrayLength];
	memcpy(localArray, handleArray, neededSize);

	lastHandle = localArray + handleArrayLength - 1;
	currentHandle = localArray;
	firstModule = moduleArray;
	lastModule = moduleArray + moduleCount - 1;


	
	for (;; currentHandle++)
	{
		LONG moduleHandle = *currentHandle;
		baseNameLength = RemoteCalls->GetModuleBaseNameA(targetHandle, moduleHandle, baseName, 32);

		for (currentModule = firstModule;; currentModule++)
		{
			bool moduleFound = CheckModule64(baseName, baseNameLength, currentModule, moduleHandle);

			if (moduleFound)
			{
				if (currentModule == lastModule)
				{
					if (currentModule == firstModule)
					{
						delete[] localArray;
						return true;
					}
				}
				else
				{
					*currentModule = *lastModule;
				}

				lastModule--;
				break;
			}

			if (currentModule == lastModule)
				break;
		}


		if (currentHandle == lastHandle)
		{
			delete[] localArray;
			return false;
		}
	}
}




//bool GetModuleByName64(char* moduleName, Module64* module)
//{
//	MODULEENTRY3264* moduleEntry;
//	LONG snapshotHandle = RemoteCalls->CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, TargetId);
//	bool found = false;
//
//	if (snapshotHandle != INVALID_HANDLE_VALUE)
//	{
//		//moduleEntry.dwSize = sizeof(MODULEENTRY3264);
//
//		if (RemoteCalls->Module32First(snapshotHandle, &moduleEntry))
//		{
//			do
//			{
//				char* entryModuleName = moduleEntry->szModule;
//
//				if (strcmp(entryModuleName, moduleName) == 0)
//				{
//					module->BaseAddress = moduleEntry->modBaseAddr;
//					module->Size = moduleEntry->modBaseSize;
//					found = true;
//					break;
//				}
//
//			} while (RemoteCalls->Module32Next(snapshotHandle, &moduleEntry));
//
//		}
//		int err = RemoteCalls->GetLastError();
//		RemoteCalls->CloseHandle(snapshotHandle);
//	}
//
//	return found;
//}