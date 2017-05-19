/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com

	With BIG thanks and love to:
	- @msuiche <3
	- @halsten
	- @malwareunicorn
	- @adriengnt	(https://github.com/aguinet/wannakey)
		This guy discovered how to retrieve prime numbers of the private key when it's not possible to get it in a normal way
		He rocks \o/ - I was unable to fix his code where the Private Key is malformed, so I made it here with OpenSSL lib :)

	.. Just to help ...

	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "process.h"

KULL_M_MEMORY_HANDLE KULL_M_MEMORY_GLOBAL_OWN_HANDLE = {KULL_M_MEMORY_TYPE_OWN, NULL};

BOOL kull_m_memory_open(IN KULL_M_MEMORY_TYPE Type, IN HANDLE hAny, OUT PKULL_M_MEMORY_HANDLE *hMemory)
{
	BOOL status = FALSE;

	*hMemory = (PKULL_M_MEMORY_HANDLE) LocalAlloc(LPTR, sizeof(KULL_M_MEMORY_HANDLE));
	if(*hMemory)
	{
		(*hMemory)->type = Type;
		switch (Type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			status = TRUE;
			break;
		case KULL_M_MEMORY_TYPE_PROCESS:
			if((*hMemory)->pHandleProcess = (PKULL_M_MEMORY_HANDLE_PROCESS) LocalAlloc(LPTR, sizeof(KULL_M_MEMORY_HANDLE_PROCESS)))
			{
				(*hMemory)->pHandleProcess->hProcess = hAny;
				status = TRUE;
			}
			break;
		case KULL_M_MEMORY_TYPE_FILE:
			if((*hMemory)->pHandleFile = (PKULL_M_MEMORY_HANDLE_FILE) LocalAlloc(LPTR, sizeof(KULL_M_MEMORY_HANDLE_FILE)))
			{
				(*hMemory)->pHandleFile->hFile = hAny;
				status = TRUE;
			}
			break;
		default:
			break;
		}
		if(!status)
			LocalFree(*hMemory);
	}
	return status;
}

PKULL_M_MEMORY_HANDLE kull_m_memory_close(IN PKULL_M_MEMORY_HANDLE hMemory)
{
	if(hMemory)
	{
		switch (hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_PROCESS:
			LocalFree(hMemory->pHandleProcess);
			break;
		case KULL_M_MEMORY_TYPE_FILE:
			LocalFree(hMemory->pHandleFile);
			break;
		default:
			break;
		}
		return (PKULL_M_MEMORY_HANDLE) LocalFree(hMemory);
	}
	else return NULL;
}

BOOL kull_m_memory_copy(OUT PKULL_M_MEMORY_ADDRESS Destination, IN PKULL_M_MEMORY_ADDRESS Source, IN SIZE_T Length)
{
	BOOL status = FALSE;
	BOOL bufferMeFirst = FALSE;
	KULL_M_MEMORY_ADDRESS aBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	DWORD nbReadWrite;

	switch(Destination->hMemory->type)
	{
	case KULL_M_MEMORY_TYPE_OWN:
		switch(Source->hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			RtlCopyMemory(Destination->address, Source->address, Length);
			status = TRUE;
			break;
		case KULL_M_MEMORY_TYPE_PROCESS:
			status = ReadProcessMemory(Source->hMemory->pHandleProcess->hProcess, Source->address, Destination->address, Length, NULL);
			break;
		case KULL_M_MEMORY_TYPE_FILE:
			if(SetFilePointer(Source->hMemory->pHandleFile->hFile, PtrToLong(Source->address), NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
				status = ReadFile(Source->hMemory->pHandleFile->hFile, Destination->address, (DWORD) Length, &nbReadWrite, NULL);
			break;
		default:
			break;
		}
		break;
	case KULL_M_MEMORY_TYPE_PROCESS:
		switch(Source->hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			status = WriteProcessMemory(Destination->hMemory->pHandleProcess->hProcess, Destination->address, Source->address, Length, NULL);
			break;
		default:
			bufferMeFirst = TRUE;
			break;
		}
		break;
	case KULL_M_MEMORY_TYPE_FILE:
		switch(Source->hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			if(!Destination->address || SetFilePointer(Destination->hMemory->pHandleFile->hFile, PtrToLong(Destination->address), NULL, FILE_BEGIN))
				status = WriteFile(Destination->hMemory->pHandleFile->hFile, Source->address, (DWORD) Length, &nbReadWrite, NULL);
			break;
		default:
			bufferMeFirst = TRUE;
			break;
		}
		break;
	default:
		break;
	}

	if(bufferMeFirst)
	{
		if(aBuffer.address = LocalAlloc(LPTR, Length))
		{
			if(kull_m_memory_copy(&aBuffer, Source, Length))
				status = kull_m_memory_copy(Destination, &aBuffer, Length);
			LocalFree(aBuffer.address);
		}
	}
	return status;
}

BOOL kull_m_memory_search(IN PKULL_M_MEMORY_ADDRESS Pattern, IN SIZE_T Length, IN PKULL_M_MEMORY_SEARCH Search, IN BOOL bufferMeFirst)
{
	BOOL status = FALSE;
	KULL_M_MEMORY_SEARCH  sBuffer = {{{NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, Search->kull_m_memoryRange.size}, NULL};
	PBYTE CurrentPtr;
	PBYTE limite = (PBYTE) Search->kull_m_memoryRange.kull_m_memoryAdress.address + Search->kull_m_memoryRange.size;

	switch(Pattern->hMemory->type)
	{
	case KULL_M_MEMORY_TYPE_OWN:
		switch(Search->kull_m_memoryRange.kull_m_memoryAdress.hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			for(CurrentPtr = (PBYTE) Search->kull_m_memoryRange.kull_m_memoryAdress.address; !status && (CurrentPtr + Length <= limite); CurrentPtr++)
				status = RtlEqualMemory(Pattern->address, CurrentPtr, Length);
			CurrentPtr--;
			break;
		case KULL_M_MEMORY_TYPE_PROCESS:
		case KULL_M_MEMORY_TYPE_FILE:
		case KULL_M_MEMORY_TYPE_KERNEL:
			if(sBuffer.kull_m_memoryRange.kull_m_memoryAdress.address = LocalAlloc(LPTR, Search->kull_m_memoryRange.size))
			{
				if(kull_m_memory_copy(&sBuffer.kull_m_memoryRange.kull_m_memoryAdress, &Search->kull_m_memoryRange.kull_m_memoryAdress, Search->kull_m_memoryRange.size))
					if(status = kull_m_memory_search(Pattern, Length, &sBuffer, FALSE))
						CurrentPtr = (PBYTE) Search->kull_m_memoryRange.kull_m_memoryAdress.address + (((PBYTE) sBuffer.result) - (PBYTE) sBuffer.kull_m_memoryRange.kull_m_memoryAdress.address);
				LocalFree(sBuffer.kull_m_memoryRange.kull_m_memoryAdress.address);
			}
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	Search->result = status ? CurrentPtr : NULL;

	return status;
}

BOOL kull_m_memory_alloc(IN PKULL_M_MEMORY_ADDRESS Address, IN SIZE_T Lenght, IN DWORD Protection)
{
	PVOID ptrAddress = &Address->address;
	DWORD lenPtr = sizeof(PVOID);
	Address->address = NULL;
	switch(Address->hMemory->type)
	{
		case KULL_M_MEMORY_TYPE_OWN:
			Address->address = VirtualAlloc(NULL, Lenght, MEM_COMMIT, Protection);
			break;
		case KULL_M_MEMORY_TYPE_PROCESS:
			Address->address = VirtualAllocEx(Address->hMemory->pHandleProcess->hProcess, NULL, Lenght, MEM_COMMIT, Protection);
			break;
		default:
			break;
	}
	return (Address->address) != NULL;
}

BOOL kull_m_memory_free(IN PKULL_M_MEMORY_ADDRESS Address, IN SIZE_T Lenght)
{
	BOOL status = FALSE;

	switch(Address->hMemory->type)
	{
		case KULL_M_MEMORY_TYPE_OWN:
			status = VirtualFree(Address->address, Lenght, MEM_RELEASE);
			break;
		case KULL_M_MEMORY_TYPE_PROCESS:
			status = VirtualFreeEx(Address->hMemory->pHandleProcess->hProcess, Address->address, Lenght, MEM_RELEASE);
			break;
		default:
			break;
	}
	return status;
}


BOOL kull_m_memory_query(IN PKULL_M_MEMORY_ADDRESS Address, OUT PMEMORY_BASIC_INFORMATION MemoryInfo)
{
	BOOL status = FALSE;
	switch(Address->hMemory->type)
	{
	case KULL_M_MEMORY_TYPE_OWN:
		status = VirtualQuery(Address->address, MemoryInfo, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION);
		break;
	case KULL_M_MEMORY_TYPE_PROCESS:
		status = VirtualQueryEx(Address->hMemory->pHandleProcess->hProcess, Address->address, MemoryInfo, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION);
		break;
	default:
		break;
	}

	return status;
}

BOOL kull_m_memory_protect(IN PKULL_M_MEMORY_ADDRESS Address, IN SIZE_T dwSize, IN DWORD flNewProtect, OUT OPTIONAL PDWORD lpflOldProtect)
{
	BOOL status = FALSE;
	DWORD OldProtect;

	switch(Address->hMemory->type)
	{
	case KULL_M_MEMORY_TYPE_OWN:
		status = VirtualProtect(Address->address, dwSize, flNewProtect, &OldProtect);
		break;
	case KULL_M_MEMORY_TYPE_PROCESS:
		status = VirtualProtectEx(Address->hMemory->pHandleProcess->hProcess, Address->address, dwSize, flNewProtect, &OldProtect);
		break;
	default:
		break;
	}

	if(status && lpflOldProtect)
		*lpflOldProtect = OldProtect;

	return status;
}

BOOL kull_m_memory_equal(IN PKULL_M_MEMORY_ADDRESS Address1, IN PKULL_M_MEMORY_ADDRESS Address2, IN SIZE_T Lenght)
{
	BOOL status = FALSE;
	KULL_M_MEMORY_ADDRESS aBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	switch(Address1->hMemory->type)
	{
	case KULL_M_MEMORY_TYPE_OWN:
		switch(Address2->hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			status = RtlEqualMemory(Address1->address, Address2->address, Lenght);
			break;
		default:
			status = kull_m_memory_equal(Address2, Address1, Lenght);
			break;
		}
		break;
	default:
		if(aBuffer.address = LocalAlloc(LPTR, Lenght))
		{
			if(kull_m_memory_copy(&aBuffer, Address1, Lenght))
				status = kull_m_memory_equal(&aBuffer, Address2, Lenght);
			LocalFree(aBuffer.address);
		}
		break;
	}
	return status;
}

NTSTATUS kull_m_process_NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS informationClass, PVOID buffer, ULONG informationLength)
{
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	DWORD sizeOfBuffer;

	if(*(PVOID *) buffer)
	{
		status = NtQuerySystemInformation(informationClass, *(PVOID *) buffer, informationLength, NULL);
	}
	else
	{
		for(sizeOfBuffer = 0x1000; (status == STATUS_INFO_LENGTH_MISMATCH) && (*(PVOID *) buffer = LocalAlloc(LPTR, sizeOfBuffer)) ; sizeOfBuffer <<= 1)
		{
			status = NtQuerySystemInformation(informationClass, *(PVOID *) buffer, sizeOfBuffer, NULL);
			if(!NT_SUCCESS(status))
				LocalFree(*(PVOID *) buffer);
		}
	}
	return status;
}

NTSTATUS kull_m_process_getProcessInformation(PKULL_M_PROCESS_ENUM_CALLBACK callBack, PVOID pvArg)
{
	NTSTATUS status;
	PSYSTEM_PROCESS_INFORMATION buffer = NULL, myInfos;

	status = kull_m_process_NtQuerySystemInformation(SystemProcessInformation, &buffer, 0);
	
	if(NT_SUCCESS(status))
	{
		for(myInfos = buffer; callBack(myInfos, pvArg) && myInfos->NextEntryOffset ; myInfos = (PSYSTEM_PROCESS_INFORMATION) ((PBYTE) myInfos + myInfos->NextEntryOffset));
		LocalFree(buffer);
	}
	return status;
}

BOOL CALLBACK kull_m_process_callback_pidForName(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg)
{
	if(((PKULL_M_PROCESS_PID_FOR_NAME) pvArg)->isFound = RtlEqualUnicodeString(&pSystemProcessInformation->ImageName, ((PKULL_M_PROCESS_PID_FOR_NAME) pvArg)->name, TRUE))
		*((PKULL_M_PROCESS_PID_FOR_NAME) pvArg)->processId = PtrToUlong(pSystemProcessInformation->UniqueProcessId);
	return !((PKULL_M_PROCESS_PID_FOR_NAME) pvArg)->isFound;
}

BOOL kull_m_process_getProcessIdForName(LPCWSTR name, PDWORD processId)
{
	BOOL status = FALSE;
	UNICODE_STRING uName;
	KULL_M_PROCESS_PID_FOR_NAME mySearch = {&uName, processId, FALSE};
	
	RtlInitUnicodeString(&uName, name);
	if(NT_SUCCESS(kull_m_process_getProcessInformation(kull_m_process_callback_pidForName, &mySearch)))
		status = mySearch.isFound;
	return status;;
}

NTSTATUS kull_m_process_getVeryBasicModuleInformations(PKULL_M_MEMORY_HANDLE memory, PKULL_M_MODULE_ENUM_CALLBACK callBack, PVOID pvArg)
{
	NTSTATUS status = STATUS_DLL_NOT_FOUND;
	PLDR_DATA_TABLE_ENTRY pLdrEntry;
	PEB Peb; PEB_LDR_DATA LdrData; LDR_DATA_TABLE_ENTRY LdrEntry;
#ifdef _M_X64
	PLDR_DATA_TABLE_ENTRY_F32 pLdrEntry32;
	PEB_F32 Peb32; PEB_LDR_DATA_F32 LdrData32; LDR_DATA_TABLE_ENTRY_F32 LdrEntry32;
#endif
	KULL_M_MEMORY_ADDRESS aBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_ADDRESS aProcess= {NULL, memory};
	PBYTE aLire, fin;
	UNICODE_STRING moduleName;
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION moduleInformation;
	PRTL_PROCESS_MODULES modules = NULL;
	BOOL continueCallback = TRUE;
	moduleInformation.DllBase.hMemory = memory;
	switch(memory->type)
	{
	case KULL_M_MEMORY_TYPE_OWN:
		if(kull_m_process_peb(memory, &Peb, FALSE))
		{
			for(pLdrEntry  = (PLDR_DATA_TABLE_ENTRY) ((PBYTE) (Peb.Ldr->InMemoryOrderModulevector.Flink) - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
				(pLdrEntry != (PLDR_DATA_TABLE_ENTRY) ((PBYTE) (Peb.Ldr) + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModulevector))) && continueCallback;
				pLdrEntry  = (PLDR_DATA_TABLE_ENTRY) ((PBYTE) (pLdrEntry->InMemoryOrderLinks.Flink ) - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks))
					)
				{
					moduleInformation.DllBase.address = pLdrEntry->DllBase;
					moduleInformation.SizeOfImage = pLdrEntry->SizeOfImage;
					moduleInformation.NameDontUseOutsideCallback = &pLdrEntry->BaseDllName;
					kull_m_process_adjustTimeDateStamp(&moduleInformation);
					continueCallback = callBack(&moduleInformation, pvArg);
				}
				status = STATUS_SUCCESS;
		}
#ifdef _M_X64
		moduleInformation.NameDontUseOutsideCallback = &moduleName;
		if(continueCallback && NT_SUCCESS(status) && kull_m_process_peb(memory, (PPEB) &Peb32, TRUE))
		{
			status = STATUS_PARTIAL_COPY;
			
			for(pLdrEntry32  = (PLDR_DATA_TABLE_ENTRY_F32) ((PBYTE) ULongToPtr(((PEB_LDR_DATA_F32 *) ULongToPtr(Peb32.Ldr))->InMemoryOrderModulevector.Flink) - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY_F32, InMemoryOrderLinks));
				(pLdrEntry32 != (PLDR_DATA_TABLE_ENTRY_F32) ((PBYTE) ULongToPtr(Peb32.Ldr) + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModulevector))) && continueCallback;
				pLdrEntry32  = (PLDR_DATA_TABLE_ENTRY_F32) ((PBYTE) ULongToPtr(pLdrEntry32->InMemoryOrderLinks.Flink) - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY_F32, InMemoryOrderLinks))
				)
			{
				moduleInformation.DllBase.address = ULongToPtr(pLdrEntry32->DllBase);
				moduleInformation.SizeOfImage = pLdrEntry32->SizeOfImage;
				moduleName.Length = pLdrEntry32->BaseDllName.Length;
				moduleName.MaximumLength = pLdrEntry32->BaseDllName.MaximumLength;
				moduleName.Buffer = (PWSTR) ULongToPtr(pLdrEntry32->BaseDllName.Buffer);
				kull_m_process_adjustTimeDateStamp(&moduleInformation);
				continueCallback = callBack(&moduleInformation, pvArg);
			}
			status = STATUS_SUCCESS;
		}
#endif
		break;

	case KULL_M_MEMORY_TYPE_PROCESS:
		moduleInformation.NameDontUseOutsideCallback = &moduleName;
		if(kull_m_process_peb(memory, &Peb, FALSE))
		{
			aBuffer.address = &LdrData; aProcess.address = Peb.Ldr;
			if(kull_m_memory_copy(&aBuffer, &aProcess, sizeof(LdrData)))
			{
				for(
					aLire  = (PBYTE) (LdrData.InMemoryOrderModulevector.Flink) - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
					fin    = (PBYTE) (Peb.Ldr) + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModulevector);
					(aLire != fin) && continueCallback;
					aLire  = (PBYTE) LdrEntry.InMemoryOrderLinks.Flink - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)
					)
				{
					aBuffer.address = &LdrEntry; aProcess.address = aLire;
					if(continueCallback = kull_m_memory_copy(&aBuffer, &aProcess, sizeof(LdrEntry)))
					{
						moduleInformation.DllBase.address = LdrEntry.DllBase;
						moduleInformation.SizeOfImage = LdrEntry.SizeOfImage;
						moduleName = LdrEntry.BaseDllName;
						if(moduleName.Buffer = (PWSTR) LocalAlloc(LPTR, moduleName.MaximumLength))
						{
							aBuffer.address = moduleName.Buffer; aProcess.address = LdrEntry.BaseDllName.Buffer;
							if(kull_m_memory_copy(&aBuffer, &aProcess, moduleName.MaximumLength))
							{
								kull_m_process_adjustTimeDateStamp(&moduleInformation);
								continueCallback = callBack(&moduleInformation, pvArg);
							}
							LocalFree(moduleName.Buffer);
						}
					}
				}
				status = STATUS_SUCCESS;
			}
		}
#ifdef _M_X64
		if(continueCallback && NT_SUCCESS(status) && kull_m_process_peb(memory, (PPEB) &Peb32, TRUE))
		{
			status = STATUS_PARTIAL_COPY;
			aBuffer.address = &LdrData32; aProcess.address = ULongToPtr(Peb32.Ldr);
			if(kull_m_memory_copy(&aBuffer, &aProcess, sizeof(LdrData32)))
			{
				for(
					aLire  = (PBYTE) ULongToPtr(LdrData32.InMemoryOrderModulevector.Flink) - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY_F32, InMemoryOrderLinks),
					fin    = (PBYTE) ULongToPtr(Peb32.Ldr) + FIELD_OFFSET(PEB_LDR_DATA_F32, InLoadOrderModulevector);
					(aLire != fin) && continueCallback;
					aLire  = (PBYTE) ULongToPtr(LdrEntry32.InMemoryOrderLinks.Flink) - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY_F32, InMemoryOrderLinks)
					)
				{
					aBuffer.address = &LdrEntry32; aProcess.address = aLire;
					if(kull_m_memory_copy(&aBuffer, &aProcess, sizeof(LdrEntry32)))
					{
						moduleInformation.DllBase.address = ULongToPtr(LdrEntry32.DllBase);
						moduleInformation.SizeOfImage = LdrEntry32.SizeOfImage;
						
						moduleName.Length = LdrEntry32.BaseDllName.Length;
						moduleName.MaximumLength = LdrEntry32.BaseDllName.MaximumLength;
						if(moduleName.Buffer = (PWSTR) LocalAlloc(LPTR, moduleName.MaximumLength))
						{
							aBuffer.address = moduleName.Buffer; aProcess.address = ULongToPtr(LdrEntry32.BaseDllName.Buffer);
							if(kull_m_memory_copy(&aBuffer, &aProcess, moduleName.MaximumLength))
							{
								kull_m_process_adjustTimeDateStamp(&moduleInformation);
								continueCallback = callBack(&moduleInformation, pvArg);
							}
							LocalFree(moduleName.Buffer);
						}
					}
				}
				status = STATUS_SUCCESS;
			}
		}
#endif
		break;

	default:
		status = STATUS_NOT_IMPLEMENTED;
		break;
	}

	return status;
}

void kull_m_process_adjustTimeDateStamp(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION information)
{
	PIMAGE_NT_HEADERS ntHeaders;
	if(kull_m_process_ntheaders(&information->DllBase, &ntHeaders))
	{
		information->TimeDateStamp = ntHeaders->FileHeader.TimeDateStamp;
		LocalFree(ntHeaders);
	}
	else information->TimeDateStamp = 0;
}

BOOL CALLBACK kull_m_process_callback_moduleForName(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg)
{
	if(((PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION_FOR_NAME) pvArg)->isFound = RtlEqualUnicodeString(pModuleInformation->NameDontUseOutsideCallback, ((PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION_FOR_NAME) pvArg)->name, TRUE))
		*((PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION_FOR_NAME) pvArg)->informations = *pModuleInformation;
	return !((PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION_FOR_NAME) pvArg)->isFound;
}

BOOL CALLBACK kull_m_process_callback_moduleFirst(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg)
{
	*(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION) pvArg = *pModuleInformation;
	return FALSE;
}

BOOL kull_m_process_getVeryBasicModuleInformationsForName(PKULL_M_MEMORY_HANDLE memory, PCWSTR name, PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION informations)
{
	BOOL status = FALSE;
	UNICODE_STRING uName;
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION_FOR_NAME mySearch = {&uName, informations, FALSE};

	if(name)
	{
		RtlInitUnicodeString(&uName, name);
		if(NT_SUCCESS(kull_m_process_getVeryBasicModuleInformations(memory, kull_m_process_callback_moduleForName, &mySearch)))
			status = mySearch.isFound;
	}
	else
		status = NT_SUCCESS(kull_m_process_getVeryBasicModuleInformations(memory, kull_m_process_callback_moduleFirst, informations));
	return status;
}

NTSTATUS kull_m_process_getMemoryInformations(PKULL_M_MEMORY_HANDLE memory, PKULL_M_MEMORY_RANGE_ENUM_CALLBACK callBack, PVOID pvArg)
{
	NTSTATUS status = STATUS_NOT_FOUND;
	MEMORY_BASIC_INFORMATION memoryInfos;
	PBYTE currentPage, maxPage;
	BOOL continueCallback = TRUE;

	if(!NT_SUCCESS(kull_m_process_NtQuerySystemInformation(KIWI_SystemMmSystemRangeStart, &maxPage, sizeof(PBYTE))))
		maxPage = MmSystemRangeStart;

	switch(memory->type)
	{
	case KULL_M_MEMORY_TYPE_OWN:
		for(currentPage = 0; (currentPage < maxPage) && continueCallback; currentPage += memoryInfos.RegionSize)
			if(VirtualQuery(currentPage, &memoryInfos, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION))
				continueCallback = callBack(&memoryInfos, pvArg);
			else break;
		status = STATUS_SUCCESS;
		break;
	case KULL_M_MEMORY_TYPE_PROCESS:
		for(currentPage = 0; (currentPage < maxPage) && continueCallback; currentPage += memoryInfos.RegionSize)
			if(VirtualQueryEx(memory->pHandleProcess->hProcess, currentPage, &memoryInfos, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION))
				continueCallback = callBack(&memoryInfos, pvArg);
			else break;
		status = STATUS_SUCCESS;
		break;
	default:
		break;
	}

	return status;
}

BOOL kull_m_process_peb(PKULL_M_MEMORY_HANDLE memory, PPEB pPeb, BOOL isWOW)
{
	BOOL status = FALSE;
	PROCESS_BASIC_INFORMATION processInformations;
	HANDLE hProcess = (memory->type == KULL_M_MEMORY_TYPE_PROCESS) ? memory->pHandleProcess->hProcess : GetCurrentProcess();
	KULL_M_MEMORY_ADDRESS aBuffer = {pPeb, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_ADDRESS aProcess= {NULL, memory};
	PROCESSINFOCLASS info;
	ULONG szPeb, szBuffer, szInfos;
	LPVOID buffer;

#ifdef _M_X64
	if(isWOW)
	{
		info = ProcessWow64Information;
		szBuffer = sizeof(processInformations.PebBaseAddress);
		buffer = &processInformations.PebBaseAddress;
		szPeb = sizeof(PEB_F32);
	}
	else
	{
#endif
		info = ProcessBasicInformation;
		szBuffer = sizeof(processInformations);
		buffer = &processInformations;
		szPeb = sizeof(PEB);
#ifdef _M_X64
	}
#endif

	switch(memory->type)
	{
#ifndef MIMIKATZ_W2000_SUPPORT
	case KULL_M_MEMORY_TYPE_OWN:
		if(!isWOW)
		{
			*pPeb = *RtlGetCurrentPeb();
			status = TRUE;
			break;
		}
#endif
	case KULL_M_MEMORY_TYPE_PROCESS:
		if(NT_SUCCESS(NtQueryInformationProcess(hProcess, info, buffer, szBuffer, &szInfos)) && (szInfos == szBuffer) && processInformations.PebBaseAddress)
		{
			aProcess.address = processInformations.PebBaseAddress;
			status = kull_m_memory_copy(&aBuffer, &aProcess, szPeb);
		}
		break;
	}
	return status;
}

BOOL kull_m_process_ntheaders(PKULL_M_MEMORY_ADDRESS pBase, PIMAGE_NT_HEADERS * pHeaders)
{
	BOOL status = FALSE;
	IMAGE_DOS_HEADER headerImageDos;
	KULL_M_MEMORY_ADDRESS aBuffer = {&headerImageDos, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aRealNtHeaders = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aProcess= {NULL, pBase->hMemory};
	DWORD size;

	if(kull_m_memory_copy(&aBuffer, pBase, sizeof(IMAGE_DOS_HEADER)) && headerImageDos.e_magic == IMAGE_DOS_SIGNATURE)
	{
		aProcess.address = (PBYTE) pBase->address + headerImageDos.e_lfanew;
		if(aBuffer.address = LocalAlloc(LPTR, sizeof(DWORD) + IMAGE_SIZEOF_FILE_HEADER))
		{
			if(kull_m_memory_copy(&aBuffer, &aProcess, sizeof(DWORD) + IMAGE_SIZEOF_FILE_HEADER) && ((PIMAGE_NT_HEADERS) aBuffer.address)->Signature == IMAGE_NT_SIGNATURE);
			{
				size = (((PIMAGE_NT_HEADERS) aBuffer.address)->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) ? sizeof(IMAGE_NT_HEADERS32) : sizeof(IMAGE_NT_HEADERS64);
				if(aRealNtHeaders.address = (PIMAGE_NT_HEADERS) LocalAlloc(LPTR, size))
				{
					status = kull_m_memory_copy(&aRealNtHeaders, &aProcess, size);

					if(status)
						*pHeaders = (PIMAGE_NT_HEADERS) aRealNtHeaders.address;
					else
						LocalFree(aRealNtHeaders.address);
				}
			}
			LocalFree(aBuffer.address);
		}
	}
	return status;
}

BOOL kull_m_process_datadirectory(PKULL_M_MEMORY_ADDRESS pBase, DWORD entry, PDWORD pRva, PDWORD pSize, PWORD pMachine, PVOID *pData)
{
	BOOL status = FALSE;
	KULL_M_MEMORY_ADDRESS aBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_ADDRESS aProcess= *pBase;
	
	DWORD rva, size;

	PIMAGE_NT_HEADERS pNtHeaders;
	if(kull_m_process_ntheaders(pBase, &pNtHeaders))
	{
		if(pMachine)
			*pMachine = pNtHeaders->FileHeader.Machine;
		
		if(pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
		{
			rva = ((PIMAGE_NT_HEADERS32) pNtHeaders)->OptionalHeader.DataDirectory[entry].VirtualAddress;
			size = ((PIMAGE_NT_HEADERS32) pNtHeaders)->OptionalHeader.DataDirectory[entry].Size;
		}
		else
		{
			rva = ((PIMAGE_NT_HEADERS64) pNtHeaders)->OptionalHeader.DataDirectory[entry].VirtualAddress;
			size = ((PIMAGE_NT_HEADERS64) pNtHeaders)->OptionalHeader.DataDirectory[entry].Size;
		}
		
		if(pRva)
			*pRva = rva;
		if(pSize)
			*pSize = size;

		if(rva && size && pData)
		{
			if(*pData = LocalAlloc(LPTR, size))
			{
				aProcess.address = (PBYTE) pBase->address + rva;
				aBuffer.address = *pData;
				status = kull_m_memory_copy(&aBuffer, &aProcess, size);

				if(!status)
					LocalFree(*pData);
			}
		}
		LocalFree(pNtHeaders);
	}
	return status;
}

PSTR kull_m_process_getImportNameWithoutEnd(PKULL_M_MEMORY_ADDRESS base)
{
	CHAR sEnd = '\0';
	SIZE_T size;
	KULL_M_MEMORY_ADDRESS aStringBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aNullBuffer = {&sEnd, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_SEARCH sMemory = {{{base->address, base->hMemory}, MAX_PATH}, NULL};

	if(kull_m_memory_search(&aNullBuffer, sizeof(sEnd), &sMemory, FALSE))
	{
		size = (PBYTE) sMemory.result - (PBYTE) base->address + sizeof(char);
		if(aStringBuffer.address = LocalAlloc(LPTR, size))
			if(!kull_m_memory_copy(&aStringBuffer, base, size))
				aStringBuffer.address = LocalFree(aStringBuffer.address);
	}
	return (PSTR) aStringBuffer.address;
}

NTSTATUS kull_m_process_getImportedEntryInformations(PKULL_M_MEMORY_ADDRESS address, PKULL_M_IMPORTED_ENTRY_ENUM_CALLBACK callBack, PVOID pvArg)
{
	PVOID pLocalBuffer;
	PIMAGE_IMPORT_DESCRIPTOR pImportDir;
	ULONG sizeThunk;
	ULONGLONG OriginalFirstThunk, FirstThunk, ordinalPattern;
	KULL_M_MEMORY_ADDRESS aOriginalFirstThunk = {&OriginalFirstThunk, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aFirstThunk = {&FirstThunk, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_ADDRESS aProcOriginalFirstThunk = {NULL, address->hMemory}, aProcName = {NULL, address->hMemory};
	KULL_M_PROCESS_IMPORTED_ENTRY importedEntry;
	BOOL continueCallback = TRUE;

	importedEntry.pFunction.hMemory = address->hMemory;
	importedEntry.function.hMemory = address->hMemory;

	if(kull_m_process_datadirectory(address, IMAGE_DIRECTORY_ENTRY_IMPORT, NULL, NULL, &importedEntry.machine, &pLocalBuffer))
	{
		if(importedEntry.machine == IMAGE_FILE_MACHINE_I386)
		{
			sizeThunk = sizeof(IMAGE_THUNK_DATA32);
			ordinalPattern = IMAGE_ORDINAL_FLAG32;
		}
		else
		{
			sizeThunk = sizeof(IMAGE_THUNK_DATA64);
			ordinalPattern = IMAGE_ORDINAL_FLAG64;
		}
		
		for(pImportDir = (PIMAGE_IMPORT_DESCRIPTOR) pLocalBuffer ; pImportDir->Characteristics && continueCallback; pImportDir++)
		{
			aProcName.address = (PBYTE) address->address + pImportDir->Name;
			if(importedEntry.libname = kull_m_process_getImportNameWithoutEnd(&aProcName))
			{
				for(
					aProcOriginalFirstThunk.address = ((PBYTE) address->address + pImportDir->OriginalFirstThunk),
					importedEntry.pFunction.address = ((PBYTE) address->address + pImportDir->FirstThunk);

					(kull_m_memory_copy(&aOriginalFirstThunk, &aProcOriginalFirstThunk, sizeThunk) && kull_m_memory_copy(&aFirstThunk, &importedEntry.pFunction, sizeThunk)) && (OriginalFirstThunk && FirstThunk) ;

					aProcOriginalFirstThunk.address = ((PBYTE) aProcOriginalFirstThunk.address + sizeThunk), ((PDWORD) &OriginalFirstThunk)[1] = 0,
					importedEntry.pFunction.address = ((PBYTE) importedEntry.pFunction.address + sizeThunk), ((PDWORD) &FirstThunk)[1] = 0
					)
				{
					importedEntry.function.address = (PVOID) FirstThunk;
					if(OriginalFirstThunk & ordinalPattern)
					{
						importedEntry.name = NULL;
						importedEntry.ordinal = IMAGE_ORDINAL(OriginalFirstThunk);
					}
					else
					{
						aProcName.address = ((PIMAGE_IMPORT_BY_NAME) ((PBYTE) address->address + OriginalFirstThunk))->Name;
						importedEntry.name = kull_m_process_getImportNameWithoutEnd(&aProcName);
						importedEntry.ordinal = 0;
					}

					continueCallback = callBack(&importedEntry, pvArg);

					if(importedEntry.name)
						LocalFree(importedEntry.name);

				}
				LocalFree(importedEntry.libname);
			}
		}
		LocalFree(pLocalBuffer);
	}
	return TRUE;
}

BOOL kull_m_process_getUnicodeString(IN PUNICODE_STRING string, IN PKULL_M_MEMORY_HANDLE source)
{
	BOOL status = FALSE;
	KULL_M_MEMORY_HANDLE hOwn = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aDestin = {NULL, &hOwn};
	KULL_M_MEMORY_ADDRESS aSource = {string->Buffer, source};
	
	string->Buffer = NULL;
	if(aSource.address && string->MaximumLength)
	{
		if(aDestin.address = LocalAlloc(LPTR, string->MaximumLength))
		{
			string->Buffer = (PWSTR) aDestin.address;
			status = kull_m_memory_copy(&aDestin, &aSource, string->MaximumLength);
		}
	}
	return status;
}

BOOL kull_m_process_getSid(IN PSID * pSid, IN PKULL_M_MEMORY_HANDLE source)
{
	BOOL status = FALSE;
	BYTE nbAuth;
	DWORD sizeSid;
	KULL_M_MEMORY_HANDLE hOwn = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aDestin = {&nbAuth, &hOwn};
	KULL_M_MEMORY_ADDRESS aSource = {(PBYTE) *pSid + 1, source};

	*pSid = NULL;
	if(kull_m_memory_copy(&aDestin, &aSource, sizeof(BYTE)))
	{
		aSource.address = (PBYTE) aSource.address - 1;
		sizeSid =  4 * nbAuth + 6 + 1 + 1;

		if(aDestin.address = LocalAlloc(LPTR, sizeSid))
		{
			*pSid = (PSID) aDestin.address;
			status = kull_m_memory_copy(&aDestin, &aSource, sizeSid);
		}
	}
	return status;
}

void kull_m_memory_reverseBytes(PBYTE start, DWORD size)
{
	PBYTE lo = start, hi = start + size - 1;
	BYTE swap;
	while (lo < hi)
	{
		swap = *lo;
		*lo++ = *hi;
		*hi-- = swap;
	}
}