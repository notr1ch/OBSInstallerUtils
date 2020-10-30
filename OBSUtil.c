/*
    Copyright (C) 2017 Richard Stanway

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <windows.h>
#include <psapi.h>
#include <RestartManager.h>
#include <strsafe.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdbool.h>

#include "nsis/api.h"
#include "nsis/pluginapi.h"

#pragma comment(linker, "/merge:.pdata=.rdata")
#pragma comment(linker, "/merge:.gfids=.rdata")

typedef BOOL (* ENUMPROC)(DWORD, const wchar_t *);

typedef struct ll_s
{
	struct ll_s	*next;
	wchar_t		fileName[MAX_PATH];
} ll_t;

static ll_t inUseFiles;

HMODULE hSelf;

UINT_PTR NSISCallback(enum NSPIM reason)
{
	if (reason == NSPIM_UNLOAD)
	{
		//TODO: Cleanup properly
	}
	return 0;
}

BOOL MatchingProcess(DWORD processID, const wchar_t *match)
{
	wchar_t szPath[1024];

	HANDLE hProcess = OpenProcess (PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processID);
	if (!hProcess)
		return FALSE;

	DWORD len = _countof(szPath);
	if (!QueryFullProcessImageName(hProcess, 0, szPath, &len))
	{
		CloseHandle (hProcess);
		return FALSE;
	}

	CloseHandle (hProcess);

	wchar_t *p = wcsrchr (szPath, '\\');
	if (p)
	{
		*p = 0;
		p++;
	}
	else
		p = szPath;

	_wcslwr (p);

	if (!wcscmp(p, match))
	{
		setuservariable(INST_R0, L"1");
		return TRUE;
	}

	return FALSE;
}

BOOL KillProcessProc(DWORD processID, const wchar_t *match)
{
	wchar_t szPath[1024];

	HANDLE hProcess = OpenProcess (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, processID);
	if (!hProcess)
		return FALSE;

	DWORD len = _countof(szPath);
	if (!QueryFullProcessImageName(hProcess, 0, szPath, &len))
	{
		CloseHandle (hProcess);
		return FALSE;
	}

	_wcslwr (szPath);

	if (wcsstr(szPath, match))
	{
		TerminateProcess (hProcess, -1);
		setuservariable(INST_R0, L"1");
	}

	CloseHandle (hProcess);

	return FALSE;
}

BOOL MatchingDLL(DWORD processID, const wchar_t *match)
{
	wchar_t szPath[1024];
	HMODULE hMods[1024];
	DWORD ret;

	HANDLE hProcess = OpenProcess (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
	if (!hProcess)
		return FALSE;

	DWORD len = _countof(szPath);
	if (!QueryFullProcessImageName(hProcess, 0, szPath, &len))
	{
		CloseHandle (hProcess);
		return FALSE;
	}

	wchar_t *exeName = wcsrchr (szPath, '\\');
	if (exeName)
	{
		*exeName = 0;
		exeName++;
	}
	else
		exeName = szPath;

	if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &ret))
	{
		CloseHandle (hProcess);
		return FALSE;
	}

	for (DWORD i = 0; i < (ret / sizeof(HMODULE)); i++)
	{
		wchar_t szModName[MAX_PATH];
		if (GetModuleFileNameEx(hProcess, hMods[i], szModName, _countof(szModName)))
		{
			wchar_t *p = wcsrchr (szModName, '\\');
			if (p)
			{
				*p = 0;
				p++;
			}
			else
				p = szModName;

			_wcslwr (p);

			if (!wcscmp(p, match))
			{
				setuservariable(INST_R0, exeName);
				CloseHandle (hProcess);
				return TRUE;
			}
		}

	}

	CloseHandle (hProcess);

	return FALSE;
}

BOOL DoEnumProcs(ENUMPROC callback, const wchar_t *targetName)
{
	DWORD processIDs[4096];
	DWORD ret;

	if (!EnumProcesses (processIDs, sizeof(processIDs), &ret))
		goto notfound;

	DWORD numProcs = ret / sizeof(DWORD);
	DWORD i;

	for (i = 0; i < numProcs; i++)
	{
		if (processIDs[i])
		{
			if (callback(processIDs[i], targetName))
			{
				return TRUE;
			}
		}
	}

notfound:
	return FALSE;
}

static bool add_aap_perms(const wchar_t *dir)
{
	PSECURITY_DESCRIPTOR sd = NULL;
	SID *aap_sid = NULL;
	SID *bu_sid = NULL;
	PACL new_dacl1 = NULL;
	PACL new_dacl2 = NULL;
	bool success = false;

	PACL dacl;
	if (GetNamedSecurityInfoW(dir, SE_FILE_OBJECT,
				  DACL_SECURITY_INFORMATION, NULL, NULL, &dacl,
				  NULL, &sd) != ERROR_SUCCESS) {
		goto fail;
	}

	EXPLICIT_ACCESSW ea = {0};
	ea.grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
	ea.grfAccessMode = GRANT_ACCESS;
	ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;

	/* ALL_APP_PACKAGES */
	ConvertStringSidToSidW(L"S-1-15-2-1", &aap_sid);
	ea.Trustee.ptstrName = (wchar_t *)aap_sid;

	if (SetEntriesInAclW(1, &ea, dacl, &new_dacl1) != ERROR_SUCCESS) {
		goto fail;
	}

	ea.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE |
				  GENERIC_EXECUTE;

	/* BUILTIN_USERS */
	ConvertStringSidToSidW(L"S-1-5-32-545", &bu_sid);
	ea.Trustee.ptstrName = (wchar_t *)bu_sid;

	DWORD s = SetEntriesInAclW(1, &ea, new_dacl1, &new_dacl2);
	if (s != ERROR_SUCCESS) {
		goto fail;
	}

	if (SetNamedSecurityInfoW((wchar_t *)dir, SE_FILE_OBJECT,
				  DACL_SECURITY_INFORMATION, NULL, NULL,
				  new_dacl2, NULL) != ERROR_SUCCESS) {
		goto fail;
	}

	success = true;
fail:
	if (sd)
		LocalFree(sd);
	if (new_dacl1)
		LocalFree(new_dacl1);
	if (new_dacl2)
		LocalFree(new_dacl2);
	if (aap_sid)
		LocalFree(aap_sid);
	if (bu_sid)
		LocalFree(bu_sid);
	return success;
}

void __declspec(dllexport) IsProcessRunning(HWND hwndParent, int string_size, 
	LPTSTR variables, stack_t **stacktop,
	extra_parameters *extra, ...)
{
	wchar_t targetName[1024];

	EXDLL_INIT();

	extra->RegisterPluginCallback(hSelf, NSISCallback);

	popstring(targetName);

	if (!targetName[0])
		goto notfound;

	if (DoEnumProcs (MatchingProcess, targetName))
		return;

notfound:
	setuservariable(INST_R0, L"");
}

void __declspec(dllexport) IsDLLLoaded(HWND hwndParent, int string_size, 
	LPTSTR variables, stack_t **stacktop,
	extra_parameters *extra, ...)
{
	wchar_t targetName[1024];

	EXDLL_INIT();

	extra->RegisterPluginCallback(hSelf, NSISCallback);

	popstring(targetName);

	if (!targetName[0])
		goto notfound;

	if (DoEnumProcs (MatchingDLL, targetName))
		return;

notfound:
	setuservariable(INST_R0, L"");
}

void __declspec(dllexport) AddAllApplicationPackages(HWND hwndParent, int string_size,
	LPTSTR variables, stack_t **stacktop,
	extra_parameters *extra, ...)
{
	wchar_t targetDir[MAX_PATH];

	EXDLL_INIT();

	extra->RegisterPluginCallback(hSelf, NSISCallback);

	popstring(targetDir);

	if (!targetDir[0])
		return;

	add_aap_perms(targetDir);
}

void __declspec(dllexport) AddInUseFileCheck(HWND hwndParent, int string_size, 
	LPTSTR variables, stack_t **stacktop,
	extra_parameters *extra, ...)
{
	wchar_t targetName[1024];

	EXDLL_INIT();

	extra->RegisterPluginCallback(hSelf, NSISCallback);

	popstring(targetName);

	if (!targetName[0])
		return;

	if (wcslen(targetName) >= MAX_PATH - 1)
		return;

	ll_t *l;
	l = &inUseFiles;
	while (l->next)
		l = l->next;

	l->next = malloc (sizeof(*l));
	l = l->next;
	l->next = NULL;
	wcscpy (l->fileName, targetName);
}

void __declspec(dllexport) ResetInUseFileChecks(HWND hwndParent, int string_size,
	LPTSTR variables, stack_t** stacktop,
	extra_parameters* extra, ...)
{
	EXDLL_INIT();

	extra->RegisterPluginCallback(hSelf, NSISCallback);

	if (!inUseFiles.next)
		return;

	ll_t *l, *o;

	l = inUseFiles.next;

	while (l->next) {
		o = l;
		l = l->next;
		free (o);
	}
	free (l);

	inUseFiles.next = NULL;
}

void __declspec(dllexport) GetAppNameForInUseFiles(HWND hwndParent, int string_size, 
	LPTSTR variables, stack_t **stacktop,
	extra_parameters *extra, ...)
{
	wchar_t sessionName[256];
	wchar_t message[2048];
	wchar_t **fileNames;

	ll_t *l;

	EXDLL_INIT();

	extra->RegisterPluginCallback(hSelf, NSISCallback);

	message[0] = 0;

	l = &inUseFiles;

	int count = 0;
	int i;

	while (l->next)
	{
		l = l->next;
		count++;
	}

	fileNames = malloc(sizeof(wchar_t *) * (count + 1));

	l = &inUseFiles;
	for (i = 0; i < count; i++)
	{
		l = l->next;
		fileNames[i] = l->fileName;
	}

	fileNames[i] = NULL;

	DWORD rmSession;
	if (RmStartSession(&rmSession, 0, sessionName) == ERROR_SUCCESS)
	{
		if (RmRegisterResources(rmSession, count, fileNames, 0, NULL, 0, NULL) == ERROR_SUCCESS)
		{
			UINT procCount = 16;
			UINT procNeeded = 0;
			DWORD rebootReason;
			int ret;
			RM_PROCESS_INFO *processInfo = malloc (procCount * sizeof(RM_PROCESS_INFO));

retry:

			ret = RmGetList(rmSession, &procNeeded, &procCount, processInfo, &rebootReason);
			if (ret == ERROR_MORE_DATA)
			{
				free (processInfo);
				processInfo = malloc(procNeeded);
				procCount = procNeeded / sizeof(RM_PROCESS_INFO);
				goto retry;
			}
			else if (ret == ERROR_SUCCESS)
			{
				int j;
				int remaining = _countof(message);
				for (i = 0; i < (int)procCount; i++)
				{
					for (j = 0; j < i; j++)
					{
						if (!wcscmp(processInfo[i].strAppName, processInfo[j].strAppName))
						{
							goto skipOne;
						}
					}
					StringCbCatW (message, sizeof(message), processInfo[i].strAppName);
					StringCbCatW (message, sizeof(message), L"\n");
skipOne:;
				}
				setuservariable(INST_R0, message);
			}

			free (processInfo);
		}

		RmEndSession (rmSession);
	}

	free (fileNames);
}

void __declspec(dllexport) KillProcess(HWND hwndParent, int string_size, 
	LPTSTR variables, stack_t **stacktop,
	extra_parameters *extra, ...)
{
	wchar_t targetName[1024];

	EXDLL_INIT();

	extra->RegisterPluginCallback(hSelf, NSISCallback);

	popstring(targetName);

	if (!targetName[0])
		goto notfound;

	if (DoEnumProcs (KillProcessProc, targetName))
		return;

notfound:
	setuservariable(INST_R0, L"");
}

BOOL WINAPI DllMain(HINSTANCE hInst, ULONG ul_reason_for_call, LPVOID lpReserved)
{
	hSelf = (HMODULE)hInst;
	return TRUE;
}
