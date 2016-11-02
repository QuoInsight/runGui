/*
  © (ɔ) QuoInsight
*/
#define WINVER 0x501
#define _WIN32_WINNT 0x0501

#include <stdio.h>
#include <strings.h>
#include <windows.h>

  /*missing in winnt.h*/
  #define SID_MAX_SUB_AUTHORITIES (15)
  #define SECURITY_MAX_SID_SIZE (sizeof(SID) - sizeof(DWORD) + (SID_MAX_SUB_AUTHORITIES *sizeof(DWORD)))
  typedef enum {
    WinNullSid = 0,WinWorldSid = 1,WinLocalSid = 2,WinCreatorOwnerSid = 3,WinCreatorGroupSid = 4,WinCreatorOwnerServerSid = 5,WinCreatorGroupServerSid = 6,WinNtAuthoritySid = 7,WinDialupSid = 8,WinNetworkSid = 9,WinBatchSid = 10,WinInteractiveSid = 11,WinServiceSid = 12,WinAnonymousSid = 13,WinProxySid = 14,WinEnterpriseControllersSid = 15,WinSelfSid = 16,WinAuthenticatedUserSid = 17,WinRestrictedCodeSid = 18,WinTerminalServerSid = 19,WinRemoteLogonIdSid = 20,WinLogonIdsSid = 21,WinLocalSystemSid = 22,WinLocalServiceSid = 23,WinNetworkServiceSid = 24,WinBuiltinDomainSid = 25,WinBuiltinAdministratorsSid = 26,WinBuiltinUsersSid = 27,WinBuiltinGuestsSid = 28,WinBuiltinPowerUsersSid = 29,WinBuiltinAccountOperatorsSid = 30,WinBuiltinSystemOperatorsSid = 31,WinBuiltinPrintOperatorsSid = 32,WinBuiltinBackupOperatorsSid = 33,WinBuiltinReplicatorSid = 34,WinBuiltinPreWindows2000CompatibleAccessSid = 35,WinBuiltinRemoteDesktopUsersSid = 36,WinBuiltinNetworkConfigurationOperatorsSid = 37,WinAccountAdministratorSid = 38,WinAccountGuestSid = 39,WinAccountKrbtgtSid = 40,WinAccountDomainAdminsSid = 41,WinAccountDomainUsersSid = 42,WinAccountDomainGuestsSid = 43,WinAccountComputersSid = 44,WinAccountControllersSid = 45,WinAccountCertAdminsSid = 46,WinAccountSchemaAdminsSid = 47,WinAccountEnterpriseAdminsSid = 48,WinAccountPolicyAdminsSid = 49,WinAccountRasAndIasServersSid = 50,WinNTLMAuthenticationSid = 51,WinDigestAuthenticationSid = 52,WinSChannelAuthenticationSid = 53,WinThisOrganizationSid = 54,WinOtherOrganizationSid = 55,WinBuiltinIncomingForestTrustBuildersSid = 56,WinBuiltinPerfMonitoringUsersSid = 57,WinBuiltinPerfLoggingUsersSid = 58,WinBuiltinAuthorizationAccessSid = 59,WinBuiltinTerminalServerLicenseServersSid = 60,WinBuiltinDCOMUsersSid = 61
  } WELL_KNOWN_SID_TYPE;

  #ifdef __cplusplus
   /*
    [https://sourceforge.net/mailarchive/message.php?msg_id=26953058]
    Yes, to use a C function from C++, you need to declare it as "extern "C""
    (unless this gets done for you automatically), because C and C++
    expose there functions to the outside world in slightly different way.

    The reason is that C++ needs to encode some type information in the
    symbol name -- "name decoration" or "name mangling" -- because
    function overloading in C++ means that two completely different functions
    can have the same (undecorated) name.
   */
   extern "C" {
  #endif
    /*new in WinXP wincon.h*/
    //BOOL WINAPI AttachConsole(DWORD);

    /*missing in winbase.h*/
    WINADVAPI WINBOOL WINAPI CreateWellKnownSid(WELL_KNOWN_SID_TYPE WellKnownSidType,PSID DomainSid,PSID pSid,DWORD *cbSid);
  #ifdef __cplusplus
   }
  #endif

/* http://msdn.microsoft.com/en-us/windows/ff420334.aspx */
BOOL IsElevatedAdministrator(HANDLE hInputToken) {
  BOOL fIsAdmin = FALSE;
  HANDLE hTokenToCheck = NULL;
  DWORD lastErr;
  DWORD sidLen = SECURITY_MAX_SID_SIZE;
  BYTE localAdminsGroupSid[SECURITY_MAX_SID_SIZE];

  // If the caller supplies a token, duplicate it as an impersonation token, 
  // because CheckTokenMembership requires an impersonation token.
  if (hInputToken) {
    if ( ! DuplicateToken(hInputToken, SecurityIdentification, &hTokenToCheck) ) {
      lastErr = GetLastError();
      goto CLEANUP;
    }
  }

  if ( !CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, localAdminsGroupSid, &sidLen) ) {
    lastErr = GetLastError();
    goto CLEANUP;
  }

  // Now, determine whether the user is an administrator.
  if (CheckTokenMembership (hTokenToCheck, localAdminsGroupSid, &fIsAdmin)) {
    lastErr = ERROR_SUCCESS;
  } else {
    lastErr = GetLastError();
  }

CLEANUP:
  // Close the impersonation token only if we opened it.
  if (hTokenToCheck) {
    CloseHandle (hTokenToCheck);
    hTokenToCheck = NULL;
  }

  //if (ERROR_SUCCESS != lastErr) throw (lastErr); // "throw" will caused the executable calling lib*.dll during runtime!!
  return (fIsAdmin);
}

/* [itsme86] http://www.linuxquestions.org/questions/programming-9/replace-a-substring-with-another-string-in-c-170076/ */
/*
char *replace(char *str, char *str1, char *str2) {
  static char buffer[4096];
  char *p;
  if ( !( p=strstr(str,str1) ) ) return str; // Is 'str1' even in 'str'?

  //replace only the 1st instance!!
  strncpy(buffer, str, p-str); // Copy characters from 'str' start to 'str1' st$
  buffer[p-str] = '\0';
  sprintf(buffer+(p-str), "%s%s", str2, p+strlen(str1));

  return buffer;
}
*/

int WINAPI WinMain (HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{
  //char tmpStr[255];  sprintf(tmpStr, "[%s]", lpCmd);  MessageBox(0, tmpStr, "lpCmd", 0);

  int i, j, returnVal, argLength=strlen(lpCmd);
  char c0, c1, c2;
  char *p=lpCmd, *pwd;
  /*CREATE_NO_WINDOW is ignored if the application is not a console application*/
  /*CREATE_NO_WINDOW is not supported in Win9x*/
  DWORD dwCreationFlags=CREATE_NO_WINDOW; 
  BOOL showstdout=FALSE, forwardslash=FALSE;

  SHELLEXECUTEINFOA lpExecInfo = {0};
  char exepath[MAX_PATH], param[MAX_PATH];
  //WINDOWPLACEMENT wp; GetWindowPlacement(0, &wp); wp.showCmd;

  if (argLength > 1 && (*p=='/'||*p=='-'||*p==' ') ) {
    for (i=1; i<=argLength; i++, p++) {
      c0=*(p-1);  c1=*p;  c2=*(p+1);
      if (c0=='/'||c0=='-') {
        if (c1=='?') {
          argLength = 0;
          break;
        } else if (strstr(p, "adm")==p||strstr(p, "root")==p||strstr(p, "sudo")==p) {
          if ( strstr(lpCmd,"--ELEVATED--")==NULL && !IsElevatedAdministrator(NULL) ) {
            /*
              http://stackoverflow.com/questions/2426594/starting-a-uac-elevated-process-from-a-non-interactive-service-win32-net-powers
              http://www.eggheadcafe.com/software/aspnet/29620442/how-to-proper-use-sendinp.aspx
              ** In Vista, the official documented way to elevate a process 
              ** is only using the shell API ShellExecute(Ex), 
              ** not CreateProcess or CreateProcessAsUser.
            */
            GetModuleFileName(0, exepath, MAX_PATH);
            lpExecInfo.cbSize = sizeof(SHELLEXECUTEINFOA);
            lpExecInfo.fMask = 0;
            lpExecInfo.hwnd = NULL;
            lpExecInfo.lpVerb = "runas"; /*elevated*/
            lpExecInfo.lpFile = exepath;
            //lpExecInfo.lpDirectory = "";
            //lpCmd = replace(lpCmd, "adm", "");
            sprintf(param, "%s%s", "--ELEVATED-- ", lpCmd);
            lpExecInfo.lpParameters = param;
            lpExecInfo.nShow = nShow;
            ShellExecuteExA(&lpExecInfo);
            return 0;
          }
        } else if (strstr(p, "forwardslash")==p) {
          forwardslash = TRUE;
        } else if (strstr(p, "showconsole")==p) {
          dwCreationFlags = 0;
        } else if (strstr(p, "showstdout")==p) {
          showstdout = TRUE;
        } else if (strstr(p, "pwd=")==p) {
          pwd = p + 4;
          for (j=0; j+i<=argLength; j++){
            if ( *(pwd+j)==' ' ) {
              pwd[j] = '\0';
              SetCurrentDirectory(pwd);
              i=i+j; p=p+j;
              break;
            }
          }
        }
      } else if ((c0==' '||c0=='\0') && c1!=' ' && c1!='/' && c1!='-') {
        /*command starts here*/
        lpCmd = p;
        break;
      }
    }
  }

  if (argLength == 0) {
    MessageBox(0, "usage: runGui.exe [/adm] [/pwd=path] [/showstdout] [/showconsole] [/forwardslash] executable_path [parameters]", "usage", 0);
    return 1;
  }

  if (forwardslash) {
    for (i=i; i<=argLength; i++, p++) {
      if (*p=='\\') {
        *p='/';
      }
    }
  }

  SECURITY_ATTRIBUTES sa;
  sa.nLength=12;
  sa.lpSecurityDescriptor=0;
  sa.bInheritHandle=TRUE;

  HANDLE hReadPipe1, hWritePipe1;
  returnVal = CreatePipe(&hReadPipe1,&hWritePipe1,&sa,0);

  STARTUPINFO si = { sizeof(STARTUPINFO) };
  si.dwFlags = STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;
  si.wShowWindow = SW_SHOW; /*hide console with dwCreationFlags instead*/
  if (dwCreationFlags==0) si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  si.hStdError = hWritePipe1;
  if (showstdout) {
    si.hStdOutput = hWritePipe1;
  } else if (dwCreationFlags==0) {
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  } else {
    si.hStdOutput = CreateFile("nul", GENERIC_READ|GENERIC_WRITE,
      FILE_SHARE_READ|FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
  }
  PROCESS_INFORMATION pi;
  returnVal = CreateProcess(0, lpCmd, 0, 0, 1, dwCreationFlags, NULL, NULL, &si, &pi);
  if (returnVal == 0) {
    MessageBox(0, lpCmd, "runGUI: Invalid Command !!", MB_OK|MB_ICONEXCLAMATION);
    return 1;
  }

  DWORD dwExitCode = STILL_ACTIVE;
  char Buff[1024];
  unsigned long lBytesRead;
  do {
    returnVal= GetExitCodeProcess(pi.hProcess, &dwExitCode);
    returnVal = PeekNamedPipe(hReadPipe1,Buff,1024,&lBytesRead,0,0);
    if (!returnVal) break;
    if (lBytesRead) {
      returnVal=ReadFile(hReadPipe1,Buff,lBytesRead,&lBytesRead,0);
      if (!returnVal || returnVal<=0) break;
      Buff[lBytesRead] = '\0';
      MessageBox(0, Buff, lpCmd, 0);
    }
    Sleep(100);
  } while(dwExitCode == STILL_ACTIVE || lBytesRead > 0);

  CloseHandle(hReadPipe1);
  CloseHandle(hWritePipe1);
  return 0;

  //MessageBox(0, GetCommandLine(), "command_line", MB_OK);
  AllocConsole(); /*AttachConsole( (DWORD)-1 ); /*ATTACH_PARENT_PROCESS */
  WriteConsoleW( GetStdHandle( STD_OUTPUT_HANDLE), L"Hello, World!\n", 14, NULL, NULL );
  Sleep(1000);
  FreeConsole();
  return 0;
}

