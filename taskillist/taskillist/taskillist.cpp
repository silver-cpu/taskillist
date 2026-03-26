#define _WIN32_DCOM          // Enables Distributed COM features (needed for remote WMI connections).
#include <windows.h>         // The core Windows API header for handles, types, and system functions.
#include <tlhelp32.h>        // Tool Help Library; used to take snapshots of processes and threads.
#include <psapi.h>           // Process Status API; used to retrieve memory usage and process information
#include <WtsApi32.h>        // Windows Terminal Services API; used for session and process enumeration
#include <winsvc.h>          // Service Control Manager API; used to map processes to Windows Services
#include <iostream>          // Standard input/output stream library
#include <string>            // Standard string and wstring classes
#include <vector>            // Standard dynamic array container
#include <map>               // Standard associative container (key-value pairs)
#include <comdef.h>          // Native COM support for BSTR and VARIANT types
#include <Wbemidl.h>         // WMI (Windows Management Instrumentation) interfaces
#include <iomanip>           // Input/output manipulators for table formatting (setw, left, right)


#pragma comment(lib, "Wtsapi32.lib") // Tells the linker to include the Terminal Services library.
#pragma comment(lib, "wbemuuid.lib") // Tells the linker to include the WMI UUID library


using namespace std;         // Uses the standard namespace to avoid typing 'std::' repeatedly


// --- TASKLIST UTILITY FUNCTIONS ---
// Formatting Memory
wstring FormatWithCommas(SIZE_T value) {
    wstring str = to_wstring(value); // Converts the numerical memory value to a wide string
    // Loops backward through the string, inserting a comma every three digits
    for (int pos = (int)str.length() - 3; pos > 0; pos -= 3) str.insert(pos, L",");
    return str + L" K"; // Appends " K" to signify Kilobytes, matching tasklist output
}


// 1. Function definition: Returns a wide-string (wstring) containing "Domain\User"
// It takes 'hProcess', a handle (reference) to an already-open Windows process
wstring GetProcessUser(HANDLE hProcess) {
    // 2. Initialize a handle for the Access Token to NULL
    // This token is a handle that contains information about who owns the process
    HANDLE hToken = NULL;
    // 3. Call OpenProcessToken: Asks Windows to give us the security badge (hToken) for the process
    // 'TOKEN_QUERY' provides permission to only read the badge, not write
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
        // 4. If the call fails (e.g., the process is a protected system process), return "N/A"
        return L"N/A";
    // 5. Initialize a DWORD (32-bit unsigned integer) to 0
    // This will eventually hold the exact number of bytes needed for the user information
    DWORD size = 0;
    // 6. First call to GetTokenInformation: We pass 'NULL' and '0' for the buffer
    // This trick forces the function to fail, but it populates the 'size' variable with the required byte count
    GetTokenInformation(hToken, TokenUser, NULL, 0, &size);
    // 7. Safety check: If for some reason the size is still 0, we can't proceed
    if (size == 0) {
        // 8. Close the token handle to prevent a memory/handle leak
        CloseHandle(hToken);
        return L"N/A";
    }
    // 9. Use 'malloc' to reserve a block of memory in the heap exactly 'size' bytes large.
    // We cast it to 'PTOKEN_USER', which is a pointer to a structure that holds a User SID (Security ID)
    PTOKEN_USER pUser = (PTOKEN_USER)malloc(size);
    // 10. Second call to GetTokenInformation: Now we provide the actual memory buffer ('pUser') 
    // and the 'size' we just calculated. This actually copies the user's security ID into our memory
    if (!GetTokenInformation(hToken, TokenUser, pUser, size, &size)) {
        // 11. If this second call fails returns N/A, and frees the memory and closes handle
        free(pUser);
        CloseHandle(hToken);
        return L"N/A";
    }
    // 12. Create two pointers (n for name, d for domain) to hold the readable text
    LPWSTR n = NULL, d = NULL;
    // 13. Create two counters to hold the length of the name and domain strings
    DWORD cn = 0, cd = 0;
    // 14. Declare a variable to store the 'type' of account found (User, Group, Alias, etc)
    SID_NAME_USE snu;
    // 15. First call to LookupAccountSidW: We pass the binary SID (from pUser->User.Sid)
    //     NULL/0 for the buffers to get Windows to answer how many characters are the name and domain
    LookupAccountSidW(NULL, pUser->User.Sid, NULL, &cn, NULL, &cd, &snu);
    // 16. Initialize the final result string to "N/A" as a fallback
    wstring res = L"N/A";
    // 17. Check if we received valid lengths for both the username (cn) and the domain (cd)
    if (cn > 0 && cd > 0) {
        // 18. Allocate enough memory for the username string (cn * size of a wide character)
        n = (LPWSTR)malloc(cn * sizeof(WCHAR));
        // 19. Allocate enough memory for the domain name string (cd * size of a wide character)
        d = (LPWSTR)malloc(cd * sizeof(WCHAR));
        // 20. Second call to LookupAccountSidW: Now we provide the allocated buffers 'n' and 'd'
        //     This translates the binary security ID into human-readable text like "User" and "DESKTOP-123"
        if (LookupAccountSidW(NULL, pUser->User.Sid, n, &cn, d, &cd, &snu))
            // 21. Success: Combine the domain, a backslash, and the name into the 'res' string
            res = wstring(d) + L"\\" + wstring(n);
        // 22. Free the wide-char buffers for 'n' (name) and 'd' (domain) after converting them to a wstring
        free(n);
        free(d);
    }
    // 23. Free the original buffer that held the binary SID information.
    free(pUser);
    // 24. Close the token handle; we are finished communicating with the Windows Security subsystem.
    CloseHandle(hToken);
    // 25. Return the final "Domain\User" string to the caller (usually GetAllProcesses).
    return res;
}


// Cacluating CPU Time
// 1. Define function: returns a wide-string (wstring). Takes an open handle to a process (hProcess)
wstring GetProcessCPUTime(HANDLE hProcess) {
    // 2. Declare 4 FILETIME structures: c (creation), e (exit), k (kernel), and u (user mode)
    FILETIME c, e, k, u; 
    // 3. Call GetProcessTimes API: Requests the four timing metrics for the specific process handle
    // If it fails,  returns a default
    if (!GetProcessTimes(hProcess, &c, &e, &k, &u)) return L"0:00:00";
    // 4. Declare two ULARGE_INTEGERs: 64-bit unions that make it easier for 64-bit Windows times
    ULARGE_INTEGER ki, ui; 
    // 5. Map the 32-bit low and high parts of the Kernel FILETIME into the 64-bit ki structure
    ki.LowPart = k.dwLowDateTime; ki.HighPart = k.dwHighDateTime;
    
    // 6. Map the 32-bit low and high parts of the User FILETIME into the 64-bit ui structure
    ui.LowPart = u.dwLowDateTime; ui.HighPart = u.dwHighDateTime;
    // 7. Calculate total seconds: Adds Kernel and User time (QuadPart), then divides by 10,000,000
    // Windows measures time in 100-nanosecond intervals. 10,000,000 intervals = 1 second
    unsigned long ts = (unsigned long)((ki.QuadPart + ui.QuadPart) / 10000000ULL);
    // 8. Create a wide-character buffer array of 32 characters to hold the formatted text.
    wchar_t b[32];
    // 9. Use swprintf to format the seconds into a string: HH : MM : SS
    swprintf(b, 32, L"%lu:%02lu:%02lu", ts / 3600, (ts % 3600) / 60, ts % 60);
    // 10. Return the finished character buffer as a wstring object
    return b;
}



// Finding the Window Title
// 1. Define function: returns a wide-string title. Takes a numerical Process ID
wstring GetWindowTitle(DWORD pid) {
    // 2. Initialize the result 't' to "N/A" in case no window with a title is found
    wstring t = L"N/A";
    // 3. GetTopWindow(NULL): Asks Windows for the handle (HWND) of the very first window at the top of the Z order (NULL)
    HWND h = GetTopWindow(NULL);
    // 4. Start a loop that continues as long as 'h' (the window handle) is not NULL.
    while (h) {
        // 5. Declare a variable to store the ID of the process that created the window we are looking at
        DWORD wPid;
        // 6. GetWindowThreadProcessId: grabs from Windows the PID that owns this specific window handle (h)
        GetWindowThreadProcessId(h, &wPid);
        // 7. Check if the owner of this window (wPid) is the specific process we are looking for (pid)
        if (wPid == pid) {
            // 8. Create a temporary buffer to store the window's title text (up to 256 characters)
            wchar_t b[256];
            // 9. GetWindowTextW: Attempts to copy the title bar text of the window into our buffer 'b'
            // If the length returned is greater than 0 (meaning the window actually has a title):
            if (GetWindowTextW(h, b, 256) > 0) {
                // 10. Store the title in our result variable 't' and 'break' to stop searching
                t = b; 
                break;
            }
        }
        // 11. GetNextWindow: Asks Windows for the next window handle "below" the current one in the Z-order
        h = GetNextWindow(h, GW_HWNDNEXT);
    }
    // 12. Return the title found, or "N/A" if the process has no windows or titleless windows
    return t;
}


// Mapping Processes to Services
// 1. Define function: returns a map where the Key is a PID and the Value is a string of Service Names
map<DWORD, wstring> GetServiceMap() {
    // 2. Initialize an empty map 'm' to hold our findings
    map<DWORD, wstring> m;
    // 3. OpenSCManager: Connects to the Service Control Manager (SCM)
    // 'SC_MANAGER_ENUMERATE_SERVICE' is the specific permission needed to list services
    SC_HANDLE s = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    // 4. if we can't open the Manager, return the empty map
    if (!s) return m;
    // 5. Declare variables bn bytes needed, sc services counted, and rh resume handle
    DWORD bn = 0, sc = 0, rh = 0;
    // 6. First call to EnumServicesStatusExW: We provide NULL/0 for the buffer.
    // This will fail but it fills bn with the number of bytes needed to store the service list
    EnumServicesStatusExW(s, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &bn, &sc, &rh, NULL);
    // 7. Check if there are bytes to be read which means there are services therein
    if (bn > 0) {
        // 8. Create a byte vector 'buf' of size bn to act as our memory buffer
        vector<BYTE> buf(bn);
        // 9. Cast the start of our byte buffer to a pointer type the API understands (LPENUM_SERVICE_STATUS_PROCESSW)
        LPENUM_SERVICE_STATUS_PROCESSW svc = (LPENUM_SERVICE_STATUS_PROCESSW)buf.data();
        // 10. Second call to EnumServicesStatusExW: Now we provide the actual buffer and its size
        // This copies the full list of services, their status, and their PIDs into our 'buf'
        if (EnumServicesStatusExW(s, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buf.data(), (DWORD)buf.size(), &bn, &sc, &rh, NULL)) {
            // 11. Loop through sc: the count of service structures
            for (DWORD i = 0; i < sc; ++i) {
                // 12. Extract the Process ID that is currently hosting this specific service
                DWORD pid = svc[i].ServiceStatusProcess.dwProcessId;
                // 13. If the PID is not 0 (meaning the service is stopped and has no process)
                if (pid != 0) {
                    // 14. If our map already has an entry for this PID (meaning it hosts multiple services):
                    // Add a comma and a space to separate the names                        
                    if (!m[pid].empty()) m[pid] += L", \n                                   ";
                    // 15. Append the name of the service (lpServiceName) to the map entry for that PID
                    m[pid] += svc[i].lpServiceName;
                }
            }
        }
    }
    // 16. CloseServiceHandle: Properly disconnect from the Service Control Manager
    CloseServiceHandle(s);
    // 17. Return the completed map to the caller
    return m;
}



// --- TASKLIST LOGIC ---
// Function: GetAllProcesses
// Purpose: The core TASKLIST logic; displays a formatted table of all running processes
// 1. Start of the 'GetAllProcesses' function; takes two booleans to determine display mode (Verbose or Service)
void GetAllProcesses(bool verbose, bool svc) {
    // 2. Take a "snapshot" of all current processes in the system using the Toolhelp32 API
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    // 3. Check if the snapshot failed; if the handle is INVALID_HANDLE_VALUE, exit the function immediately
    if (hSnap == INVALID_HANDLE_VALUE) return;
    // 4. Create an associative map key:value pairs of PID:"Service Names" to store service to process mappings
    map<DWORD, wstring> sMap;
    // 5. If the 'svc' flag is true, call the GetServiceMap utility to populate our map with service data
    if (svc) sMap = GetServiceMap();
    // 6. Initialize a PROCESSENTRY32W structure, which will hold the data for each process we iterate over
    PROCESSENTRY32W pe = { sizeof(pe) };
    // 7. Header Logic: If 'verbose' is true, print the long, detailed table header and the separator line
    if (verbose) cout << "Image Name                     PID Session Name        Session#    Mem Usage Status          User Name                                              CPU Time Window Title" << endl << "========================= ======== ================ =========== ============ =============== ================================================== ============ ========================================================================" << endl;
    // 8. If 'svc' is true (and not verbose), print the specific header for process names and their mapped services
    else if (svc) cout << "Image Name                     PID Services" << endl << "========================= ======== ============================================" << endl;
    // 9. Otherwise, print the 'Standard View' header (Image Name, PID, Session, and Memory)
    else cout << "Image Name                     PID Session Name        Session#    Mem Usage" << endl << "========================= ======== ================ =========== ============" << endl;
    // 10. Attempt to retrieve information about the first process in the snapshot we took earlier
    if (Process32FirstW(hSnap, &pe)) {
        // 11. Start a 'do-while' loop to process every entry found in the snapshot
        do {
            // 12. Copy the executable filename into a string named 'name'
            wstring name = pe.szExeFile;
            // 13. If the filename is longer than 25 characters, truncate it and add "..." to maintain table alignment
            if (name.length() > 25) name = name.substr(0, 22) + L"...";
            // 14. Variable to hold the Session ID (identifies if it's a Console or RDP/Remote session)
            DWORD sId = 0;
            // 15. Call the Windows API to map the Process ID to its specific Session ID
            ProcessIdToSessionId(pe.th32ProcessID, &sId);
            // 16. Initialize 'sName' (Session Name) to "N/A" and setup buffers for a session query
            wstring sName = L"N/A"; LPWSTR buf = nullptr; DWORD b = 0;
            // 17. Query the terminal server for the "Station Name" (e.g., 'Console' or 'Services') for this Session ID
            if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sId, WTSWinStationName, &buf, &b)) {
                // 18. If the query succeeds, store the buffer in 'sName'; if empty, keep it as "N/A"
                sName = buf; if (sName.empty()) sName = L"N/A";
                // 19. Free the memory that was automatically allocated by the WTS query function
                WTSFreeMemory(buf);
            }
            // 20. Initialize default strings for extended data (Memory, User, CPU Time, Status, and Window Title)
            wstring mem = L"0 K", user = L"N/A", cpu = L"0:00:00", status = (sId == 0 ? L"Unknown" : L"Running"), title = L"N/A";
            // 21. Set the 'User Name' for the System Idle (PID 0) and System (PID 4) processes
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) user = L"NT AUTHORITY\\SYSTEM";
            // 22. Attempt to open a handle to the process with 'Limited Information' access (prevents access-denied errors)
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            // 23. If we successfully got a handle to the process
            if (hProc) {
                PROCESS_MEMORY_COUNTERS pmc;
                // 24. Retrieve memory usage statistics (specifically the 'Working Set Size' in bytes)
                if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc)))
                    // 25. Convert bytes to KB (/1024) and format with commas for readability
                    mem = FormatWithCommas(pmc.WorkingSetSize / 1024);
                // 26. Check if 'verbose' mode is active before performing "expensive" queries
                if (verbose) {
                    // 27. Get the account name (Domain\User) that owns this specific process handle
                    user = GetProcessUser(hProc);
                    // 28. Calculate the total CPU time (Kernel + User) consumed by this process
                    cpu = GetProcessCPUTime(hProc);
                    // 29. Search for any top-level window titles belonging to this PID
                    title = GetWindowTitle(pe.th32ProcessID);
                }
                // 30. Close the process handle immediately to prevent a handle leak
                CloseHandle(hProc);
            }
            // 31. Service View Logic: Print Name, PID, and the list of services from our map
            if (svc) {
                wcout << left << setw(25) << name << " " << right << setw(8) << pe.th32ProcessID << " " << (sMap.count(pe.th32ProcessID) ? sMap[pe.th32ProcessID] : L"N/A") << endl;
            }
            // 32. Verbose View Logic: Print every piece of gathered data into a very wide table row
            else if (verbose) {
                wcout << left << setw(25) << name << " " << right << setw(8) << pe.th32ProcessID << " " << left << setw(16) << sName << " " << right << setw(11) << sId << " " << right << setw(12) << mem << " " << left << setw(15) << status << " " << left << setw(50) << user << " " << right << setw(12) << cpu << " " << title << endl;
            }
            // 33. Standard View Logic: Print only the basic columns found in a standard 'tasklist' command
            else {
                wcout << left << setw(25) << name << " " << right << setw(8) << pe.th32ProcessID << " " << left << setw(16) << sName << " " << right << setw(11) << sId << " " << right << setw(12) << mem << endl;
            }
            // 34. Continue the loop as long as the snapshot contains another process entry
        } while (Process32NextW(hSnap, &pe));
    }
    // 35. Release the snapshot handle to the operating system before finishing
    CloseHandle(hSnap);
}





// --- TASKKILL UTILITIES --- start
// Building the Process Tree
map<DWORD, vector<DWORD>> BuildTree() {
    // 1. Map where key = Parent PID, value = List of Child PIDs
    map<DWORD, vector<DWORD>> tree;
    // 2. Takes a snapshot of all active processes in the system
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe{ sizeof(pe) };
    // 3. Iterates through the snapshot and builds the parent -> child relationship map
    if (Process32First(snap, &pe)) {
        do { 
            tree[pe.th32ParentProcessID].push_back(pe.th32ProcessID); 
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return tree;
}

//Recursive Tree Killing
void KillTree(DWORD pid, HANDLE hServer, bool force, map<DWORD, vector<DWORD>>& tree) {
    // 1. Recursively calls itself for every child of the current PID before killing the current PID
    for (DWORD child : tree[pid]) KillTree(child, hServer, force, tree);
    // 2. Terminates the process once its children have been addressed
    if (WTSTerminateProcess(hServer, pid, force ? 1 : 0))
        wcout << L"SUCCESS: Sent termination signal to the process with PID " << pid << L"." << endl;
    else
        wcout << L"ERROR: Could not terminate process " << pid << L"." << endl;
}


// --- TASKKILL LOGIC ---
// 1. Define the function: 'pids' (IDs to kill), 'images' (names to kill), 'force' (termination type), 'tree' (kill children?), 'remote' (target PC), 'user' 'pass' (login credentials)
void RunTaskKill(vector<DWORD>& pids, vector<wstring>& images, bool force, bool tree, string remote, string user, string pass) {
    // 2. Create a map to link specific Process IDs (DWORD) to their Image Names (wstring) for final processing
    map<DWORD, wstring> targetsToKill;
    // 3. Conditional: If the 'remote' string is empty, the user wants to kill processes on the local computer
    if (remote.empty()) {
        // 4. Define a handle for the local server using a constant that represents the current machine
        HANDLE hServer = WTS_CURRENT_SERVER_HANDLE;
        // 5. Initialize a pointer for the WTS_PROCESS_INFO structure which will store the system's process list
        PWTS_PROCESS_INFOW pInfo = NULL;
        // 6. Declare a DWORD variable to store the total count of processes found by the enumeration function
        DWORD count = 0;
        // 7. Call the Windows API to list every process on the local machine; returns results into pInfo
        if (WTSEnumerateProcessesW(hServer, 0, 1, &pInfo, &count)) {
            // 8. Start a loop that iterates through every process entry returned by the system snapshot
            for (DWORD i = 0; i < count; i++) {
                // 9. Extract the wide-character process name from the current item in the pInfo array
                wstring name = pInfo[i].pProcessName;
                // 10. Extract the unique numerical Process ID from the current item in the pInfo array
                DWORD pid = pInfo[i].ProcessId;
                // 11. Loop through the list of Image Names the user wants to terminate (example: "notepad.exe")
                for (const auto& img : images) {
                    // 12. Compare the running process name to the target name (case-insensitive); if match, add to map
                    if (_wcsicmp(name.c_str(), img.c_str()) == 0) targetsToKill[pid] = name;
                }
                // 13. Loop through the list of specific PIDs the user wants to terminate (example: 1234)
                for (const auto& targetPid : pids) {
                    // 14. If the current running PID matches a target PID, add it to our 'targetsToKill' map
                    if (pid == targetPid) targetsToKill[pid] = name;
                }
            }
            // 15. Free the memory buffer that was automatically allocated by the WTSEnumerateProcessesW function
            WTSFreeMemory(pInfo);
        }
        // 16. Error Check: If our map is still empty, no processes matched the user's input; stop and notify
        if (targetsToKill.empty()) {
            // 17. Output error message to the standard console
            cout << "ERROR: The process not found." << endl;
            // 18. Exit the function as there is nothing left to do
            return;
        }
        // 19. If 'tree' is true, call BuildTree to map parent/child relations; otherwise, create an empty map
        map<DWORD, vector<DWORD>> treeMap = tree ? BuildTree() : map<DWORD, vector<DWORD>>();
        // 20. Iterate through every entry (PID and Name) stored in our final target map.
        for (auto const& [pid, name] : targetsToKill) {
            // 21. Critical Check: PID 0 is the "System Idle Process"; attempting to kill it causes system failure
            if (pid == 0) continue;
            // 22. If tree-kill flag is set, call the recursive KillTree function to wipe out children first
            if (tree) KillTree(pid, hServer, force, treeMap);
            // 23. If not a tree kill, proceed with standard single-process termination
            else {
                // 24. Send the termination signal to the specific PID; '1' is the exit code for the process
                if (WTSTerminateProcess(hServer, pid, 1))
                    // 25. If successful, print a success message showing the name and PID to the user
                    wcout << L"SUCCESS: Sent termination signal to the process \"" << name << L"\" with PID " << pid << L"." << endl;
                else
                    // 26. If the API fails (often due to lack of Administrator rights), print an error message
                    wcout << L"ERROR: Could not terminate process " << pid << L"." << endl;
            }
        }
    }
    // --- REMOTE MODE (WMI) ---
    // 27. Else block: This code runs if the user provided a 'remote' computer name/IP address
    else {
        // 28. Convert the standard 'remote' string to a COM-compatible BSTR (Basic String)
        _bstr_t bstrRemote(remote.c_str());
        // 29. Convert the 'user' string to a BSTR for WMI authentication
        _bstr_t bstrUserAttr(user.c_str());
        // 30. Convert the 'pass' string to a BSTR for WMI authentication
        _bstr_t bstrPassAttr(pass.c_str());
        // 31. Cast BSTRs to wide-character strings for use in credential structures
        wstring wUser = (wchar_t*)bstrUserAttr;
        // 32. Store the password in a wide-string format
        wstring wPassword = (wchar_t*)bstrPassAttr;
        // 33. Initialize the Component Object Model (COM) library for the current thread to allow WMI calls
        HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        // 34. Set the security level for the current process to allow impersonation of the user on remote PCs
        CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        // 35. Declare a pointer for the WMI Locator, the entry point for connecting to WMI namespaces
        IWbemLocator* pLoc = NULL;
        // 36. Create an instance of the WMI Locator object
        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
        // 37. If COM fails to create the locator, uninitialize the library and stop the function
        if (FAILED(hres)) { CoUninitialize(); return; }
        // 38. Declare a pointer for the WMI Services interface (the actual connection)
        IWbemServices* pSvc = NULL;
        // 39. Construct the full WMI network path (eexample: "\\192.168.1.50\root\cimv2")
        wstring networkPath = L"\\\\" + (wstring)((wchar_t*)bstrRemote) + L"\\root\\cimv2";
        // 40. Attempt to connect to the remote machine's WMI service using the constructed path and credentials
        hres = pLoc->ConnectServer(_bstr_t(networkPath.c_str()), bstrUserAttr, bstrPassAttr, 0, NULL, 0, 0, &pSvc);
        // 41. Connection Check: If connection fails (firewall, wrong password, etc.), clean up and exit
        if (FAILED(hres)) {
            // 42. Print the failure and the specific hex error code (HRESULT)
            cout << "Connection failed. HRESULT: 0x" << hex << hres << endl;
            // 43. Release the locator object from memory
            pLoc->Release();
            // 44. Uninitialize COM for this thread
            CoUninitialize();
            // 45. Exit.
            return;
        }
        // 46. Define an authentication structure to pass credentials during WMI method calls
        SEC_WINNT_AUTH_IDENTITY_W authIdent = { 0 };
        // 47. If a username was provided, fill the identity structure with user/pass details
        if (!wUser.empty()) {
            // 48. Set pointer to the username string
            authIdent.User = (unsigned short*)wUser.c_str();
            // 49. Set the length of the username
            authIdent.UserLength = (ULONG)wUser.length();
            // 50. Set pointer to the password string
            authIdent.Password = (unsigned short*)wPassword.c_str();
            // 51. Set the length of the password
            authIdent.PasswordLength = (ULONG)wPassword.length();
            // 52. Specify that the credentials are in Unicode (Wide) format
            authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
            // 53. Apply these credentials to the 'Proxy Blanket' of the service so WMI calls are authorized
            CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, &authIdent, EOAC_NONE);
        }
        // 54. Declare pointers for the WMI class and the definition of the method we want to call
        IWbemClassObject* pClass = NULL;
        IWbemClassObject* pInParamsDefinition = NULL;
        // 55. Retrieve the 'Win32_Process' WMI class definition from the remote machine
        hres = pSvc->GetObject(_bstr_t(L"Win32_Process"), 0, NULL, &pClass, NULL);
        // 56. If class retrieval succeeded, extract the parameters needed for the "Terminate" method
        if (SUCCEEDED(hres)) {
            // 57. Populate pInParamsDefinition with the signature of the 'Terminate' function
            pClass->GetMethod(L"Terminate", 0, &pInParamsDefinition, NULL);
        }
        // 58. Initialize a boolean to track if any target processes were actually found on the remote PC
        bool anyFound = false;
        // 59. Loop through each Image Name provided by the user for termination
        for (const auto& img : images) {
            // 60. Declare an enumerator to store the results of the WMI query
            IEnumWbemClassObject* pEnumerator = NULL;
            // 61. Construct a WQL (WMI Query Language) string to find the process by its filename
            wstring query = L"SELECT * FROM Win32_Process WHERE Name = '" + img + L"'";
            // 62. Execute the WQL query on the remote machine to find all matching process instances
            hres = pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(query.c_str()),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
            // 63. If the query execution started successfully:
            if (SUCCEEDED(hres)) {
                // 64. Apply the proxy credentials to the enumerator so we can read the results
                if (!wUser.empty()) {
                    CoSetProxyBlanket(pEnumerator, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, &authIdent, EOAC_NONE);
                }
                // 65. Pointer for a single WMI object (one specific process)
                IWbemClassObject* pclsObj = NULL;
                // 66. Variable to receive the count of objects returned by Next()
                ULONG uReturn = 0;
                // 67. Iterate through the results; Next() retrieves one process instance at a time
                while (SUCCEEDED(pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn)) && uReturn > 0) {
                    // 68. Mark that we found at least one match
                    anyFound = true;
                    // 69. Variables to hold the WMI path and the PID of the remote process
                    VARIANT vtPath, vtPid;
                    // 70. Get the '__PATH' property (the unique internal WMI address for this process)
                    pclsObj->Get(L"__PATH", 0, &vtPath, NULL, NULL);
                    // 71. Get the 'Handle' property (which is the PID in string format for WMI)
                    pclsObj->Get(L"Handle", 0, &vtPid, NULL, NULL);
                    // 72. Pointer for the actual parameter values we will send to the Terminate method
                    IWbemClassObject* pInParams = NULL;
                    // 73. If the method definition was successfully loaded earlier:
                    if (pInParamsDefinition) {
                        // 74. Create a new instance of the input parameters for this specific call
                        pInParamsDefinition->SpawnInstance(0, &pInParams);
                        // 75. Create a VARIANT to hold the Reason / exit code for the termination
                        VARIANT varReason;
                        // 76. Set variant type to 4byte integer 
                        varReason.vt = VT_I4;
                        // 77. Set the value to 0 (Standard successful exit)
                        varReason.lVal = 0;
                        // 78. Insert the 'Reason' value into the method parameters
                        pInParams->Put(L"Reason", 0, &varReason, 0);
                    }
                    // 79. Remotely execute the 'Terminate' method on the specific process path found
                    hres = pSvc->ExecMethod(vtPath.bstrVal, _bstr_t(L"Terminate"), 0, NULL, pInParams, NULL, NULL);
                    // 80. Success Check: If WMI accepted and executed the termination command
                    if (SUCCEEDED(hres)) {
                        // 81. Print confirmation to the user including the remote PID
                        wcout << L"SUCCESS: The process \"" << img << L"\" with PID " << vtPid.bstrVal << L" has been terminated." << endl;
                    }
                    else {
                        // 82. Print failure message with the hex HRESULT error if the remote kill failed
                        cout << "Terminate failed. HRESULT: 0x" << hex << hres << endl;
                    }
                    // 83. Release the input parameters object to prevent memory leaks
                    if (pInParams) pInParams->Release();
                    // 84. Clear the memory used by the path VARIANT
                    VariantClear(&vtPath);
                    // 85. Clear the memory used by the PID VARIANT
                    VariantClear(&vtPid);
                    // 86. Release the single WMI process object
                    pclsObj->Release();
                }
                // 87. Release the query enumerator object
                pEnumerator->Release();
            }
        }
        // 88. Final Check: If no processes were found on the remote machine after all queries
        if (!anyFound) cout << "No process found with the specified image name(s)." << endl;
        // 89. Release the method definition object
        if (pInParamsDefinition) pInParamsDefinition->Release();
        // 90. Release the WMI class object
        if (pClass) pClass->Release();
        // 91. Release the WMI service connection
        pSvc->Release();
        // 92. Release the WMI locator
        pLoc->Release();
        // 93. Uninitialize COM to clean up the thread before the function ends
        CoUninitialize();
    }
}








// Function: PrintHelp
// Purpose: Outputs the command usage guide to the console.
// Displays the full usage guide, parameter list, and examples for both Tasklist and Taskkill modes
void PrintHelp() {
    cout<< "         _______________________________________" << endl
        << "________|                                       |_______" << endl
        << "\\       |      TASKLIST / TASKKILL Utility      |      /" << endl
        << " \\      |            Matteen Mahfooz            |     /" << endl
        << " /      |_______________________________________|     \\" << endl
        << "/___________)                               (__________\\" << endl
        << "Description:" << endl
        << "    This tool displays a list of currently running processes on the local" << endl
        << "    machine or terminates them by process ID (PID) or image name." << endl << endl
        << "Parameter List (TASKLIST Mode):" << endl
        << "    /V           Displays verbose task information including Status," << endl
        << "                 User Name, CPU Time, and Window Title." << endl
        << "    /SVC         Displays the services hosted in each process." << endl << endl
        << "Parameter List (TASKKILL Mode):" << endl
        << " /KILL           Switch to process termination functionality." << endl
        << "    /PID  id     Specifies the PID of the process to be terminated." << endl
        << "    /IM   name   Specifies the image name of the process to be terminated." << endl
        << "    /F           Specifies to forcefully terminate the process(es)." << endl
        << "    /T           Terminates the specified process and any child processes." << endl << endl
        << "General Parameters:" << endl
        << "    /S    system Specifies the remote system to connect to." << endl
        << "    /?           Displays this help message." << endl << endl
        << "Examples:" << endl
        << "    tasklist" << endl
        << "    tasklist /V" << endl
        << "    tasklist /SVC" << endl
        << "    tasklist /KILL /S remotesystem /U username /PID 1111" << endl
        << "    tasklist /IM notepad.exe /F" << endl
        << "    tasklist /KILL /PID 1230 /PID 1241 /T" << endl;
}


// 1. Entry point of the program: 'argc' counts arguments, 'argv' is an array of the argument strings
int main(int argc, char* argv[]) {
    // 2. Initialize boolean flags: k (kill), f (force), t (tree), v (verbose), s (remote system mode)
    bool k = false, f = false, t = false, v = false, s = false;
    // 3. Create a vector (dynamic list) to store all Process IDs (PIDs) the user wants to target
    vector<DWORD> p;
    // 4. Create a vector to store all Image Names (example: notepad.exe ) the user wants to target
    vector<wstring> im;
    // 5. Initialize strings to hold the remote computer name, the username, and the password
    string remote = "", user = "", pass = "";
    // --- Argument Parsing ---
    // 6. Start a loop at index 1 (skipping the program name itself) to process each command-line argument
    for (int i = 1; i < argc; ++i) {
        // 7. Store the current argument in a string called flag for easier manipulation
        string flag = argv[i];
        // 8. Loop through every character in the current flag string
        for (auto& x : flag)
            // 9. Convert each character to lowercase so the program is not case-sensitive
            x = (char)tolower(x);
        // 10. If the flag matches "/kill", set the kill mode boolean to true
        if (flag == "/kill") k = true;
        // 11. If the flag matches "/f", the user wants to forcefully terminate the process
        else if (flag == "/f") f = true;
        // 12. If the flag matches "/t", the user wants to kill the process and all its child processes
        else if (flag == "/t") t = true;
        // 13. If the flag matches "/v", set verbose mode to true to show detailed process info
        else if (flag == "/v") v = true;
        // 14. If the flag matches "/svc", enable service mode and explicitly turn off verbose mode to avoid conflict
        else if (flag == "/svc") { s = true; v = false; }
        // 15. If the flag is "/s" and there is another argument after it, store that next argument as the remote PC name
        else if (flag == "/s" && i + 1 < argc) remote = argv[++i];
        // 16. If the flag is "/u" and there is another argument after it, store the next argument as the username
        else if (flag == "/u" && i + 1 < argc) user = argv[++i];
        // 17. If the flag is "/p" and there is another argument after it, store the next argument as the password
        else if (flag == "/p" && i + 1 < argc) pass = argv[++i];
        // 18. If the flag is "/pid" and there is a value after it, attempt to process the Process ID
        else if (flag == "/pid" && i + 1 < argc) {
            // 19. Start a try block to catch errors if the user provides text instead of a number for the PID
            try {
                // 20. Convert the next string argument to an integer and add it to our PID vector
                p.push_back((DWORD)stoi(argv[++i]));
            }
            // 21. If 'stoi' fails (e.g., user typed "/pid abc"), catch the error here
            catch (...) {
                // 22. Print an error message and exit the program with a failure code (1).
                cout << "ERROR: Invalid PID specified." << endl; return 1;
            }
        }
        // 23. If the flag is "/im" and there is a name after it, process the Image Name
        else if (flag == "/im" && i + 1 < argc) {
            // 24. Capture the next argument string (the filename)
            string r = argv[++i];
            // 25. Convert the standard string into a wide-character string (wstring) and add it to our list
            im.push_back(wstring(r.begin(), r.end()));
        }
        // 26. If the user asks for help using the "/?" flag:
        else if (flag == "/?") {
            // 27. Stop execution and return 0 (success). This is where you would normally print help text
            PrintHelp();
            return 0;
        }
    }
    // 28. Logic Check: Determine if we should be in "Kill Mode" based on flags or if targets (PIDs/Images) were provided
    if (k || !p.empty() || !im.empty()) {
        // 29. Syntax Check: If we are in kill mode but the user didn't specify WHICH process to kill, it's an error
        if (p.empty() && im.empty()) {
            // 30. Print the syntax error message
            cout << "ERROR: Invalid syntax. /PID or /IM must be specified." << endl;
            // 31. Exit the program with failure code 1
            return 1;
        }
        // 32. Security Check: Remote credentials (/U or /P) are only allowed if a remote system (/S) is specified
        if ((!user.empty() || !pass.empty()) && remote.empty()) {
            // 33. Print the error explaining that /S is missing
            cout << "ERROR: Invalid syntax. /U and /P can be specified only when /S is specified." << endl;
            // 34. Exit the program with failure code 1
            return 1;
        }
        // 35. Credential Pair Check: If a remote user is provided, they MUST also provide a password
        if (!(remote.empty()) && !(user.empty()) && (pass.empty())) {
            // 36. Print the error explaining the missing password
            cout << "ERROR: Invalid syntax. /U user needs a /P password." << endl;
            // 37. Exit the program with failure code 1
            return 1;
        }
        // 38. Execute the Kill Operation: All checks passed, call the main termination logic function
        RunTaskKill(p, im, f, t, remote, user, pass);
    }
    // 39. Default Case: If no "kill" indicators were found, the program acts like 'tasklist'
    else {
        // 40. Call the function to display the process table using the Verbose and Service flags
        GetAllProcesses(v, s);
    }
    // 41. End of the program: Return 0 to the operating system to indicate successful completion
    return 0;
}
