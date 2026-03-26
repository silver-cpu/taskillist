# ⚙️ Advanced Tasklist / Taskkill Utility (Windows)

A powerful, from-scratch reimplementation of the Windows **`tasklist`** and **`taskkill`** utilities in modern C++, with extended capabilities such as:

* 🔍 Deep process inspection (user, CPU time, window titles)
* 🔗 Service-to-process mapping
* 🌳 Recursive process tree termination
* 🌐 Remote process termination via WMI
* 📊 Clean, formatted console output

---

## 🚀 Features

### 🖥️ Tasklist Mode

* Display all running processes
* Show:

  * Process Name
  * PID
  * Session Name & ID
  * Memory Usage (formatted with commas)
* **Verbose Mode (`/V`) includes:**

  * User (Domain\User)
  * CPU Time (HH:MM:SS)
  * Window Title
  * Process Status

### 🧩 Service Mapping (`/SVC`)

* Maps Windows services to their hosting processes
* Displays multiple services per process
* Uses Service Control Manager APIs

### 💀 Taskkill Mode

* Kill processes by:

  * PID (`/PID`)
  * Image name (`/IM`)
* Optional flags:

  * `/F` → Force termination
  * `/T` → Kill entire process tree

### 🌳 Process Tree Termination

* Recursively finds and terminates child processes
* Prevents orphaned processes

### 🌐 Remote Execution (WMI)

* Kill processes on remote machines
* Authenticated via:

  * `/S` → remote system
  * `/U` → username
  * `/P` → password
* Uses COM + WMI (`Win32_Process::Terminate`)

---

## 🛠️ Tech Stack

* **Language:** C++
* **APIs Used:**

  * Windows API (Win32)
  * ToolHelp32 (process snapshots)
  * PSAPI (memory usage)
  * WTS API (sessions & processes)
  * SCM (Service Control Manager)
  * COM + WMI (remote execution)

---

## 📦 Build Instructions

### Requirements

* Windows OS
* C++ Compiler (MSVC recommended)
* Visual Studio or `cl.exe`

### Compile (MSVC)

```bash
cl main.cpp /EHsc /std:c++17 /link Wtsapi32.lib wbemuuid.lib
```

---

## ▶️ Usage

### 🔹 Basic Task Listing

```bash
tasklist
```

### 🔹 Verbose Output

```bash
tasklist /V
```

### 🔹 Show Services

```bash
tasklist /SVC
```

---

### 🔹 Kill by PID

```bash
tasklist /KILL /PID 1234
```

### 🔹 Kill by Image Name

```bash
tasklist /KILL /IM notepad.exe
```

### 🔹 Force Kill

```bash
tasklist /KILL /IM chrome.exe /F
```

### 🔹 Kill Process Tree

```bash
tasklist /KILL /PID 1234 /T
```

---

### 🌐 Remote Kill

```bash
tasklist /KILL /S 192.168.1.10 /U username /P password /IM notepad.exe
```

---

## 📊 Example Output

### Standard Mode

```
Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
notepad.exe                  1234 Console                     1       12,340 K
```

### Verbose Mode

```
Image Name                     PID Session Name        Session#    Mem Usage Status          User Name                     CPU Time Window Title
notepad.exe                  1234 Console                     1       12,340 K Running         DESKTOP\User                 0:00:05 Untitled - Notepad
```

---

## 🧠 How It Works

### 🔍 Process Enumeration

* Uses `CreateToolhelp32Snapshot`
* Iterates with `Process32First/Next`

### 👤 User Resolution

* Extracts process token via `OpenProcessToken`
* Converts SID → `Domain\User` using `LookupAccountSid`

### ⏱ CPU Time Calculation

* Combines kernel + user time from `GetProcessTimes`
* Converts from 100-nanosecond intervals → seconds

### 🪟 Window Titles

* Iterates all top-level windows
* Matches PID → retrieves title via `GetWindowText`

### 🔗 Service Mapping

* Queries SCM via `EnumServicesStatusEx`
* Maps services → hosting PIDs

### 🌳 Process Tree

* Builds parent-child relationships
* Recursively terminates children before parent

### 🌐 Remote Execution

* Initializes COM (`CoInitializeEx`)
* Connects to WMI (`IWbemLocator`)
* Executes:

  ```
  Win32_Process::Terminate
  ```

---

## ⚠️ Notes & Limitations

* Requires **Administrator privileges** for:

  * Killing protected/system processes
  * Accessing some process details
* Remote execution depends on:

  * WMI being enabled
  * Firewall configuration
  * Correct credentials
* Some system processes will return:

  ```
  Access Denied / N/A
  ```

---

## 📌 Why This Project Is Interesting

This isn’t just a wrapper around system commands—it’s a **low-level reimplementation** of Windows process management using native APIs.

It demonstrates:

* Deep understanding of Windows internals
* COM + WMI integration
* Memory and handle management
* System-level programming in C++

---

## 🙌 Author

**Matteen Mahfooz**

---

## ⭐ Contributing

Pull requests are welcome. Fork it if you like.

---

## 💡 Future Improvements

* [ ] Add filtering (by name, memory, user)
* [ ] Export to JSON/CSV
* [ ] Real-time monitoring mode
* [ ] GUI version
* [ ] Safer kill confirmation prompts

---

## 🧪 Disclaimer

This tool can terminate critical system processes.
Use responsibly.
