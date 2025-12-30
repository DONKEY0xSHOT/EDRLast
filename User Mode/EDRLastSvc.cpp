#include <windows.h>
#include <iostream>
#include <vector>
#include "Shared.h"

int main() {
    std::cout << "[*] Starting EDRLast" << std::endl;

    HANDLE hDevice = CreateFile(L"\\\\.\\EDRLast", GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Failed to open the EDRLast driver. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Diagnostics check
    EDRLastStatus status = { 0 };
    DWORD bytes = 0;
    if (DeviceIoControl(hDevice, IOCTL_EDRLAST_GET_STATUS, NULL, 0, &status, sizeof(status), &bytes, NULL)) {
        std::cout << "\n[+] DRIVER STATUS:" << std::endl;
        std::cout << "    Monitored Address: 0x" << std::hex << status.MonitoredAddress << std::endl;
        std::cout << "    Active Callbacks:  " << std::dec << status.ActiveCallbackCount << std::endl;
        std::cout << "    Watchdog Ticks:    " << status.WatchdogRunCount << std::endl;

        if (status.MonitoredAddress == 0) {
            std::cout << "    [!] WARNING: Driver failed to locate PspCreateProcessNotifyRoutine!" << std::endl;
        }
        else {
            std::cout << "    [*] Monitoring Active" << std::endl;
        }
        std::cout << std::endl;
    }
    else {
        std::cerr << "[!] Failed to query driver status" << std::endl;
    }

    std::cout << "[*] Listening for alerts" << std::endl;

    EDRLastAlert alert;
    while (true) {
        if (DeviceIoControl(hDevice, IOCTL_EDRLAST_WAIT_ALERT,
            NULL, 0, &alert, sizeof(alert), &bytes, NULL)) {

            if (alert.recovered) {
                wchar_t msg[1024];
                swprintf_s(msg, 1024,
                    L"SECURITY ALERT!\n\n"
                    L"Unauthorized callback removal attempt blocked\n\n"
                    L"Driver: %s\n"
                    L"Original Address: 0x%llX\n"
                    L"State: RESTORED",
                    alert.driverName, alert.callbackAddress);

                MessageBox(NULL, msg, L"EDRLast", MB_ICONWARNING | MB_TOPMOST);

                std::wcout << L"[!] ALERT: Restored callback for " << alert.driverName << std::endl;
            }
        }
        else {
            Sleep(500); // Retry delay
        }
    }

    CloseHandle(hDevice);
    return 0;
}
