#pragma once

// Unique IOCTLs
#define IOCTL_EDRLAST_WAIT_ALERT    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EDRLAST_GET_STATUS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Structure for alert details
struct EDRLastAlert {
    wchar_t driverName[256];
    unsigned long long callbackAddress;
    bool recovered;
};

// Structure for debugging
struct EDRLastStatus {
    unsigned long long MonitoredAddress; // The array address the driver found
    int ActiveCallbackCount;             // How many callbacks are currently registered
    int WatchdogRunCount;                // Proof the thread is alive
    bool IsMonitoring;                   // True if address was found
    unsigned long long FirstCallback;    // The value of the first callback (for verification)
};