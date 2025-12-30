#pragma once
#include <ntddk.h>
#include "Shared.h"

// Constants
#define POOL_TAG 'tnS'
#define MAX_CALLBACKS 64
#define WATCHDOG_INTERVAL_MS 100

// Globals
typedef struct _EDRLAST_CONTEXT {
    PVOID PspCreateProcessNotifyRoutine; // Address of the kernel array
    PVOID ShadowCallbacks[MAX_CALLBACKS]; // The trusted state
    KGUARDED_MUTEX StateLock;

    bool StopWatchdog;
    PETHREAD WatchdogThread;
    int WatchdogRunCount; // For diagnostics

    // Notification mechanism
    KEVENT AlertEvent;
    EDRLastAlert PendingAlert;
    bool HasPendingAlert;
    KSPIN_LOCK AlertLock;
} EDRLAST_CONTEXT, * PEDRLAST_CONTEXT;

// Function prototypes
extern "C" DRIVER_INITIALIZE DriverEntry;
extern "C" DRIVER_UNLOAD DriverUnload;
void WatchdogRoutine(PVOID Context);
NTSTATUS LocatePspCreateProcessNotifyRoutine(PVOID* OutAddress);
bool IsDriverLoaded(PVOID Address, wchar_t* OutName, size_t NameSize);