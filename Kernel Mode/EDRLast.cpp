#include "EDRLast.h"

EDRLAST_CONTEXT g_Ctx = { 0 };

// Check if memory range is valid kernel memory
bool IsValidKernelPointer(PVOID Ptr) {
    if (!Ptr) return false;
    ULONG_PTR addr = (ULONG_PTR)Ptr;
    
    // Basic check for x64 kernel pointer range (ffff0000...)
    return (addr > 0xFFFF000000000000);
}

// Check if a driver is loaded (Basic IsAddressValid check)
bool IsDriverLoaded(PVOID Address, wchar_t* OutName, size_t NameSize) {
    if (!Address || !MmIsAddressValid(Address)) return false;
    if (OutName) wcscpy_s(OutName, NameSize / sizeof(wchar_t), L"Unknown Driver");
    return true;
}

// Robust Scanner
NTSTATUS LocatePspCreateProcessNotifyRoutine(PVOID* OutAddress) {
    UNICODE_STRING funcName = RTL_CONSTANT_STRING(L"PsSetCreateProcessNotifyRoutine");
    PVOID pFunc = MmGetSystemRoutineAddress(&funcName);
    if (!pFunc) return STATUS_NOT_FOUND;

    unsigned char* pCode = (unsigned char*)pFunc;

    // Follow Thunks (JMP/CALL)
    // Scan first 32 bytes for JMP (0xE9) or CALL (0xE8)
    for (int i = 0; i < 32; i++) {
        if (pCode[i] == 0xE9 || pCode[i] == 0xE8) {
            long offset = *(long*)(pCode + i + 1);
            PVOID target = (PVOID)(pCode + i + 5 + offset);
            if (MmIsAddressValid(target)) {
                pCode = (unsigned char*)target;
                break; // Jump "taken", start scanning target
            }
        }
    }

    // Scan for LEA instruction
    for (int i = 0; i < 512; i++) {
        if (!MmIsAddressValid(pCode + i + 7)) break;

        // Check for LEA opcode
        if ((pCode[i] == 0x48 || pCode[i] == 0x4C) && pCode[i + 1] == 0x8D) {

            // Check ModRM for RIP-relative addressing
            unsigned char modRM = pCode[i + 2];
            if ((modRM & 0xC7) == 0x05) {
                long offset = *(long*)(pCode + i + 3);
                PVOID candidate = (PVOID)(pCode + i + 7 + offset);

                if (MmIsAddressValid(candidate)) {

                    // Validation - Does this candidate look like the Notify Routine Array?
                    // If we see valid kernel pointers, it's likely the one : )
                    PVOID* table = (PVOID*)candidate;
                    int validPointersFound = 0;
                    for (int k = 0; k < 8; k++) {
                        if (MmIsAddressValid(table + k)) {
                            PVOID val = (PVOID)((ULONG_PTR)table[k] & ~0xF); // Unmask
                            if (IsValidKernelPointer(val)) {
                                validPointersFound++;
                            }
                        }
                    }

                    // If we found valid callbacks inside, we trust this address
                    if (validPointersFound > 0) {
                        *OutAddress = candidate;
                        return STATUS_SUCCESS;
                    }
                }
            }
        }
    }
    return STATUS_NOT_FOUND;
}

void WatchdogRoutine(PVOID Context) {
    LARGE_INTEGER interval;
    interval.QuadPart = -10000LL * WATCHDOG_INTERVAL_MS;

    while (!g_Ctx.StopWatchdog) {
        g_Ctx.WatchdogRunCount++;

        if (g_Ctx.PspCreateProcessNotifyRoutine) {
            KeAcquireGuardedMutex(&g_Ctx.StateLock);

            PVOID* osCallbacks = (PVOID*)g_Ctx.PspCreateProcessNotifyRoutine;

            for (int i = 0; i < MAX_CALLBACKS; i++) {
                PVOID rawVal = osCallbacks[i];
                PVOID osVal = (PVOID)((ULONG_PTR)rawVal & ~0xF);
                PVOID shadowVal = g_Ctx.ShadowCallbacks[i];

                // Case 1: New driver
                if (osVal != NULL && shadowVal == NULL) {
                    g_Ctx.ShadowCallbacks[i] = osVal;
                }
                // Case 2: Detect callback removal
                else if (osVal == NULL && shadowVal != NULL) {
                    wchar_t driverName[256];
                    if (IsDriverLoaded(shadowVal, driverName, sizeof(driverName))) {

                        // Rrestore the pointer
                        osCallbacks[i] = shadowVal;

                        // Alert!
                        KLOCK_QUEUE_HANDLE lh;
                        KeAcquireInStackQueuedSpinLock(&g_Ctx.AlertLock, &lh);
                        if (!g_Ctx.HasPendingAlert) {
                            g_Ctx.PendingAlert.callbackAddress = (unsigned long long)shadowVal;
                            g_Ctx.PendingAlert.recovered = true;
                            wcscpy_s(g_Ctx.PendingAlert.driverName, driverName);
                            g_Ctx.HasPendingAlert = true;
                            KeSetEvent(&g_Ctx.AlertEvent, 0, FALSE);
                        }
                        KeReleaseInStackQueuedSpinLock(&lh);
                    }
                    else {
                        g_Ctx.ShadowCallbacks[i] = NULL;
                    }
                }
            }
            KeReleaseGuardedMutex(&g_Ctx.StateLock);
        }

        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
}

NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_EDRLAST_WAIT_ALERT:
        KeWaitForSingleObject(&g_Ctx.AlertEvent, Executive, KernelMode, FALSE, NULL);
        {
            KLOCK_QUEUE_HANDLE lh;
            KeAcquireInStackQueuedSpinLock(&g_Ctx.AlertLock, &lh);
            if (g_Ctx.HasPendingAlert) {
                EDRLastAlert* userBuff = (EDRLastAlert*)Irp->AssociatedIrp.SystemBuffer;
                if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(EDRLastAlert)) {
                    *userBuff = g_Ctx.PendingAlert;
                    info = sizeof(EDRLastAlert);
                    g_Ctx.HasPendingAlert = false;
                    KeClearEvent(&g_Ctx.AlertEvent);
                }
                else { status = STATUS_BUFFER_TOO_SMALL; }
            }
            KeReleaseInStackQueuedSpinLock(&lh);
        }
        break;

    // Diagnostic Handler
    case IOCTL_EDRLAST_GET_STATUS:
    {
        EDRLastStatus* statusBuff = (EDRLastStatus*)Irp->AssociatedIrp.SystemBuffer;
        if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(EDRLastStatus)) {
            statusBuff->MonitoredAddress = (unsigned long long)g_Ctx.PspCreateProcessNotifyRoutine;
            statusBuff->WatchdogRunCount = g_Ctx.WatchdogRunCount;
            statusBuff->IsMonitoring = (g_Ctx.PspCreateProcessNotifyRoutine != NULL);
            statusBuff->ActiveCallbackCount = 0;
            statusBuff->FirstCallback = 0;

            // Take a snapshot of the state
            if (g_Ctx.PspCreateProcessNotifyRoutine) {
                PVOID* arr = (PVOID*)g_Ctx.PspCreateProcessNotifyRoutine;
                if (MmIsAddressValid(arr)) {
                    statusBuff->FirstCallback = (unsigned long long)arr[0];
                    for (int k = 0; k < MAX_CALLBACKS; k++) if (arr[k]) statusBuff->ActiveCallbackCount++;
                }
            }

            info = sizeof(EDRLastStatus);
        }
        else { status = STATUS_BUFFER_TOO_SMALL; }
    }
    break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// DriverEntry & Unload
NTSTATUS CreateClose(PDEVICE_OBJECT, PIRP Irp) {
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    LocatePspCreateProcessNotifyRoutine(&g_Ctx.PspCreateProcessNotifyRoutine);

    KeInitializeGuardedMutex(&g_Ctx.StateLock);
    KeInitializeSpinLock(&g_Ctx.AlertLock);
    KeInitializeEvent(&g_Ctx.AlertEvent, NotificationEvent, FALSE);

    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\EDRLast");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\EDRLast");
    PDEVICE_OBJECT devObj;
    IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &devObj);
    IoCreateSymbolicLink(&symLink, &devName);

    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    HANDLE hThread;
    PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, WatchdogRoutine, NULL);
    ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, (PVOID*)&g_Ctx.WatchdogThread, NULL);
    ZwClose(hThread);

    return STATUS_SUCCESS;
}

extern "C" VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    g_Ctx.StopWatchdog = true;
    KeWaitForSingleObject(g_Ctx.WatchdogThread, Executive, KernelMode, FALSE, NULL);
    ObDereferenceObject(g_Ctx.WatchdogThread);
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\EDRLast");
    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(DriverObject->DeviceObject);
}