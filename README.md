# EDRLast
**EDRLast** is a PoC designed to detect and actively block the technique that's used by tools like **EDRSandblast**, which utilize BYOVD to "blind" EDRs by unregistering their kernel callbacks.

## Why EDRLast?

Anti-EDR tools locate kernel arrays and zero out the pointers of security drivers, which makes the EDR stops receiving critical events.
**EDRLast** ensures that these callbacks remain unchanged!

## Tested Environment
Tested on Windows 10 22H2 against EDRSandblast (Kernel Mode unhooking).
<img width="720" height="225" alt="image" src="https://github.com/user-attachments/assets/fec61ffe-2e61-4448-bae0-cb346049f897" />


## How It Works
1.  **Pattern Scanning:**
    Upon loading, the driver locates the `PspCreateProcessNotifyRoutine` array. It uses heuristic scanning to reliably find the structure.

2.  **State Tracking:**
    It maintains a trusted table of active callbacks. When a legitimate driver registers a callback, EDRLast adds it to this protected list.

3.  **The Callback Heuristic:**
    A watchdog thread compares the kernel array against the trusted table. It triggers an alert only if:
    * A callback pointer has been removed (nulled) or disabled
    **BUT** the driver owning that callback is *still loaded* in memory.
    This distinguishes malicious tampering from legitimate driver unloading : )

4.  **"Healing":**
    If tampering is detected, EDRLast restores the original callback pointer to the kernel array.
