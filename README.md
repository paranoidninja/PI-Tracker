# PI-Tracker
A tracker DLL which enables 'NTAPI->Syscall' tracking whenever it is loaded. It calls 'NtSetInformationProcess' API call with a callback hook and 'ProcessInstrumentationCallback' class to track all syscalls being performed via the userland.
