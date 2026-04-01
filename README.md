# AMD-SSG-Kernel-File-IO

# Information
This is not a known exploit nor is it patched yet. amdssg64.sys (AMD Radeon SSG / LiquidFlash driver) exposes three IOCTLs that allow usermode applications to perform kernel-level file I/O operations. The driver uses `ZwCreateFile`, `ZwReadFile`, `ZwWriteFile`, and `ZwClose` internally, giving any usermode caller the ability to open, read, write, and close files through Ring 0 — bypassing usermode file access restrictions entirely.

The driver is a WDF (KMDF) PnP driver originally built for AMD's Radeon SSG (Solid State Graphics) PCIe cards featuring onboard flash storage. It was designed to let AMD's usermode software perform direct file I/O through the kernel for high-bandwidth data transfers to the SSG's local storage. However, the IOCTL interface has no access control — any process that can open the device handle can issue file operations as SYSTEM.

The driver validates that AMD SSG hardware (`DEV_7300` or `DEV_6862`) is present via `IoGetDeviceInterfaces` before processing file operations. This requires a system with the matching hardware or an older version of Windows where the driver can be loaded and the device interface registered.

**Tested on Windows 10 22H2.** Newer versions of Windows may block loading the driver due to driver signing policy changes.

# How To Use
1. Download the repository and compile with CMake (MinGW or MSVC)
2. Copy `amdssg64.sys` to `C:\Windows\System32\drivers\`
3. Load the driver:
```
sc create SSG binpath="C:\Windows\System32\drivers\amdssg64.sys" type=kernel
sc start SSG
```
4. Run the compiled executable

# Driver Details

**Driver:** amdssg64.sys v1.0.2016.05106 (Built June 15, 2018)

**Device Interface GUID:** `{EBD5EFC4-27AD-4CD0-AC13-6279ED7DB699}`

**Hardware Requirement:** AMD Radeon SSG — PCI `DEV_7300` (rev `0xCC`) or `DEV_6862`

# amdssg64.sys

**IOCTL Dispatch (EvtIoDeviceControl)**
```
switch ( a5 )
{
  case 0x222828:                                // Open File
    if ( !v8 || !v10 || a4 != 576 || !v11 || a3 != 640 )
      goto LABEL_25;
    result = BuildFile(v8, v10, v11);
    goto LABEL_23;
  case 0x222830:                                // Close File
    if ( !v8 || !v10 || a4 != 64 || !v11 || a3 != 128 )
      goto LABEL_25;
    result = CloseFile(v8);
    goto LABEL_23;
  case 0x222834:                                // Read/Write File
    if ( v8 && v10 && a4 == 64 && v11 && a3 == 128 )
    {
      result = ReadWriteFile(v8, a2, v10, v11);
      goto LABEL_23;
    }
    goto LABEL_25;
}
```

**BuildFile — ZwCreateFile Wrapper (IOCTL 0x222828)**
```
RtlInitUnicodeString(&DestinationString, L"\\??\\");
RtlInitUnicodeString(&Source, v4 + 4);
RtlAppendUnicodeStringToString(&Destination, &DestinationString);
RtlAppendUnicodeStringToString(&Destination, &Source);

v6 = ZwCreateFile(
       &FileHandle,
       v13,                    // ACCESS_MASK from input flags
       &ObjectAttributes,
       &IoStatusBlock,
       &AllocationSize,
       0x80u,                  // FILE_ATTRIBUTE_NORMAL
       0,
       CreateDisposition,      // FILE_OPEN or FILE_OPEN_IF
       0x48u,
       0LL,
       0);
```

**ReadWriteFile — ZwReadFile/ZwWriteFile (IOCTL 0x222834)**
```
if ( *(_DWORD *)(a3 + 8) == 1 )
  v13 = ZwReadFile(v12, 0LL, ApcRoutine, v11, IoStatusBlock, Buffer, Length, &ByteOffset, 0LL);
else
  v13 = ZwWriteFile(v12, 0LL, ApcRoutine, v11, IoStatusBlock, Buffer, Length, &ByteOffset, 0LL);
```

**Hardware Validation**
```
IoGetDeviceInterfaces(&InterfaceClassGuid, 0LL, 0, &SymbolicLinkList);
// Searches for DEV_7300 (rev CC) and DEV_6862 in device interface strings
wcscpy(SubStr, L"DEV_");
ultow_s(v5, &SubStr[4], 5uLL, 16);
v8 = wcsstr(v1, SubStr);
```

**Process Cleanup (NotifyRoutine)**
```
// Registered via PsSetCreateProcessNotifyRoutine
// On process exit: walks linked list, closes all kernel handles owned by that PID
if ( (HANDLE)*(v7 - 2) == ProcessId )
{
  // Unlink from list
  v11 = (void *)v8[2];
  if ( v11 )
    ZwClose(v11);
}
```

# Possibilities
- Read/write any file on disk as SYSTEM from usermode
- Bypass ACLs and file security descriptors
- Access locked/in-use files through kernel handles
- Async I/O via APC completion routines
