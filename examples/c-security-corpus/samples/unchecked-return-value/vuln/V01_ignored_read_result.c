/* EvidenceLab synthetic corpus | CWE-252 | VULN
 * Intent: Uses a buffer without validating how many bytes were read.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <unistd.h>
extern void process_buffer(const char *);
void sample(int fd) {
    char buf[16];
    (void)read(fd, buf, sizeof buf); /* VULN: result ignored */
    process_buffer(buf);
}
