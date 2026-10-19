/* EvidenceLab synthetic corpus | CWE-252 | SAFE
 * Intent: Processes only the bytes reported by the read operation.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <unistd.h>
extern void process_bytes(const char *, long);
void sample(int fd) {
    char buf[16];
    ssize_t n = read(fd, buf, sizeof buf);
    if (n > 0) process_bytes(buf, n);
}
