/* EvidenceLab synthetic corpus | CWE-120 | VULN
 * Intent: Read length can exceed the destination buffer.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <unistd.h>
void sample(int fd, unsigned count) {
    char buf[16];
    (void)read(fd, buf, count); /* VULN: count may exceed buf */
}
