/* EvidenceLab synthetic corpus | CWE-120 | SAFE
 * Intent: Read is capped at the destination size.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <unistd.h>
void sample(int fd) {
    char buf[16];
    (void)read(fd, buf, sizeof buf);
}
