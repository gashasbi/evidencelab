/* EvidenceLab synthetic corpus | CWE-362 | VULN
 * Intent: Checks a pathname before a separate open operation.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
int sample(const char *path) {
    if (access(path, W_OK) != 0) return -1;
    int fd = open(path, O_WRONLY); /* VULN: file may change after check */
    if (fd < 0) return -1;
    close(fd);
    return 0;
}
