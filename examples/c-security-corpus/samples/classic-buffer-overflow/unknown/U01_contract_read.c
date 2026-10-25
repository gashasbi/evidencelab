/* EvidenceLab synthetic corpus | CWE-120 | UNKNOWN
 * Intent: Actual storage size is not visible.
 * Educational fixture; not production code or proof of exploitability.
 */
extern long bounded_read(int fd, char *dst, unsigned capacity);
void sample(int fd, char *dst, unsigned capacity) {
    (void)bounded_read(fd, dst, capacity);
    /* UNKNOWN: caller's capacity may not match actual storage */
}
