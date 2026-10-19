/* EvidenceLab synthetic corpus | CWE-22 | UNKNOWN
 * Intent: Containment depends on an external filesystem API.
 * Educational fixture; not production code or proof of exploitability.
 */
extern int open_sandboxed_file(const char *relative_path);
int sample(const char *path) {
    return open_sandboxed_file(path);
    /* UNKNOWN: sandbox and symlink guarantees are undocumented */
}
