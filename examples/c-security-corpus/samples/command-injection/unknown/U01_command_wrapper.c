/* EvidenceLab synthetic corpus | CWE-78 | UNKNOWN
 * Intent: Command wrapper implementation is unavailable.
 * Educational fixture; not production code or proof of exploitability.
 */
extern int run_command(const char *name, const char *argument);
int sample(const char *user) {
    return run_command("tool", user);
    /* UNKNOWN: shell use and escaping behavior are undocumented */
}
