/* EvidenceLab synthetic corpus | CWE-476 | UNKNOWN
 * Intent: Pointer validity depends on an external contract.
 * Educational fixture; not production code or proof of exploitability.
 */
extern int read_value(const int *nonnull_value);
int sample(const int *value) {
    return read_value(value);
    /* UNKNOWN: caller's pointer guarantee is undocumented */
}
