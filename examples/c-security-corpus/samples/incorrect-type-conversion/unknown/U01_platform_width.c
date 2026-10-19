/* EvidenceLab synthetic corpus | CWE-704 | UNKNOWN
 * Intent: Safety depends on source range and target type width.
 * Educational fixture; not production code or proof of exploitability.
 */
extern long external_length(void);
unsigned sample(void) {
    return (unsigned)external_length();
    /* UNKNOWN: value range and platform width are not specified */
}
