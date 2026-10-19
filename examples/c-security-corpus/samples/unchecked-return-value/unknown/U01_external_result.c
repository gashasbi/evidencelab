/* EvidenceLab synthetic corpus | CWE-252 | UNKNOWN
 * Intent: The return-value contract is missing.
 * Educational fixture; not production code or proof of exploitability.
 */
extern int perform_security_check(void);
int sample(void) {
    return perform_security_check();
    /* UNKNOWN: return-value meaning and failure convention are undocumented */
}
