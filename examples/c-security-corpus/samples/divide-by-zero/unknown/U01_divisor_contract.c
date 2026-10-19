/* EvidenceLab synthetic corpus | CWE-369 | UNKNOWN
 * Intent: Safety depends on the external function contract.
 * Educational fixture; not production code or proof of exploitability.
 */
extern int nonzero_divisor(void);
int sample(int value) {
    return value / nonzero_divisor();
    /* UNKNOWN: function contract and failure behavior are absent */
}
