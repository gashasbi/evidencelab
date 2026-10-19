/* EvidenceLab synthetic corpus | CWE-330 | UNKNOWN
 * Intent: Randomness quality depends on an external wrapper.
 * Educational fixture; not production code or proof of exploitability.
 */
extern int secure_random(void *buffer, unsigned long length);
int sample(void *buffer, unsigned long length) {
    return secure_random(buffer, length);
    /* UNKNOWN: entropy source and implementation are absent */
}
