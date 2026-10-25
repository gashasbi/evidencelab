/* EvidenceLab synthetic corpus | CWE-327 | UNKNOWN
 * Intent: Security depends on the external cryptographic provider.
 * Educational fixture; not production code or proof of exploitability.
 */
extern int secure_hash(const void *, unsigned long, void *, unsigned long);
int sample(const void *input, unsigned long n, void *out, unsigned long cap) {
    return secure_hash(input, n, out, cap);
    /* UNKNOWN: algorithm and configuration are not visible */
}
