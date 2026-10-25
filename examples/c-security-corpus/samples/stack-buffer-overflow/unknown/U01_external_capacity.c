/* EvidenceLab synthetic corpus | CWE-121 | UNKNOWN
 * Intent: Safety depends on external capacity and function contracts.
 * Educational fixture; not production code or proof of exploitability.
 */
extern void copy_with_contract(char *dst, const char *src, unsigned capacity);
void sample(char *dst, const char *input, unsigned claimed_capacity) {
    copy_with_contract(dst, input, claimed_capacity);
    /* UNKNOWN: actual destination capacity and callee contract are absent */
}
