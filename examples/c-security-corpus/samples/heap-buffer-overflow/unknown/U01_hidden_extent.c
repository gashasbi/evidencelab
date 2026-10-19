/* EvidenceLab synthetic corpus | CWE-122 | UNKNOWN
 * Intent: Pointer-only API hides destination capacity.
 * Educational fixture; not production code or proof of exploitability.
 */
extern void fill_buffer(char *dst, const char *src);
void sample(char *dst, const char *src) {
    fill_buffer(dst, src);
    /* UNKNOWN: destination extent and callee behavior are unavailable */
}
