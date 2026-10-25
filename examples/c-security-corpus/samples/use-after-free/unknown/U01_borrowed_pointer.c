/* EvidenceLab synthetic corpus | CWE-416 | UNKNOWN
 * Intent: Lifetime of an externally borrowed pointer is unspecified.
 * Educational fixture; not production code or proof of exploitability.
 */
extern const char *get_borrowed_string(void);
void sample(void) {
    const char *p = get_borrowed_string();
    /* UNKNOWN: lifetime and ownership contract are missing */
    (void)p;
}
