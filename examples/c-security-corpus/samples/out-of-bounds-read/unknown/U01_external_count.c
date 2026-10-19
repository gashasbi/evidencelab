/* EvidenceLab synthetic corpus | CWE-125 | UNKNOWN
 * Intent: The buffer extent and index contract are missing.
 * Educational fixture; not production code or proof of exploitability.
 */
extern unsigned get_count(void);
int sample(const int *values, unsigned index) {
    unsigned count = get_count();
    return values[index]; /* UNKNOWN: count is unused and extent is unclear */
}
