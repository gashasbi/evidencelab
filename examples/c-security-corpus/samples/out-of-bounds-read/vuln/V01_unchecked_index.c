/* EvidenceLab synthetic corpus | CWE-125 | VULN
 * Intent: Array index is not validated.
 * Educational fixture; not production code or proof of exploitability.
 */
int sample(const int *values, unsigned count, unsigned index) {
    (void)count;
    return values[index]; /* VULN: index is not checked */
}
