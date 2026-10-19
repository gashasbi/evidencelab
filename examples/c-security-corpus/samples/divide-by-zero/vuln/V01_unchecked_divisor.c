/* EvidenceLab synthetic corpus | CWE-369 | VULN
 * Intent: Divisor is not checked.
 * Educational fixture; not production code or proof of exploitability.
 */
int sample(int value, int divisor) {
    return value / divisor; /* VULN: divisor may be zero */
}
