/* EvidenceLab synthetic corpus | CWE-369 | SAFE
 * Intent: Rejects a zero divisor.
 * Educational fixture; not production code or proof of exploitability.
 */
int sample(int value, int divisor) {
    if (divisor == 0) return -1;
    return value / divisor;
}
