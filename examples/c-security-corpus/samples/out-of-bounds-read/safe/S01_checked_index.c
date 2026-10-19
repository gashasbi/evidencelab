/* EvidenceLab synthetic corpus | CWE-125 | SAFE
 * Intent: Pointer and index are checked before reading.
 * Educational fixture; not production code or proof of exploitability.
 */
int sample(const int *values, unsigned count, unsigned index) {
    if (!values || index >= count) return -1;
    return values[index];
}
