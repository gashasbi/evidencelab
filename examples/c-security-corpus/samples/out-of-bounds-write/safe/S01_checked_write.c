/* EvidenceLab synthetic corpus | CWE-787 | SAFE
 * Intent: Validates pointer and index before writing.
 * Educational fixture; not production code or proof of exploitability.
 */
void sample(int *values, int count, int index) {
    if (!values || index < 0 || index >= count) return;
    values[index] = 7;
}
