/* EvidenceLab synthetic corpus | CWE-787 | VULN
 * Intent: Input-controlled index is written without bounds checks.
 * Educational fixture; not production code or proof of exploitability.
 */
void sample(int *values, int index) {
    values[index] = 7; /* VULN: no bounds validation */
}
