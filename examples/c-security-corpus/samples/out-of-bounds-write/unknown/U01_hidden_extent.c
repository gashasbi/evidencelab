/* EvidenceLab synthetic corpus | CWE-787 | UNKNOWN
 * Intent: Destination capacity is hidden behind an external API.
 * Educational fixture; not production code or proof of exploitability.
 */
extern int store_value(int *destination, int index);
int sample(int *destination, int index) {
    return store_value(destination, index);
    /* UNKNOWN: destination extent and callee contract are missing */
}
