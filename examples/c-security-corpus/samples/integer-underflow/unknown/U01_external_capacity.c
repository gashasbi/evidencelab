/* EvidenceLab synthetic corpus | CWE-191 | UNKNOWN
 * Intent: The relation between capacity and used length is unknown.
 * Educational fixture; not production code or proof of exploitability.
 */
extern size_t get_used(void);
extern size_t get_capacity(void);
size_t sample(void) {
    return get_capacity() - get_used();
    /* UNKNOWN: relationship between values is unspecified */
}
