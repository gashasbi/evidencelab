/* EvidenceLab synthetic corpus | CWE-190 | UNKNOWN
 * Intent: Safety depends on an absent range contract.
 * Educational fixture; not production code or proof of exploitability.
 */
extern unsigned get_count(void);
extern void allocate_items(unsigned count);
void sample(void) {
    allocate_items(get_count());
    /* UNKNOWN: valid count range and allocation behavior are undocumented */
}
