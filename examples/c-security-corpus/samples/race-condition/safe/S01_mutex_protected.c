/* EvidenceLab synthetic corpus | CWE-362 | SAFE
 * Intent: Protects a shared counter with a mutex.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <pthread.h>
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int shared;
void sample(void) {
    pthread_mutex_lock(&lock);
    shared++;
    pthread_mutex_unlock(&lock);
}
