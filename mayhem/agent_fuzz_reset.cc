// Replaces upstream's agent_fuzz.cc. upstream's test_one() resets idtab and the socket table per
// input, but not ssh-agent.c's lock state: one SSH_AGENTC_LOCK input would leave every later input
// refused at the `if (locked && type != SSH_AGENTC_UNLOCK)` check. Reset it here so each input is
// independent (the other statics in ssh-agent.c are only written by main(), which the harness skips).
#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern "C" {
extern int locked;
extern unsigned char lock_pwhash[32]; /* LOCK_SIZE in ssh-agent.c */
extern unsigned char lock_salt[16];   /* LOCK_SALT_SIZE in ssh-agent.c */
void test_one(const uint8_t *s, size_t slen);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *s, size_t slen) {
    locked = 0;
    memset(lock_pwhash, 0, sizeof(lock_pwhash));
    memset(lock_salt, 0, sizeof(lock_salt));
    test_one(s, slen);
    return 0;
}
