/* SPDX-License-Identifier: MIT -- synthetic authenticator, never installed. */
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdlib.h>
#include <string.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags,
                                  int argc, const char **argv) {
    (void)flags;
    if (!argc) return PAM_AUTH_ERR;
    if (!strcmp(argv[0], "fail")) return PAM_AUTH_ERR;
    char *reply = NULL;
    int key = !strcmp(argv[0], "key");
    int result = pam_prompt(handle, PAM_PROMPT_ECHO_OFF, &reply,
                            "%s", key ? "Key PIN: " : "Account password: ");
    int accepted = result == PAM_SUCCESS && reply && !strcmp(reply, key ? "123456" : "test-password");
    free(reply);
    return accepted ? PAM_SUCCESS : PAM_AUTH_ERR;
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t *handle, int flags,
                            int argc, const char **argv) {
    (void)handle; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
