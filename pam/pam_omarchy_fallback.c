/* SPDX-License-Identifier: MIT
 * A conversation gate only: success permits the following password stack.
 * This module never authenticates a user and must never be sufficient.
 */
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdlib.h>
#include <string.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                  int argc, const char **argv) {
    (void)argv;
    if (argc != 0 || (flags & PAM_SILENT)) return PAM_AUTH_ERR;
    char *reply = NULL;
    int result = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &reply,
        "Use password fallback? Type password to continue: ");
    int accepted = result == PAM_SUCCESS && reply != NULL
        && strcmp(reply, "password") == 0;
    if (reply != NULL) {
        /* Users may accidentally enter a secret at any conversation prompt. */
        explicit_bzero(reply, strlen(reply));
        free(reply);
    }
    return accepted ? PAM_SUCCESS : PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                            int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
