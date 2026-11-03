/* SPDX-License-Identifier: MIT -- isolated Linux-PAM integration test driver. */
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct answers { int count; int next; char **values; };
static int converse(int count, const struct pam_message **messages,
                    struct pam_response **response, void *data) {
    struct answers *answers = data;
    *response = calloc((size_t)count, sizeof(**response));
    if (!*response) return PAM_BUF_ERR;
    for (int i = 0; i < count; ++i) {
        int style = messages[i]->msg_style;
        if (style != PAM_PROMPT_ECHO_ON && style != PAM_PROMPT_ECHO_OFF) continue;
        printf("PROMPT %d %s\n", style, messages[i]->msg);
        if (answers->next == answers->count) {
            for (int j = 0; j < i; ++j) free((*response)[j].resp);
            free(*response); *response = NULL;
            return PAM_CONV_ERR;
        }
        (*response)[i].resp = strdup(answers->values[answers->next++]);
        if (!(*response)[i].resp) abort();
    }
    return PAM_SUCCESS;
}
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    struct answers answers = {argc - 3, 0, argv + 3};
    struct pam_conv conv = {converse, &answers};
    pam_handle_t *handle = NULL;
    int result = pam_start_confdir("isolated-test", "example_user", &conv, argv[1], &handle);
    if (result == PAM_SUCCESS) result = pam_authenticate(handle, atoi(argv[2]));
    if (handle) pam_end(handle, result);
    printf("RESULT %d\n", result);
    return result == PAM_SUCCESS ? 0 : 1;
}
