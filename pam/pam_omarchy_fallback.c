/* SPDX-License-Identifier: MIT
 * A conversation gate only: success permits the following password stack.
 * This module never authenticates a user and must never be sufficient.
 */
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "translations.h"

static const char *fallback_prompt(void) {
    const char *raw = getenv("OMARCHY_YUBIKEY_LANGUAGE");
    const char *names[] = {"LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"};
    for (size_t i = 0; (!raw || !*raw) && i < sizeof(names) / sizeof(names[0]); ++i)
        raw = getenv(names[i]);
    char code[64] = "en";
    if (raw && *raw && strlen(raw) < sizeof(code)) {
        size_t n = strcspn(raw, ".@:");
        for (size_t i = 0; i < n; ++i)
            code[i] = raw[i] == '_' ? '-' : (char)tolower((unsigned char)raw[i]);
        code[n] = '\0';
    }
    if (!strcmp(code, "zh-hk") || !strcmp(code, "zh-hant")) strcpy(code, "zh-TW");
    for (int pass = 0; pass < 2; ++pass) {
        if (!strcmp(code, "es")) strcpy(code, "es-MX");
        if (!strcmp(code, "nb") || !strcmp(code, "nn")) strcpy(code, "no");
        if (!strcmp(code, "tl")) strcpy(code, "fil");
        if (!strcmp(code, "zh")) strcpy(code, "zh-CN");
        for (size_t i = 0; i < sizeof(fallback_prompts) / sizeof(fallback_prompts[0]); ++i)
            if (!strcasecmp(code, fallback_prompts[i].code)) return fallback_prompts[i].text;
        char *region = strchr(code, '-');
        if (region) *region = '\0';
    }
    return "Use password fallback? Type password to continue: ";
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                  int argc, const char **argv) {
    (void)argv;
    if (argc != 0 || (flags & PAM_SILENT)) return PAM_AUTH_ERR;
    char *reply = NULL;
    int result = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &reply, "%s", fallback_prompt());
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
