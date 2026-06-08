#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sasl.h>
#include <saslplug.h>

#include "xoauth_common.h"

int plugin_get_identity(const sasl_client_params_t *params,
                        int callback_id,
                        const char **out_authname,
                        unsigned *out_len)
{
    sasl_getsimple_t *authname_cb = NULL;
    void *authname_context = NULL;
    int result;

    if (!params || !params->utils || !out_authname) {
        return SASL_BADPARAM;
    }

    // Lookup the callback pointer
    result = params->utils->getcallback(params->utils->conn,
                                         callback_id,
                                         (int (**)(void)) &authname_cb,
                                         &authname_context);

    // Call the application routine if available
    if (result == SASL_OK && authname_cb) {
        result = authname_cb(authname_context,
                             callback_id,
                             out_authname,
                             out_len);
    }

    return SASL_OK;
}

/* Helper to safely retrieve the password secret struct */
int plugin_get_password(const sasl_client_params_t *params,
                        const sasl_secret_t **out_secret)
{
    sasl_getsecret_t *password_cb = NULL;
    void *password_context = NULL;
    int result;

    if (!params || !params->utils || !out_secret) {
        return SASL_BADPARAM;
    }

    // Lookup the callback pointer
    result = params->utils->getcallback(params->utils->conn,
                                         SASL_CB_PASS,
                                         (int (**)(void)) &password_cb,
                                         &password_context);

    // Call the application routine if available
    if (result == SASL_OK && password_cb) {
        // cast to allow passing a pointer to modifiable secret struct
        result = password_cb(params->utils->conn,
                             password_context,
                             SASL_CB_PASS,
                             (sasl_secret_t **) out_secret);
    }

    return SASL_OK;
}

int build_response(const char *authn_id,
                    const char *authz_id,
                    const sasl_secret_t *secret,
                    const sasl_client_params_t *params,
                    sasl_out_params_t *oparams,
                    client_context_t *text

)
{
    int result;
    unsigned authn_id_len = 0;
    unsigned authz_id_len = 0;
    // 1. Extract identities
    result = plugin_get_identity(params, SASL_CB_AUTHNAME, &authn_id, &authn_id_len);
    if (result != SASL_OK) {
        return result;
    }

    result = plugin_get_identity(params, SASL_CB_USER, &authz_id, &authz_id_len);
    if (result != SASL_OK) {
        return result;
    }

    // 2. Extract Secrets
    result = plugin_get_password(params, &secret);
    if (result != SASL_OK) {
        return result;
    }


    //NOTE: Using canon_user is a SASL plugin requirement
    //NOTE: Both an AUTHID and AUTHZID are not always returned.
    //      Sometimes, it's just an AUTHID and you set both using it.
    if ( authn_id && authz_id ){
        params->canon_user(params->utils->conn, authn_id, 0,
            SASL_CU_AUTHID, oparams);
        params->canon_user(params->utils->conn, authz_id, 0,
            SASL_CU_AUTHZID, oparams);
    }
    else if ( authn_id && ! authz_id ){
        params->canon_user(params->utils->conn, authn_id, 0,
            SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
    }
    else if ( !authn_id && authz_id ){
        params->canon_user(params->utils->conn, authz_id, 0,
            SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
    }

    //NOTE: Format the credentials for XOAUTH2

    const char *token_data = secret ? (const char *)secret->data : "";
    size_t token_len = strlen(token_data);

    const char *user_prefix = "user=";
    size_t user_prefix_len = strlen(user_prefix);

    const char *auth_prefix = "auth=Bearer ";
    size_t auth_prefix_len = strlen(auth_prefix);

    const char *user_str = authn_id ? authn_id : authz_id;
    size_t user_len = strlen(user_str);

    //NOTE: The final 1 is for the NULL terminator added by snprintf
    text->out_buf_len = user_prefix_len + user_len + 1 +
        auth_prefix_len + token_len + 1 + 1 + 1;

    text->out_buf = params->utils->malloc(text->out_buf_len);
    memset(text->out_buf, 0, text->out_buf_len);

    int raw_len = snprintf(text->out_buf, text->out_buf_len,
                            "%s%s\001%s%s\001\001",
                            user_prefix,user_str,auth_prefix,token_data);
    if (raw_len <= 0 || raw_len >= text->out_buf_len) {
        return SASL_BUFOVER;
    }

    return SASL_OK;
}

