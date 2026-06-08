typedef struct client_context {
    char *out_buf;
    unsigned out_buf_len;
} client_context_t;

int plugin_get_password(const sasl_client_params_t *params,
                        const sasl_secret_t **out_secret);

int plugin_get_identity(const sasl_client_params_t *params,
                        int callback_id,
                        const char **out_authname,
                        unsigned *out_len);

int build_response(const char *authn_id,
                    const char *authz_id,
                    const sasl_secret_t *secret,
                    const sasl_client_params_t *params,
                    sasl_out_params_t *oparams,
                    client_context_t *text);

