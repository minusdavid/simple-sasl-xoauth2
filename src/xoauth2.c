/*
 * Simple Cyrus SASL XOAUTH2 client plugin
 * 
 * This plugin is designed to non-interactively get both the username
 * and OAuth2 token from the application. It is only responsible for
 * formatting these credentials into an XOAUTH2 payload. 
 * 
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sasl.h>
#include <saslplug.h>

#include "xoauth_common.h"
#include "version.h"

/* -------------------------
 * mech_new
 * Allocates the connection context.
 * ------------------------- */
static int mech_new(void *glob_context,
            sasl_client_params_t *params,
            void **conn_context)
{
    client_context_t *text;
    text = params->utils->malloc(sizeof(client_context_t));
    if (text == NULL){
        return SASL_NOMEM;
    }
    memset(text, 0, sizeof(client_context_t));
    *conn_context = text;
    return SASL_OK;
}

/* -------------------------
 * mech_step
 * ------------------------- */
static int mech_step(void *conn_context,
             sasl_client_params_t *params,
             const char *serverin,
             unsigned serverinlen,
             sasl_interact_t **prompt_need,
             const char **clientout,
             unsigned *clientoutlen,
             sasl_out_params_t *oparams)
{
    const char *authn_id = NULL;

    const char *authz_id = NULL;

    const sasl_secret_t *secret = NULL;

    *clientout = NULL;
    *clientoutlen = 0;

    client_context_t *text = (client_context_t *) conn_context;

    int result = build_response(
        authn_id,
        authz_id,
        secret,
        params,
        oparams,
        text
    );
    if (result != SASL_OK) {
        return result;
    }

    *clientout = text->out_buf;
    //NOTE: We don't need the null byte at the end of the output buffer so minus 1 from the length
    *clientoutlen = text->out_buf_len - 1;

    oparams->doneflag = 1;

    return SASL_OK;
}

/* -------------------------
 * mech_dispose
 * Clean up the connection context. Based off core PLAIN plugin.
 * ------------------------- */
static void mech_dispose(void *conn_context,
                         const sasl_utils_t *utils)
{
    client_context_t *text = (client_context_t *) conn_context;
    if (text){
        if (text->out_buf){
            utils->free(text->out_buf);
        }
        utils->free(text);
    }
    else {
        return;
    }
}

/* -------------------------
 * Plugin definition
 * This is where we create a list of SASL plugins.
 * In this case, there is just one SASL client plugin.
 * The most important parts are the mechanism name and the mechanism functions
 * 
 * See https://github.com/cyrusimap/cyrus-sasl/blob/master/include/saslplug.h
 * ------------------------- */
static sasl_client_plug_t sasl_plugins[] = {
    {
        "XOAUTH2", /* mechanism name */
        0, /* security strength factor: use 0 since we're not using any encryption here */ 
        SASL_SEC_NOANONYMOUS | SASL_SEC_NOPLAINTEXT, /* best security flags, as defined in sasl_security_properties_t */
        SASL_FEAT_WANT_CLIENT_FIRST | SASL_FEAT_ALLOWS_PROXY, /* features of plugin */
        NULL, /* required prompt ids, NULL = user/pass only */
        NULL, /* global state for mechanism */
        &mech_new, /* create context for mechanism, using params supplied */
        &mech_step, /* perform one step of exchange */
        &mech_dispose, /* dispose of connection context from mech_new */
        NULL, /* free all global space used by mechanism */
        NULL, /* idle */
        NULL, /* spare_fptr1 */
        NULL, /* spare_fptr2 */
    }
};

/* -------------------------
 * Init hook for the plugin
 * Cyrus SASL opens the library and runs this init function to get the plugin(s) we provide 
 * 
 * Note: mechanism plugins frequently provide server and client implementations, 
 *       but we are just providing a client plugin for now.
 * 
 * See https://www.cyrusimap.org/sasl/sasl/developer/plugprog.html#overview-of-plugin-programming
 * See https://www.cyrusimap.org/sasl/sasl/reference/manpages/library/sasl_client_plug_init_t.html
 * ------------------------- */
int sasl_client_plug_init(const sasl_utils_t *utils,
                              int max_version,
                              int *out_version,
                              sasl_client_plug_t **pluglist,
                              int *plugcount)
{
    if (max_version < SASL_CLIENT_PLUG_VERSION){
        utils->seterror(utils->conn, 0, "XOAUTH2 version mismatch");
        return SASL_BADVERS;
    }
    *pluglist = sasl_plugins;
    *plugcount = 1;
    *out_version = SASL_CLIENT_PLUG_VERSION;
    return SASL_OK;
}
