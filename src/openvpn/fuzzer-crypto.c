#include "config.h"
#include "syshead.h"
#include "fuzzing.h"
#include "crypto.h"
#include "ssl.h"
#include "ssl_common.h"
#include "mtu.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
bool server = false;

static int init_frame(struct frame* frame)
{
    ssize_t generic_ssizet;

    FUZZER_GET_INTEGER(generic_ssizet, 1000);
    frame->link_mtu = generic_ssizet+100;
    FUZZER_GET_INTEGER(generic_ssizet, 1000);
    frame->extra_buffer = generic_ssizet+100;
    FUZZER_GET_INTEGER(generic_ssizet, 1000);
    frame->link_mtu_dynamic = generic_ssizet+100;
    FUZZER_GET_INTEGER(generic_ssizet, 1000);
    frame->extra_frame = generic_ssizet+100;
    FUZZER_GET_INTEGER(generic_ssizet, 1000);
    frame->extra_tun = generic_ssizet+100;
    FUZZER_GET_INTEGER(generic_ssizet, 1000);
    frame->extra_link = generic_ssizet+100;
    frame->align_flags = 0;
    frame->align_adjust = 0;
    if ( TUN_MTU_SIZE(frame) <= 0 ) {
        goto cleanup;
    }
    return 0;

cleanup:
    return -1;
}
static void
key_ctx_update_implicit_iv(struct key_ctx *ctx, uint8_t *key, size_t key_len)
{
    const cipher_kt_t *cipher_kt = cipher_ctx_get_cipher_kt(ctx->cipher);

    /* Only use implicit IV in AEAD cipher mode, where HMAC key is not used */
    if (cipher_kt_mode_aead(cipher_kt))
    {
        size_t impl_iv_len = 0;
        ASSERT(cipher_kt_iv_size(cipher_kt) >= OPENVPN_AEAD_MIN_IV_LEN);
        impl_iv_len = cipher_kt_iv_size(cipher_kt) - sizeof(packet_id_type);
        ASSERT(impl_iv_len <= OPENVPN_MAX_IV_LENGTH);
        ASSERT(impl_iv_len <= key_len);
        memcpy(ctx->implicit_iv, key, impl_iv_len);
        ctx->implicit_iv_len = impl_iv_len;
    }
}
static int
key_source2_read(struct key_source2 *k2,
                 struct buffer *buf)
{
    /*
    struct key_source *k = &k2->client;

    if (!server)
    {
        k = &k2->server;
    }
    */
    struct key_source _k;
    struct key_source *k = &_k;

    CLEAR(*k);

    if (server)
    {
        if (!buf_read(buf, k->pre_master, sizeof(k->pre_master)))
        {
            return 0;
        }
    }

    if (!buf_read(buf, k->random1, sizeof(k->random1)))
    {
        return 0;
    }
    if (!buf_read(buf, k->random2, sizeof(k->random2)))
    {
        return 0;
    }

    return 1;
}

static bool
read_string(struct buffer *buf, char *str, const unsigned int capacity)
{
    const int len = buf_read_u16(buf);
    if (len < 1 || len > (int)capacity)
    {
        return false;
    }
    if (!buf_read(buf, str, len))
    {
        return false;
    }
    str[len-1] = '\0';
    return true;
}

static bool
/*key_method_2_read(struct buffer *buf, struct tls_multi *multi, struct tls_session *session)*/
key_method_2_read(struct buffer *buf)
{
    /*struct key_state *ks = &session->key[KS_PRIMARY];*/      /* primary key */
    struct key_state _ks;
    struct key_state *ks = &_ks;
    memset(ks, 0, sizeof(struct key_state));

    int key_method_flags;
    bool username_status, password_status;

    struct gc_arena gc = gc_new();
    char *options;
    struct user_pass *up = NULL;

    /* allocate temporary objects */
    ALLOC_ARRAY_CLEAR_GC(options, char, TLS_OPTIONS_LEN, &gc);

    //ASSERT(session->opt->key_method == 2);

    /* discard leading uint32 */
    if (!buf_advance(buf, 4))
    {
        msg(D_TLS_ERRORS, "TLS ERROR: Plaintext buffer too short (%d bytes).",
            buf->len);
        goto error;
    }

    /* get key method */
    key_method_flags = buf_read_u8(buf);
    if ((key_method_flags & KEY_METHOD_MASK) != 2)
    {
        msg(D_TLS_ERRORS,
            "TLS ERROR: Unknown key_method/flags=%d received from remote host",
            key_method_flags);
        goto error;
    }

    /* get key source material (not actual keys yet) */
    /*if (!key_source2_read(ks->key_src, buf, session->opt->server))*/
    if (!key_source2_read(ks->key_src, buf))
    {
        msg(D_TLS_ERRORS, "TLS Error: Error reading remote data channel key source entropy from plaintext buffer");
        goto error;
    }

    /* get options */
    if (!read_string(buf, options, TLS_OPTIONS_LEN))
    {
        msg(D_TLS_ERRORS, "TLS Error: Failed to read required OCC options string");
        goto error;
    }

    /*ks->authenticated = false;*/

    /* always extract username + password fields from buf, even if not
     * authenticating for it, because otherwise we can't get at the
     * peer_info data which follows behind
     */
    ALLOC_OBJ_CLEAR_GC(up, struct user_pass, &gc);
    username_status = read_string(buf, up->username, USER_PASS_LEN);
    password_status = read_string(buf, up->password, USER_PASS_LEN);

#if 0
    /* get peer info from control channel */
    free(multi->peer_info);
    multi->peer_info = read_string_alloc(buf);
    if (multi->peer_info)
    {
        output_peer_info_env(session->opt->es, multi->peer_info);
    }

    free(multi->remote_ciphername);
    multi->remote_ciphername =
        options_string_extract_option(options, "cipher", NULL);

    if (tls_peer_info_ncp_ver(multi->peer_info) < 2)
    {
        /* Peer does not support NCP, but leave NCP enabled if the local and
         * remote cipher do not match to attempt 'poor-man's NCP'.
         */
        if (multi->remote_ciphername == NULL
            || 0 == strcmp(multi->remote_ciphername, multi->opt.config_ciphername))
        {
            session->opt->ncp_enabled = false;
        }
    }
#endif /* if P2MP_SERVER */

#if 0
    if (tls_session_user_pass_enabled(session))
    {
        /* Perform username/password authentication */
        if (!username_status || !password_status)
        {
            CLEAR(*up);
            if (!(session->opt->ssl_flags & SSLF_AUTH_USER_PASS_OPTIONAL))
            {
                msg(D_TLS_ERRORS, "TLS Error: Auth Username/Password was not provided by peer");
                goto error;
            }
        }

        verify_user_pass(up, multi, session);
    }
    else
    {
        /* Session verification should have occurred during TLS negotiation*/
        if (!session->verified)
        {
            msg(D_TLS_ERRORS,
                "TLS Error: Certificate verification failed (key-method 2)");
            goto error;
        }
        ks->authenticated = true;
    }

    /* clear username and password from memory */
    secure_memzero(up, sizeof(*up));

    /* Perform final authentication checks */
    if (ks->authenticated)
    {
        verify_final_auth_checks(multi, session);
    }

#ifdef ENABLE_OCC
    /* check options consistency */
    if (!session->opt->disable_occ
        && !options_cmp_equal(options, session->opt->remote_options))
    {
        options_warning(options, session->opt->remote_options);
        if (session->opt->ssl_flags & SSLF_OPT_VERIFY)
        {
            msg(D_TLS_ERRORS, "Option inconsistency warnings triggering disconnect due to --opt-verify");
            ks->authenticated = false;
        }
    }
#endif

    buf_clear(buf);

    /*
     * Call OPENVPN_PLUGIN_TLS_FINAL plugin if defined, for final
     * veto opportunity over authentication decision.
     */
    if (ks->authenticated && plugin_defined(session->opt->plugins, OPENVPN_PLUGIN_TLS_FINAL))
    {
        key_state_export_keying_material(&ks->ks_ssl, session);

        if (plugin_call(session->opt->plugins, OPENVPN_PLUGIN_TLS_FINAL, NULL, NULL, session->opt->es) != OPENVPN_PLUGIN_FUNC_SUCCESS)
        {
            ks->authenticated = false;
        }

        setenv_del(session->opt->es, "exported_keying_material");
    }

    /*
     * Generate tunnel keys if we're a client.
     * If --pull is enabled, the first key generation is postponed until after the
     * pull/push, so we can process pushed cipher directives.
     */
    if (!session->opt->server && (!session->opt->pull || ks->key_id > 0))
    {
        if (!tls_session_generate_data_channel_keys(session))
        {
            msg(D_TLS_ERRORS, "TLS Error: client generate_key_expansion failed");
            goto error;
        }
    }

#endif
    gc_free(&gc);
    return true;

error:
    /*
    secure_memzero(ks->key_src, sizeof(*ks->key_src));
    if (up)
    {
        secure_memzero(up, sizeof(*up));
    }
    */
    buf_clear(buf);
    gc_free(&gc);
    return false;
}
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
#if defined(ENABLE_CRYPTO) && defined(ENABLE_CRYPTO_OPENSSL)
    CRYPTO_malloc_init();
    SSL_library_init();
    ERR_load_crypto_strings();

    OpenSSL_add_all_algorithms();
    OpenSSL_add_ssl_algorithms();

    SSL_load_error_strings();
#else
#error "This fuzzing target cannot be built"
#endif
    return 1;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ssize_t choice;
    struct key key;
    struct key2 key2;
    struct gc_arena gc;
    struct key_type kt;
    struct key_ctx key_ctx_enc;
    struct key_ctx key_ctx_dec;
    bool key_type_initialized = false;
    bool key_initialized = false;
    bool key_ctx_enc_initialized = false;
    bool key_ctx_dec_initialized = false;
    bool key2_initialized = false;
    struct frame frame;
    int i;
    void *buf_p;
    /*
    init_key_type(&kt, "none", "x", 32, true, 0);
    printf("%u\n", kt.hmac_length);
    return 0;
    */
    gc = gc_new();

    fuzzer_set_input((unsigned char*)data, size);
    for (i = 0; i < 7; i++) {
        FUZZER_GET_INTEGER(choice, 9);
        switch ( choice )
        {
            case    0:
                {
                    if ( key2_initialized == false ) {
                        char* input;
                        FUZZER_GET_STRING_GC(input, 1024, &gc);
                        read_key_file(&key2, (const char*)input, RKF_INLINE);
                        key2_initialized = true;
                    }
                }
                break;
            case    1:
                {
                    if ( key_type_initialized == false ) {
                        char* input;
                        char* ciphername, *authname;
                        int keysize;
                        int tls_mode;
                        FUZZER_GET_STRING_GC(ciphername, 64, &gc);
                        FUZZER_GET_STRING_GC(authname, 64, &gc);
                        FUZZER_GET_INTEGER(keysize, (MAX_CIPHER_KEY_LENGTH+10));
                        FUZZER_GET_INTEGER(tls_mode, 1);
                        //printf("ciphername: %s, authname: %s\n", ciphername, authname);
                        if ( tls_item_in_cipher_list(ciphername, "AES-256-GCM:AES-128-GCM:AES-192-GCM:CAMELLIA-128-CFB128") ) {
                            //init_key_type(&kt, ciphername, authname, keysize, tls_mode ? true : false, 0);
                            init_key_type(&kt, ciphername, authname, -1, tls_mode ? true : false, 0);
                            key_type_initialized = true;
                        }
                    }
                }
                break;
            case    2:
                {
                    if ( key_type_initialized == true ) {
                        struct key key;
                        struct buffer buf;
                        unsigned char d[1024];
                        ssize_t numread;
                        //FILE* fp;
                        FUZZER_GET_DATA_RND(d, 1024);
                        //fp = fopen("keymeth1buf.bin", "wb");
                        //fwrite(d, numread, 1, fp);
                        //fclose(fp);


                        buf = alloc_buf(numread);
                        if ( buf_write(&buf, d, numread) == false ) {
                            goto cleanup;
                        }

                        //printf("%u, %u\n", kt.cipher_length, kt.hmac_length);
                        read_key(&key, &kt, &buf);

                        free_buf(&buf);
                    }
                }
                break;
            case    3:
                {
                    if ( key_type_initialized == true ) {
                        struct key key;
                        struct buffer buf;
                        unsigned char d[4096];
                        ssize_t numread;
                        FUZZER_GET_DATA_RND(d, 4096);

                        buf = alloc_buf(numread);
                        if ( buf_write(&buf, d, numread) == false ) {
                            goto cleanup;
                        }
                        key_method_2_read(&buf);

                        free_buf(&buf);
                    }
                }
                break;
            case    4:
                {
                    if ( key_type_initialized == true ) {
                        if ( key2_initialized == true ) {
                            verify_fix_key2(&key2, &kt, NULL);
                        }
                    }
                }
                break;
            case 5:
                {
                    if ( key_type_initialized == true ) {
                        generate_key_random(&key, &kt);
                        key_initialized = true;
                    }
                }
                break;
            case 6:
                {
                    if ( key_ctx_dec_initialized == false) {
                        if ( key_type_initialized == true ) {
                            if ( key2_initialized == true ) {
                                if ( key_initialized == true ) {
                                    init_key_ctx(&key_ctx_dec, &key, &kt, OPENVPN_OP_DECRYPT, "x");
                                    key_ctx_update_implicit_iv(&key_ctx_dec, &(key.hmac), MAX_HMAC_KEY_LENGTH);
                                    key_ctx_dec_initialized = true;
                                }
                            }
                        }
                    }
                }
            case 7:
                {
                    if ( key_ctx_enc_initialized == false) {
                        if ( key_type_initialized == true ) {
                            if ( key2_initialized == true ) {
                                if ( key_initialized == true ) {
                                    init_key_ctx(&key_ctx_enc, &key, &kt, OPENVPN_OP_ENCRYPT, "x");
                                    key_ctx_update_implicit_iv(&key_ctx_enc, &(key.hmac), MAX_HMAC_KEY_LENGTH);
                                    key_ctx_enc_initialized = true;
                                }
                            }
                        }
                    }
                }
                break;
            case 8:
                {
                    if ( init_frame(&frame) == -1 )
                    {
                        goto cleanup;
                    }
                    if ( key_type_initialized == true ) {
                        if ( key2_initialized == true ) {
                            if ( key_initialized == true ) {
                                if ( key_ctx_dec_initialized == true ) {
                                    if ( key_ctx_enc_initialized == true ) {
                                        struct crypto_options opt;
                                        struct buffer encrypt_workspace = alloc_buf_gc(BUF_SIZE(&(frame)), &gc);
                                        struct buffer work = alloc_buf_gc(BUF_SIZE(&(frame)), &gc);
                                        struct buffer src = alloc_buf_gc(TUN_MTU_SIZE(&(frame)), &gc);
                                        struct buffer buf = clear_buf();
                                        ssize_t numread;
                                        int x;
                                        FUZZER_GET_INTEGER(x, TUN_MTU_SIZE(&frame)-1);
                                        x++;
                                        ASSERT(buf_init(&work, FRAME_HEADROOM(&(frame))));
                                        ASSERT(buf_init(&src, 0));
                                        //printf("%d, %d\n", x, src.capacity);
                                        ASSERT(x <= src.capacity);
                                        src.len = x;
                                        ASSERT(rand_bytes(BPTR(&src), BLEN(&src)));

                                        /* copy source to input buf */
                                        buf = work;
                                        buf_p = buf_write_alloc(&buf, BLEN(&src));
                                        ASSERT(buf_p);
                                        memcpy(buf_p, BPTR(&src), BLEN(&src));

                                        ASSERT(buf_init(&encrypt_workspace, FRAME_HEADROOM(&(frame))));

                                        memset(&opt, 0, sizeof(opt));
                                        opt.pid_persist = NULL;
                                        opt.key_ctx_bi.encrypt = key_ctx_enc;
                                        opt.key_ctx_bi.decrypt = key_ctx_dec;
                                        opt.key_ctx_bi.initialized = true;
                                        FUZZER_GET_DATA_RND(&(opt.packet_id), sizeof(opt.packet_id));
                                        FUZZER_GET_DATA_RND(&(opt.flags), sizeof(opt.flags));

                                        opt.packet_id.rec.initialized = true;
                                        opt.packet_id.rec.seq_list = NULL;
                                        opt.packet_id.rec.name = NULL;
                                        openvpn_encrypt(&buf, encrypt_workspace, &opt);
                                    }
                                }
                            }
                        }
                    }
                }
                break;
            case 9:
                {
                    if ( init_frame(&frame) == -1 )
                    {
                        goto cleanup;
                    }
                    if ( key_type_initialized == true ) {
                        if ( key2_initialized == true ) {
                            if ( key_initialized == true ) {
                                if ( key_ctx_dec_initialized == true ) {
                                    if ( key_ctx_enc_initialized == true ) {
                                        struct crypto_options opt;
                                        struct buffer decrypt_workspace = alloc_buf_gc(BUF_SIZE(&(frame)), &gc);
                                        struct buffer work = alloc_buf_gc(BUF_SIZE(&(frame)), &gc);
                                        struct buffer src = alloc_buf_gc(TUN_MTU_SIZE(&(frame)), &gc);
                                        struct buffer buf = clear_buf();
                                        ssize_t numread;
                                        int x;
                                        FUZZER_GET_INTEGER(x, TUN_MTU_SIZE(&frame)-1);
                                        x++;
                                        ASSERT(buf_init(&work, FRAME_HEADROOM(&(frame))));
                                        ASSERT(buf_init(&src, 0));
                                        //printf("%d, %d\n", x, src.capacity);
                                        ASSERT(x <= src.capacity);
                                        src.len = x;
                                        ASSERT(rand_bytes(BPTR(&src), BLEN(&src)));

                                        /* copy source to input buf */
                                        buf = work;
                                        buf_p = buf_write_alloc(&buf, BLEN(&src));
                                        ASSERT(buf_p);
                                        memcpy(buf_p, BPTR(&src), BLEN(&src));


                                        memset(&opt, 0, sizeof(opt));
                                        opt.pid_persist = NULL;
                                        opt.key_ctx_bi.encrypt = key_ctx_enc;
                                        opt.key_ctx_bi.decrypt = key_ctx_dec;
                                        opt.key_ctx_bi.initialized = true;
                                        FUZZER_GET_DATA_RND(&(opt.packet_id), sizeof(opt.packet_id));
                                        FUZZER_GET_DATA_RND(&(opt.flags), sizeof(opt.flags));

                                        opt.packet_id.rec.initialized = true;
                                        opt.packet_id.rec.seq_list = NULL;
                                        opt.packet_id.rec.name = NULL;
                                        openvpn_decrypt(&buf, decrypt_workspace, &opt, &frame, BPTR(&buf));
                                    }
                                }
                            }
                        }
                    }
                }
                break;
        }
    }
cleanup:
    if ( key_ctx_dec_initialized == true) {
        free_key_ctx(&key_ctx_dec);
    }
    if ( key_ctx_enc_initialized == true) {
        free_key_ctx(&key_ctx_enc);
    }
    gc_free(&gc);
    return 0;
}
