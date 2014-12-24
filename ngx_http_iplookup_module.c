#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <db.h>

typedef struct {
    ngx_str_t database;
} ngx_http_iplookup_loc_conf_t;


static ngx_int_t ngx_http_iplookup_init(ngx_conf_t *cf);

static void *ngx_http_iplookup_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_iplookup_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_iplookup_handler(ngx_http_request_t *r);

static int compare_bt(DB *dbp, const DBT *a, const DBT *b);

static ngx_str_t search_db(ngx_http_request_t *r, ngx_http_iplookup_loc_conf_t *conf, int id);



static ngx_command_t ngx_http_iplookup_commands[] = {
    {
        ngx_string("iplookup"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_iplookup_loc_conf_t, database),
        NULL
    },
    ngx_null_command
};


static ngx_http_module_t ngx_http_iplookup_module_ctx = {
    NULL,
    ngx_http_iplookup_init,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_iplookup_create_loc_conf,
    ngx_http_iplookup_merge_loc_conf
};


ngx_module_t ngx_http_iplookup_module = {
    NGX_MODULE_V1,
    &ngx_http_iplookup_module_ctx,
    ngx_http_iplookup_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};


static void *ngx_http_iplookup_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_iplookup_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_iplookup_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_str_null(&conf->database);
    return conf;
}


static char *ngx_http_iplookup_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_iplookup_loc_conf_t *prev = parent;
    ngx_http_iplookup_loc_conf_t *conf = child;
    ngx_conf_merge_str_value(conf->database, prev->database, (u_char *) "/usr/local/share/iplookup/ip.db");
    return NGX_CONF_OK;
}


static ngx_int_t ngx_http_iplookup_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_buf_t *b;
    ngx_chain_t out;
    unsigned char *start;

    ngx_http_iplookup_loc_conf_t *conf;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_iplookup_module);

    //rc = ngx_http_discard_body(r);

    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char *) "text/plain";

    ngx_str_t content = search_db(r, conf, 16785407);
    //ngx_str_t content = conf->database;

    if (content.data == NULL) {
        content.len = sizeof("fail") - 1;
        content.data = (u_char *) "fail";
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = content.len;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    out.buf = b;
    out.next = NULL;

    start = ngx_palloc(r->pool, content.len);
    ngx_memcpy(start, content.data, content.len);

    b->pos = start;
    b->last = start + content.len;

    b->memory = 1;
    b->last_buf = 1;

    rc = ngx_http_send_header(r);

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t ngx_http_iplookup_init(ngx_conf_t *cf) {
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_iplookup_handler;

    return NGX_OK;
}


static int compare_bt(DB *dbp, const DBT *a, const DBT *b) {
    int ai, bi;

    memcpy(&ai, a->data, sizeof(int));
    memcpy(&bi, b->data, sizeof(int));
    return (ai - bi);
}


static ngx_str_t search_db(ngx_http_request_t *r, ngx_http_iplookup_loc_conf_t *conf, int id) {
    DB *dbp;
    DBC *dbcp;
    DBT key, data;
    char s[1024];

    memset(&key, 0, sizeof(DBT));
    memset(&data, 0, sizeof(DBT));

    key.data = &id;
    key.size = sizeof(int);

    data.data = s;
    data.ulen = 1024;
    data.flags = DB_DBT_USERMEM;
    
    db_create(&dbp, NULL, 0);
    dbp->set_bt_compare(dbp, compare_bt);
    dbp->open(dbp, NULL, (const char *) conf->database.data, NULL, DB_BTREE, DB_RDONLY, 0);
    dbp->cursor(dbp, NULL, &dbcp, 0);
    dbcp->get(dbcp, &key, &data, DB_SET_RANGE);
    dbcp->close(dbcp);
    dbp->close(dbp, 0);

    ngx_str_t res;

    res.data = (u_char *) s;
    res.len = strlen(s);

    return res;
}
