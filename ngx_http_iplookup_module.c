#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <db.h>
#include <math.h>
#include <iconv.h>
#include "code_map.h"


#define ITEM_MAX_SIZE 128
#define ITEM_LARGE_ERROR "large"
#define ITEM_ICONV_ERROR "iconv"
#define CONTENT_MAX_SIZE 1024
#define CONTENT_LARGE_ERROR "large"
#define DB_MAX_SIZE 256
#define SUCCESS 1
#define ERROR_INTRANET -1
#define ERROR_NOTFOUND -2
#define ERROR_INVALID -3
#define ERROR_DBFAIL -4
#define ERROR_ITEMLARGE -5


typedef struct {
    ngx_str_t database;
    DB *dbp;
    DBC *dbcp;
    ngx_flag_t extra;
} ngx_http_iplookup_loc_conf_t;


typedef struct {
    ngx_str_t ip;
    ngx_str_t format;
    ngx_str_t encoding;
    ngx_str_t obj;
} ngx_http_iplookup_args_t;


typedef struct {
    int ret;
    int64_t start;
    int64_t end;
    ngx_str_t intip;
    ngx_array_t *a;
} ngx_http_iplookup_ipinfo_t;


static char *ngx_conf_set_iplookup_database(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

//static ngx_int_t ngx_http_iplookup_init(ngx_conf_t *cf);

static void *ngx_http_iplookup_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_iplookup_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_iplookup_handler(ngx_http_request_t *r);

static int compare_bt(DB *dbp, const DBT *a, const DBT *b);

static ngx_str_t search_db(ngx_http_request_t *r, ngx_http_iplookup_loc_conf_t *conf, int64_t n, ngx_str_t ipaddr);

static int64_t ipaddr_number(ngx_http_request_t *r, ngx_str_t ipaddr);

static ngx_http_iplookup_args_t *parse_args(ngx_http_request_t *r);

static ngx_http_iplookup_ipinfo_t *format_ipinfo(ngx_http_request_t *r, ngx_str_t ipinfo_s);

static ngx_str_t content_result(ngx_http_request_t *r, ngx_http_iplookup_ipinfo_t *ipinfo, ngx_http_iplookup_args_t *args, ngx_str_t ipaddr, ngx_http_iplookup_loc_conf_t *conf, int64_t n);

static ngx_array_t *ipinfo_decode_array(ngx_http_request_t *r, ngx_array_t *ipinfo);

static void *ipinfo_decode_item(ngx_http_request_t *r, ngx_str_t *s, ngx_str_t *ipinfo_item);

static void *ipinfo_iconv_item(ngx_http_request_t *r, ngx_str_t *s, ngx_str_t *ipinfo_item);

static ngx_array_t *ipinfo_iconv_array(ngx_http_request_t *r, ngx_array_t *ipinfo);

static ngx_array_t *ipinfo_escape_array(ngx_http_request_t *r, ngx_array_t *ipinfo);


static ngx_command_t ngx_http_iplookup_commands[] = {
    {
        ngx_string("iplookup"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        //ngx_conf_set_str_slot,
        ngx_conf_set_iplookup_database,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_iplookup_loc_conf_t, database),
        NULL
    },
    {
        ngx_string("iplookup_extra"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_iplookup_loc_conf_t, extra),
        NULL
    },
    ngx_null_command
};


static ngx_http_module_t ngx_http_iplookup_module_ctx = {
    NULL,
    //ngx_http_iplookup_init,
    NULL,
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


static char *ngx_conf_set_iplookup_database(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_iplookup_loc_conf_t *lkcf = conf;
    ngx_http_core_loc_conf_t *clcf;
    ngx_str_t *value;
    ngx_file_info_t fi;
    int rt;

    value = cf->args->elts;
    if (ngx_file_info(value[1].data, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "iplookup database \"%V\" not exist", &value[1]);
        return NGX_CONF_ERROR;
    }
    if (!ngx_is_file(&fi)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "iplookup database \"%V\" not regular file", &value[1]);
        return NGX_CONF_ERROR;
    }

    db_create(&lkcf->dbp, NULL, 0);
    lkcf->dbp->set_bt_compare(lkcf->dbp, compare_bt);
    rt = lkcf->dbp->open(lkcf->dbp, NULL, (const char *) value[1].data, NULL, DB_BTREE, DB_RDONLY, 0);
    if (rt != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "iplookup database \"%V\" open fail", &value[1]);
        return NGX_CONF_ERROR;
    }
    lkcf->dbp->cursor(lkcf->dbp, NULL, &lkcf->dbcp, 0);

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_iplookup_handler;
 
    return NGX_CONF_OK;
}


static void *ngx_http_iplookup_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_iplookup_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_iplookup_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_str_null(&conf->database);
    conf->extra = NGX_CONF_UNSET;
    return conf;
}


static char *ngx_http_iplookup_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_iplookup_loc_conf_t *prev = parent;
    ngx_http_iplookup_loc_conf_t *conf = child;
    ngx_conf_merge_value(conf->extra, prev->extra, 0);
    ngx_conf_merge_str_value(conf->database, prev->database, (u_char *) "/usr/local/share/iplookup/ip.db");

    return NGX_CONF_OK;
}


static ngx_int_t ngx_http_iplookup_handler(ngx_http_request_t *r) {
    ngx_int_t rc;
    ngx_buf_t *b;
    ngx_chain_t out;
    u_char *s;
    ngx_str_t ipaddr;
    u_char *content_type;
    
    ngx_http_iplookup_loc_conf_t *conf;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_iplookup_module);
    //ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "extra: %d ", conf->extra);

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_POST))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK && rc != NGX_AGAIN) {
        return rc;
    }

    ngx_http_iplookup_args_t *args = parse_args(r);
    
    if (args->format.data != NULL && ngx_strncmp(args->format.data, (const char *) "json", 4) == 0 && args->format.len == 4) {
        if (r->headers_in.msie == 1) {
            content_type = (u_char *) "text/html; charset=utf-8";
        } else {
            content_type = (u_char *) "application/json; charset=utf-8";
        }
    } else if (args->format.data != NULL && ngx_strncmp(args->format.data, (const char *) "js", 2) == 0) {
        if (r->headers_in.msie == 1) {
            content_type = (u_char *) "text/html; charset=utf-8";
        } else {
            content_type = (u_char *) "text/javascript; charset=utf-8";
        }
    } else if (args->encoding.data != NULL && ngx_strncmp(args->encoding.data, (const char *) "utf-8", 5) == 0 && args->encoding.len == 5) {
        content_type = (u_char *) "text/html; charset=utf-8";
    } else {
        content_type = (u_char *) "text/html; charset=gbk";
    }

    r->headers_out.content_type.len = ngx_strlen(content_type);
    r->headers_out.content_type.data = content_type;

    if (args->ip.data == NULL || args->ip.len == 0) {
        ipaddr = r->connection->addr_text;
    } else {
        ipaddr = args->ip;
    }

    int64_t n = ipaddr_number(r, ipaddr);
    ngx_str_t ipinfo_s = search_db(r, conf, n, ipaddr);
    ngx_http_iplookup_ipinfo_t *ipinfo = format_ipinfo(r, ipinfo_s);
    ngx_str_t content = content_result(r, ipinfo, args, ipaddr, conf, n);

    if (content.data == NULL || content.len == 0) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "content result is empty");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = content.len;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate memory for response buffer");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    s = ngx_palloc(r->pool, content.len);
    ngx_memcpy(s, content.data, content.len);

    b->pos = s;
    b->last = s + content.len;

    b->memory = 1;
    b->last_buf = 1;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


/*
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
*/


static int compare_bt(DB *dbp, const DBT *a, const DBT *b) {
    int64_t ai, bi;
    int rt;

    ngx_memcpy(&ai, a->data, sizeof(int64_t));
    ngx_memcpy(&bi, b->data, sizeof(int64_t));

    if (ai > bi) {
        rt = 1;
    } else if (ai == bi) {
        rt = 0;
    } else {
        rt = -1;
    }

    return rt;
}


static ngx_str_t search_db(ngx_http_request_t *r, ngx_http_iplookup_loc_conf_t *conf, int64_t n, ngx_str_t ipaddr) {
    ngx_str_t rs;
    u_char b[DB_MAX_SIZE + 10];

    if (n < 0) {
        if (n == ERROR_INTRANET) {
            ngx_snprintf(b, sizeof(b), "%L\t%V%Z", n, &ipaddr);
        } else {
            ngx_snprintf(b, sizeof(b), "%L%Z", n);
        }
        rs.data = b;
        rs.len = ngx_strlen(b);
        return rs;
    }

    DBT key, data;
    u_char s[DB_MAX_SIZE];
    int rn;

    ngx_memzero(&key, sizeof(DBT));
    ngx_memzero(&data, sizeof(DBT));

    key.data = &n;
    key.size = sizeof(int);

    data.data = s;
    data.ulen = sizeof(b) - 1;
    data.flags = DB_DBT_USERMEM;
    
    rn = conf->dbcp->get(conf->dbcp, &key, &data, DB_SET_RANGE);
    if (rn == 0) {
        ngx_snprintf(b, sizeof(b), "%d\t%s%Z", SUCCESS, s);
    } else if (rn == DB_NOTFOUND) {
        ngx_snprintf(b, sizeof(b), "%d%Z", ERROR_NOTFOUND);
    } else {
        ngx_snprintf(b, sizeof(b), "%d%Z", ERROR_DBFAIL);
    }

    rs.data = b;
    rs.len = ngx_strlen(b);

    return rs;
}


static ngx_http_iplookup_args_t *parse_args(ngx_http_request_t *r) {
    ngx_str_t args_next, args_temp;

    ngx_http_iplookup_args_t *args;
    args = ngx_pcalloc(r->pool, sizeof(ngx_http_iplookup_args_t));
    if (args == NULL) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate memory for args");
    }

    ngx_str_null(&args->ip);
    ngx_str_null(&args->format);
    ngx_str_null(&args->encoding);
    ngx_str_null(&args->obj);

    if (r->args.data == NULL) {
        return args;
    }

    args_next = r->args;
    while (1) {
        args_temp.data = ngx_strlchr(args_next.data, args_next.data + args_next.len, '&');
        if (args_temp.data == NULL) {
            args_temp.data = r->args.data + r->args.len;
        }

        args_temp.len = args_next.len - (args_temp.data - args_next.data);

        if (ngx_strncmp(args_next.data, (const char *) "ip=", 3) == 0) {
            args->ip.len = (args_temp.data - args_next.data) - 3;
            args->ip.data = args_next.data + 3;
        } else if (ngx_strncmp(args_next.data, (const char *) "format=", 7) == 0) {
            args->format.len = (args_temp.data - args_next.data) - 7;
            args->format.data = args_next.data + 7;
            ngx_strlow(args->format.data, args_next.data + 7, args->format.len);
        } else if (ngx_strncmp(args_next.data, (const char *) "encoding=", 9) == 0) {
            args->encoding.len = (args_temp.data - args_next.data) - 9;
            args->encoding.data = args_next.data + 9;
            ngx_strlow(args->encoding.data, args_next.data + 9, args->encoding.len);
        } else if (ngx_strncmp(args_next.data, (const char *) "obj=", 4) == 0) {
            args->obj.len = (args_temp.data - args_next.data) - 4;
            args->obj.data = args_next.data + 4;
        }

        if (args_temp.len == 0) {
            break;
        }

        args_next.data = args_temp.data + 1;
        args_next.len = args_temp.len - 1;
    }

    return args;
}


static int64_t ipaddr_number(ngx_http_request_t *r, ngx_str_t ipaddr) {
    int64_t n = 0;
    ngx_str_t addr_num, addr_next, addr_temp;
    int i;
    int64_t rt;

    addr_next = ipaddr;
    for (i = 3; i > 0; i--) {
        addr_temp.data = ngx_strlchr(addr_next.data, addr_next.data + addr_next.len, '.');
        if (addr_temp.data == NULL) {
            return ERROR_INVALID;
        }
        addr_temp.len = addr_next.len - (addr_temp.data - addr_next.data);

        addr_num.data = addr_next.data;
        addr_num.len = addr_temp.data - addr_next.data;

        rt = ngx_atoi(addr_num.data, addr_num.len) * pow(2, 8 * i);
        if (rt == NGX_ERROR) {
            return ERROR_INVALID;
        }
        n += rt;

        addr_next.data = addr_temp.data + 1;
        addr_next.len = addr_temp.len - 1;
    }
    rt = ngx_atoi(addr_next.data, addr_next.len);
    if (rt == NGX_ERROR) {
        return ERROR_INVALID;
    }
    n += rt;

    if (n < -10) {
        return ERROR_INVALID;
    } else if ((n >= 167772160 && n <= 184549375) || (n >= 3232235520 && n <= 3232301055) || (n >= 2886729728 && n <= 2887778303)) {
        return ERROR_INTRANET;
    }

    //ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "addr_num: %L ", n);

    return n;
}


static ngx_http_iplookup_ipinfo_t *format_ipinfo(ngx_http_request_t *r, ngx_str_t ipinfo_s) {
    ngx_http_iplookup_ipinfo_t *ipinfo;
    ipinfo = ngx_pcalloc(r->pool, sizeof(ngx_http_iplookup_ipinfo_t));
    if (ipinfo == NULL) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate memory for ipinfo");
    }

    if (ngx_strncmp(ipinfo_s.data, (const char *) "-", 1) == 0) {
        ipinfo->ret = -(ngx_atoi(ipinfo_s.data + 1, 1));
        if (ipinfo->ret == ERROR_INTRANET) {
            ipinfo->intip.data = ipinfo_s.data + 3;
            ipinfo->intip.len = ipinfo_s.len - 3;
        }
        return ipinfo;
    }

    ipinfo->a = ngx_array_create(r->pool, 7, sizeof(ngx_str_t));
    ngx_str_t *t;
    int k;
    for (k = 0; k < 7; k++) {
        t = (ngx_str_t *) ngx_array_push(ipinfo->a);
        t->data = NULL;
        t->len = 0;
    }
    ngx_str_t *ipinfo_a;
    ipinfo_a = (ngx_str_t *) ipinfo->a->elts;

    ngx_str_t ipinfo_next, ipinfo_temp, ipinfo_item;
    int i;
    int n = 0;
    int64_t m = 0;
    int country = 0, province = 0, city = 0, district = 0, isp = 0, type = 0;
    int city_offset = 0;
    ipinfo_next = ipinfo_s;
    for (i = 0; i < 9; i++) {
        ipinfo_temp.data = ngx_strlchr(ipinfo_next.data, ipinfo_next.data + ipinfo_next.len, '\t');
        ipinfo_temp.len = ipinfo_next.len - (ipinfo_temp.data - ipinfo_next.data);

        ipinfo_item.data = ipinfo_next.data;
        ipinfo_item.len = ipinfo_temp.data - ipinfo_next.data;

        ipinfo_next.data = ipinfo_temp.data + 1;
        ipinfo_next.len = ipinfo_temp.len - 1;

        if (ipinfo_item.len == 0) {
            continue;
        }

        if (i == 1 || i == 2) {
            m = ngx_atoi(ipinfo_item.data, ipinfo_item.len);
        } else {
            n = ngx_atoi(ipinfo_item.data, ipinfo_item.len);
        }

        switch (i) {
            case 0:
                ipinfo->ret = n;
                break;
            case 1:
                ipinfo->start = m;
                break;
            case 2:
                ipinfo->end = m;
                break;
            case 3:
                country = n - 1;
                ipinfo_a->data = (u_char *) text_countries[country];
                ipinfo_a->len = ngx_strlen(text_countries[country]);
                break;
            case 4:
                province = n - 1;
                (ipinfo_a + 1)->data = (u_char *) text_provinces[country][province];
                (ipinfo_a + 1)->len = ngx_strlen(text_provinces[country][province]);
                break;
            case 5:
                city = n - 1;
                city_offset = city_position[country][province];
                (ipinfo_a + 2)->data = (u_char *) text_cities[city + city_offset];
                (ipinfo_a + 2)->len = ngx_strlen(text_cities[city + city_offset]);
                break;
            case 6:
                district = n - 1;
                (ipinfo_a + 3)->data = (u_char *) text_districts[country][province][city][district];
                (ipinfo_a + 3)->len = ngx_strlen(text_districts[country][province][city][district]);
                break;
            case 7:
                isp = n - 1;
                (ipinfo_a + 4)->data = (u_char *) text_isp[isp];
                (ipinfo_a + 4)->len = ngx_strlen(text_isp[isp]);
                break;
            case 8:
                type = n - 1;
                (ipinfo_a + 5)->data = (u_char *) text_type[type];
                (ipinfo_a + 5)->len = ngx_strlen(text_type[type]);
                break;
        }

    }
    (ipinfo_a + 6)->data = ipinfo_next.data;
    (ipinfo_a + 6)->len = ipinfo_next.len;
    //ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "desc: %V ", &ipinfo->desc);

    return ipinfo;
}


static void *ipinfo_decode_item(ngx_http_request_t *r, ngx_str_t *s, ngx_str_t *ipinfo_item) {
    u_char b[ITEM_MAX_SIZE], p[ITEM_MAX_SIZE];
    int n;
    uint32_t t;

    if (ipinfo_item->data == NULL || ipinfo_item->len == 0) {
        return s;
    }

    n = ngx_utf8_length(ipinfo_item->data, ipinfo_item->len);
    if (n <= 0) {
        return s;
    }

    u_char *item = ipinfo_item->data;
    int len = ipinfo_item->len;
    int i, j, k=0, bn;
    for (i = 0; i < n; i++) {
        t = ngx_utf8_decode(&item, len);
        len = ipinfo_item->len - (item - ipinfo_item->data);
        if (t < 0x80 || t > 0x10ffff) {
            if (k == ITEM_MAX_SIZE) {
                ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Warning: utf8 decode item size too large (max size %d)", ITEM_MAX_SIZE);
                break;
            }
            p[k] = *(item - 1);
            k++;
            continue;
        }
        ngx_memzero(&b, sizeof(b));
        ngx_snprintf(b, sizeof(b), "\\u%04uXD%Z", t);
        //ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "item unicode: %s ", b);
        bn = ngx_strlen(b);
        for (j = 0; j < bn; j++) {
            if (k == ITEM_MAX_SIZE) {
                ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Warning: utf8 decode item size too large (max size %d)", ITEM_MAX_SIZE);
                break;
            }
            p[k] = ngx_tolower(b[j]);
            k++;
        }
    }


    if (k == ITEM_MAX_SIZE) {
        s->data = (u_char *) ITEM_LARGE_ERROR;
        s->len = ngx_strlen(ITEM_LARGE_ERROR);
    } else {
        s->data = p;
        s->len = k;
    }

    return s;
}


static ngx_array_t *ipinfo_decode_array(ngx_http_request_t *r, ngx_array_t *ipinfo) {
    ngx_str_t *ipinfo_a = ipinfo->elts;
    int m = ipinfo->nelts;

    ngx_array_t *ipinfo_a_u = ngx_array_create(r->pool, m, sizeof(ngx_str_t));
    ngx_str_t *item;
    ngx_str_t *s;
    s = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    if (s == NULL) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate memory for decode string");
    }
    int i;
    for (i = 0; i < m; i++) {
        item = (ngx_str_t *) ngx_array_push(ipinfo_a_u);
        ngx_str_null(s);
        ipinfo_decode_item(r, s, ipinfo_a + i);
        item->len = s->len;
        item->data = ngx_pcalloc(r->pool, s->len);
        if (item->data == NULL) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate memory for decode item");
        }
        ngx_memcpy(item->data, s->data, s->len);
    }

    return ipinfo_a_u;
}


static void *ipinfo_iconv_item(ngx_http_request_t *r, ngx_str_t *s, ngx_str_t *ipinfo_item) {
    iconv_t icp;
    u_char p[ITEM_MAX_SIZE];
    char *in = (char *) ipinfo_item->data;
    char *ou = (char *) p;
    size_t inleft = ipinfo_item->len;
    size_t ouleft = ipinfo_item->len;
    size_t rt;
    size_t i, n;

    if (ipinfo_item->data == NULL || ipinfo_item->len == 0) {
        return s;
    }

    icp = iconv_open("GBK", "UTF-8");
    rt = iconv(icp, &in, &inleft, &ou, &ouleft);
    n = ipinfo_item->len - ouleft;
    if (rt == (size_t) -1) {
        for (i = 0; i < inleft; i++ ) {
            p[n] = *(in + i);
            n++;
        }
    }
    iconv_close(icp);

    if (n > ITEM_MAX_SIZE) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Warning: iconv item size %d too large (max size %d)", n, ITEM_MAX_SIZE);
        s->data = (u_char *) ITEM_LARGE_ERROR;
        s->len = ngx_strlen(ITEM_LARGE_ERROR);
    } else {
        s->data = p;
        s->len = n;
    }

    return s;
}


static ngx_array_t *ipinfo_iconv_array(ngx_http_request_t *r, ngx_array_t *ipinfo) {
    ngx_str_t *ipinfo_a = ipinfo->elts;
    int m = ipinfo->nelts;

    ngx_array_t *ipinfo_a_g = ngx_array_create(r->pool, m, sizeof(ngx_str_t));
    ngx_str_t *item;
    ngx_str_t *s;
    s = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    if (s == NULL) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate memory for iconv string");
    }
    int i;
    for (i = 0; i < m; i++) {
        item = (ngx_str_t *) ngx_array_push(ipinfo_a_g);
        ngx_str_null(s);
        ipinfo_iconv_item(r, s, ipinfo_a + i);
        item->len = s->len;
        item->data = ngx_pcalloc(r->pool, s->len);
        if (item->data == NULL) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate memory for iconv item");
        }
        ngx_memcpy(item->data, s->data, s->len);
    }
 
    return ipinfo_a_g;
}


static ngx_array_t *ipinfo_escape_array(ngx_http_request_t *r, ngx_array_t *ipinfo) {
    ngx_str_t *ipinfo_a = ipinfo->elts;
    int m = ipinfo->nelts;

    ngx_array_t *ipinfo_a_e = ngx_array_create(r->pool, m, sizeof(ngx_str_t));
    ngx_str_t *item;
    u_char s[ITEM_MAX_SIZE];
    int i;
    for (i = 0; i < m; i++) {
        item = (ngx_str_t *) ngx_array_push(ipinfo_a_e);
        ngx_memzero(&s, sizeof(s));
        item->len = 2 * ngx_escape_uri(NULL, (ipinfo_a + i)->data, (ipinfo_a + i)->len, NGX_ESCAPE_URI_COMPONENT) + (ipinfo_a + i)->len;
        if (item->len > ITEM_MAX_SIZE) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Warning: escape item size %d too large (max size %d)", item->len, ITEM_MAX_SIZE);
            item->data = (u_char *) ITEM_LARGE_ERROR;
            item->len = ngx_strlen(ITEM_LARGE_ERROR); 
            continue;
        }
        ngx_escape_uri(s, (ipinfo_a + i)->data, (ipinfo_a + i)->len, NGX_ESCAPE_URI_COMPONENT);
        item->data = ngx_pcalloc(r->pool, item->len);
        if (item->data == NULL) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate memory for escape item");
        }
        ngx_memcpy(item->data, s, item->len);
    }
    
    return ipinfo_a_e;
}


static ngx_str_t content_result(ngx_http_request_t *r, ngx_http_iplookup_ipinfo_t *ipinfo, ngx_http_iplookup_args_t *args, ngx_str_t ipaddr, ngx_http_iplookup_loc_conf_t *conf, int64_t n) {
    ngx_str_t content;
    u_char b[1024], c[1024];
    ngx_array_t *ipinfo_a_u;
    ngx_str_t *ipinfo_u;
    ngx_array_t *ipinfo_a_g;
    ngx_str_t *ipinfo_g;
    ngx_array_t *ipinfo_a_e;
    ngx_str_t *ipinfo_e;

    if (ipinfo->ret == SUCCESS) {
        if (n < ipinfo->start) {
            ipinfo->ret = ERROR_NOTFOUND;
            ngx_snprintf(b, sizeof(b) - 1, "%d%Z", ipinfo->ret);
        } else if (args->format.data != NULL && ngx_strncmp(args->format.data, (const char *) "js", 2) == 0) {
            ipinfo_a_u = ipinfo_decode_array(r, ipinfo->a);
            ipinfo_u = ipinfo_a_u->elts;
            if (conf->extra == 1) {
                ngx_snprintf(c, sizeof(c), 
                    "{\"ret\":%d,\"start\":-1,\"end\":-1,"
                    "\"country\":\"%V\","
                    "\"province\":\"%V\","
                    "\"city\":\"%V\","
                    "\"district\":\"%V\","
                    "\"isp\":\"%V\","
                    "\"type\":\"%V\","
                    "\"desc\":\"%V\"}%Z",
                    ipinfo->ret, 
                    ipinfo_u, 
                    ipinfo_u + 1, 
                    ipinfo_u + 2, 
                    ipinfo_u + 3, 
                    ipinfo_u + 4, 
                    ipinfo_u + 5, 
                    ipinfo_u + 6);
            } else {
                ngx_snprintf(c, sizeof(c), 
                    "{\"ret\":%d,\"start\":-1,\"end\":-1,"
                    "\"country\":\"%V\","
                    "\"province\":\"%V\","
                    "\"city\":\"%V\","
                    "\"district\":\"%V\","
                    "\"isp\":\"\",\"type\":\"\",\"desc\":\"\"}%Z",
                    ipinfo->ret, 
                    ipinfo_u, 
                    ipinfo_u + 1, 
                    ipinfo_u + 2, 
                    ipinfo_u + 3);
            }
            if (ngx_strncmp(args->format.data, (const char *) "json", 4) == 0 && args->format.len == 4) {
                ngx_snprintf(b, sizeof(b), "%s%Z", c);
            } else if (ngx_strncmp(args->format.data, (const char *) "js_callback", 11) == 0 && args->format.len == 11) {
                ngx_snprintf(b, sizeof(b), "var remote_ip_info = %s;\n\nremote_ip_info_callback(remote_ip_info);%Z", c);
            } else if (ngx_strncmp(args->format.data, (const char *) "js_async", 8) == 0 && args->format.len == 8) {
                if (args->obj.data == NULL) {
                    ngx_snprintf(b, sizeof(b), "SinaIPData.callback(%s);%Z", c);
                } else {
                    ngx_snprintf(b, sizeof(b), "%V.callback(%s);%Z", &args->obj, c);
                }
            } else {
                ngx_snprintf(b, sizeof(b), "var remote_ip_info = %s;%Z", c);
            }
        } else if (args->format.data != NULL && ngx_strncmp(args->format.data, (const char *) "http", 4) == 0 && args->format.len == 4) {
            if (args->encoding.data != NULL && ngx_strncmp(args->encoding.data, (const char *) "utf-8", 5) == 0 && args->encoding.len == 5) {
                ipinfo_a_e = ipinfo_escape_array(r, ipinfo->a);
            } else {
                ipinfo_a_g = ipinfo_iconv_array(r, ipinfo->a);
                ipinfo_a_e = ipinfo_escape_array(r, ipinfo_a_g);
            }
            ipinfo_e = ipinfo_a_e->elts;

            if (conf->extra == 1) {
                ngx_snprintf(b, sizeof(b),
                    "ret=%d&start=-1&end=-1&country=%V&province=%V&"
                    "city=%V&district=%V&isp=%V&type=%V&desc=%V%Z",
                    ipinfo->ret,
                    ipinfo_e,
                    ipinfo_e + 1,
                    ipinfo_e + 2,
                    ipinfo_e + 3,
                    ipinfo_e + 4,
                    ipinfo_e + 5,
                    ipinfo_e + 6);
            } else {
                ngx_snprintf(b, sizeof(b),
                    "ret=%d&start=-1&end=-1&country=%V&province=%V&"
                    "city=%V&district=%V&isp=&type=&desc=%Z",
                    ipinfo->ret,
                    ipinfo_e,
                    ipinfo_e + 1,
                    ipinfo_e + 2,
                    ipinfo_e + 3);
            }
        } else {
            if (args->encoding.data != NULL && ngx_strncmp(args->encoding.data, (const char *) "utf-8", 5) == 0 && args->encoding.len == 5) {
                ipinfo_a_g = ipinfo->a;
            } else {
                ipinfo_a_g = ipinfo_iconv_array(r, ipinfo->a);
            }
            ipinfo_g = ipinfo_a_g->elts;

            if (conf->extra == 1) {
                ngx_snprintf(b, sizeof(b), 
                    "%d\t-1\t-1\t%V\t%V\t%V\t%V\t%V\t%V\t%V%Z", 
                    ipinfo->ret, 
                    ipinfo_g, 
                    ipinfo_g + 1, 
                    ipinfo_g + 2, 
                    ipinfo_g + 3, 
                    ipinfo_g + 4, 
                    ipinfo_g + 5, 
                    ipinfo_g + 6);
            } else {
                ngx_snprintf(b, sizeof(b), 
                    "%d\t-1\t-1\t%V\t%V\t%V\t%V\t\t\t%Z", 
                    ipinfo->ret, 
                    ipinfo_g, 
                    ipinfo_g + 1, 
                    ipinfo_g + 2, 
                    ipinfo_g + 3);
            }
        }
    } else if (ipinfo->ret == ERROR_INTRANET) {
        if (args->format.data != NULL && ngx_strncmp(args->format.data, (const char *) "js", 2) == 0 && args->format.len == 2) {
            ngx_snprintf(b, sizeof(b), "var remote_ip_info = {\"ret\":%d,\"ip\":\"%V\"};%Z", ipinfo->ret, &ipinfo->intip);
        } else if (args->format.data != NULL && ngx_strncmp(args->format.data, (const char *) "json", 4) == 0 && args->format.len == 4) {
            ngx_snprintf(b, sizeof(b), "{\"ret\":%d,\"ip\":\"%V\"}%Z", ipinfo->ret, &ipinfo->intip);
        } else {
            ngx_snprintf(b, sizeof(b), "%d\t%V%Z", ipinfo->ret, &ipinfo->intip);
        }
    } else {
        ngx_snprintf(b, sizeof(b) - 1, "%d%Z", ipinfo->ret);
    }

    content.data = b;
    content.len = ngx_strlen(b);

    return content;
}
