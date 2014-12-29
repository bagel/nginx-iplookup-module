#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <db.h>
#include <math.h>
#include "code_map.h"

typedef struct {
    ngx_str_t database;
} ngx_http_iplookup_loc_conf_t;


typedef struct {
    ngx_str_t ip;
    ngx_str_t format;
} ngx_http_iplookup_args_t;


typedef struct {
    int ret;
    u_int start;
    u_int end;
    ngx_array_t *a;
} ngx_http_iplookup_ipinfo_t;


static ngx_int_t ngx_http_iplookup_init(ngx_conf_t *cf);

static void *ngx_http_iplookup_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_iplookup_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_iplookup_handler(ngx_http_request_t *r);

static int compare_bt(DB *dbp, const DBT *a, const DBT *b);

static ngx_str_t search_db(ngx_http_request_t *r, ngx_http_iplookup_loc_conf_t *conf, u_int n);

static u_int ipaddr_number(ngx_http_request_t *r, ngx_str_t ipaddr);

static ngx_http_iplookup_args_t *parse_args(ngx_http_request_t *r);

static ngx_http_iplookup_ipinfo_t *format_ipinfo(ngx_http_request_t *r, ngx_str_t ipinfo_s);

static ngx_str_t content_result(ngx_http_request_t *r, ngx_http_iplookup_ipinfo_t *ipinfo, ngx_str_t format, ngx_str_t ipaddr);

static ngx_array_t *ipinfo_decode_array(ngx_http_request_t *r, ngx_array_t *ipinfo);

static void *ipinfo_decode_item(ngx_http_request_t *r, u_char *s, ngx_str_t *ipinfo_item);



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


static ngx_int_t ngx_http_iplookup_handler(ngx_http_request_t *r) {
    ngx_int_t rc;
    ngx_buf_t *b;
    ngx_chain_t out;
    u_char *start;
    ngx_str_t ipaddr;
    u_char *content_type;

    ngx_http_iplookup_loc_conf_t *conf;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_iplookup_module);

    //rc = ngx_http_discard_body(r);

    ngx_http_iplookup_args_t *args = parse_args(r);
    
    if (args->format.data != NULL && ngx_strncmp(args->format.data, (const char *) "json", 4) == 0) {
        content_type = (u_char *) "application/json; charset=utf-8";
    } else if (args->format.data != NULL && ngx_strncmp(args->format.data, (const char *) "js", 2) == 0) {
        content_type = (u_char *) "text/javascript; charset=utf-8";
    } else {
        content_type = (u_char *) "text/html; charset=utf-8";
    }

    r->headers_out.content_type.len = ngx_strlen(content_type);
    r->headers_out.content_type.data = content_type;

    if (args->ip.data == NULL) {
        ipaddr = r->connection->addr_text;
    } else {
        ipaddr = args->ip;
    }

    ngx_int_t n = ipaddr_number(r, ipaddr);
    ngx_str_t ipinfo_s = search_db(r, conf, n);
    ngx_http_iplookup_ipinfo_t *ipinfo = format_ipinfo(r, ipinfo_s);
    ngx_str_t content = content_result(r, ipinfo, args->format, ipaddr);

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

    ngx_memcpy(&ai, a->data, sizeof(int));
    ngx_memcpy(&bi, b->data, sizeof(int));
    return (ai - bi);
}


static ngx_str_t search_db(ngx_http_request_t *r, ngx_http_iplookup_loc_conf_t *conf, u_int n) {
    DB *dbp;
    DBC *dbcp;
    DBT key, data;
    u_char b[128], s[128];
    int rn, rt;
    ngx_str_t rs;

    ngx_memzero(&key, sizeof(DBT));
    ngx_memzero(&data, sizeof(DBT));

    key.data = &n;
    key.size = sizeof(int);

    data.data = s;
    data.ulen = sizeof(b) - 1;
    data.flags = DB_DBT_USERMEM;
    
    db_create(&dbp, NULL, 0);
    dbp->set_bt_compare(dbp, compare_bt);
    dbp->open(dbp, NULL, (const char *) conf->database.data, NULL, DB_BTREE, DB_RDONLY, 0);
    dbp->cursor(dbp, NULL, &dbcp, 0);
    rn = dbcp->get(dbcp, &key, &data, DB_SET_RANGE);
    if (rn == 0) {
        rt = 1;
        ngx_snprintf(b, sizeof(b) - 1, "%d\t%s%Z", rt, s);
    } else {
        rt = -2;
        ngx_snprintf(b, sizeof(b) - 1, "%d%Z", rt);
    }

    rs.data = b;
    rs.len = ngx_strlen(b);

    dbcp->close(dbcp);
    dbp->close(dbp, 0);

    return rs;
}


static ngx_http_iplookup_args_t *parse_args(ngx_http_request_t *r) {
    ngx_int_t max_args = 10;
    ngx_str_t args_next, args_temp;

    ngx_http_iplookup_args_t *args;
    args = ngx_pcalloc(r->pool, sizeof(ngx_http_iplookup_args_t));

    ngx_str_null(&args->ip);
    ngx_str_null(&args->format);

    if (r->args.data == NULL) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "args is null");
        return args;
    }

    args_next = r->args;
    int i = 0;
    while (i < max_args) {
        args_temp.data = ngx_strlchr(args_next.data, args_next.data + args_next.len, '&');
        if (args_temp.data == NULL) {
            break;
        }
        args_temp.len = args_next.len - (args_temp.data - args_next.data);

        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "args_temp: %s ", args_temp.data);
        
        if (ngx_strncmp(args_next.data, (const char *) "ip=", 3) == 0) {
            args->ip.len = (args_temp.data - args_next.data) - 3;
            args->ip.data = args_next.data + 3;
        }
        if (ngx_strncmp(args_next.data, (const char *) "format=", 7) == 0) {
            args->format.len = (args_temp.data - args_next.data) - 7;
            args->format.data = args_next.data + 7;
        }

        args_next.data = args_temp.data + 1;
        args_next.len = args_temp.len - 1;

        i++;
    }

    if (ngx_strncmp(args_next.data, (const char *) "ip=", 3) == 0) {
        args->ip.len = args_next.len - 3;
        args->ip.data = args_next.data + 3;
    }
    if (ngx_strncmp(args_next.data, (const char *) "format=", 7) == 0) {
        args->format.len = args_next.len - 7;
        args->format.data = args_next.data + 7;
    }

    return args;
}


static u_int ipaddr_number(ngx_http_request_t *r, ngx_str_t ipaddr) {
    u_int n = 0;
    ngx_str_t addr_num, addr_next, addr_temp;
    int i;

    addr_next = ipaddr;
    for (i = 3; i > 0; i--) {
        addr_temp.data = ngx_strlchr(addr_next.data, addr_next.data + addr_next.len, '.');
        addr_temp.len = addr_next.len - (addr_temp.data - addr_next.data);

        addr_num.data = addr_next.data;
        addr_num.len = addr_temp.data - addr_next.data;

        n += ngx_atoi(addr_num.data, addr_num.len) * pow(2, 8 * i);

        addr_next.data = addr_temp.data + 1;
        addr_next.len = addr_temp.len - 1;
    }
    n += ngx_atoi(addr_next.data, addr_next.len);

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "addr_num: %ud ", n);

    return n;
}


static ngx_http_iplookup_ipinfo_t *format_ipinfo(ngx_http_request_t *r, ngx_str_t ipinfo_s) {
    ngx_http_iplookup_ipinfo_t *ipinfo;
    ipinfo = ngx_pcalloc(r->pool, sizeof(ngx_http_iplookup_ipinfo_t));

    if (ngx_strncmp(ipinfo_s.data, (const char *) "-2", 2) == 0) {
        ipinfo->ret = -2;
        return ipinfo;
    }

    ipinfo->a = ngx_array_create(r->pool, 6, sizeof(ngx_str_t));
    ngx_str_t *t;
    int k;
    for (k = 0; k < 6; k++) {
        t = (ngx_str_t *) ngx_array_push(ipinfo->a);
        t->data = NULL;
        t->len = 0;
    }
    ngx_str_t *ipinfo_a;
    ipinfo_a = (ngx_str_t *) ipinfo->a->elts;

    ngx_str_t ipinfo_next, ipinfo_temp, ipinfo_item;
    int i;
    int n;
    u_int m;
    int country, province, city, district, isp, type;
    ipinfo_next = ipinfo_s;
    for (i = 0; i < 8; i++) {
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
                (ipinfo_a + 2)->data = (u_char *) text_cities[city];
                (ipinfo_a + 2)->len = ngx_strlen(text_cities[city]);
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
        }

    }
    if (ipinfo_next.len > 0) {
        type = ngx_atoi(ipinfo_next.data, ipinfo_next.len) - 1;
        (ipinfo_a + 5)->data = (u_char *) text_type[type];
        (ipinfo_a + 5)->len = ngx_strlen(text_type[type]);
    }


    return ipinfo;
}


static void *ipinfo_decode_item(ngx_http_request_t *r, u_char *s, ngx_str_t *ipinfo_item) {
    u_char b[128];
    int n;
    uint32_t t;

    s[0] = '\0';
    n = ngx_utf8_length(ipinfo_item->data, ipinfo_item->len);
    if (n <= 0) {
        return s;
    }

    int i;
    for (i = 0; i < n; i++) {
        t = ngx_utf8_decode(&ipinfo_item->data, ipinfo_item->len);
        ngx_memzero(&b, sizeof(b));
        ngx_snprintf(b, sizeof(b) - 1, "\\u%uXD%Z", t);
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "item unicode: %s ", b);
        int len_b = ngx_strlen(b);
        int len_s = ngx_strlen(s);
        int j;
        for (j = 0; j <= len_b; j++) {
            s[len_s + j] = ngx_tolower(b[j]);
        }
    }

    return s;
}


static ngx_array_t *ipinfo_decode_array(ngx_http_request_t *r, ngx_array_t *ipinfo) {
    ngx_str_t *ipinfo_a = ipinfo->elts;
    int m = ipinfo->nelts;
    ngx_array_t *ipinfo_a_u = ngx_array_create(r->pool, m, sizeof(ngx_str_t));
    ngx_str_t *t;
    int i;
    for (i = 0; i < m; i++) {
        t = (ngx_str_t *) ngx_array_push(ipinfo_a_u);
        t->len = 0;
        t->data = NULL;
    }

    ngx_str_t *ipinfo_u = ipinfo_a_u->elts;

    u_char country[128], province[128], city[128], district[128], isp[128], type[128];

    ipinfo_decode_item(r, country, ipinfo_a);
    ipinfo_u->len = ngx_strlen(country);
    ipinfo_u->data = country;

    ipinfo_decode_item(r, province, ipinfo_a + 1);
    (ipinfo_u + 1)->len = ngx_strlen(province);
    (ipinfo_u + 1)->data = province;

    ipinfo_decode_item(r, city, ipinfo_a + 2);
    (ipinfo_u + 2)->len = ngx_strlen(city);
    (ipinfo_u + 2)->data = city;

    ipinfo_decode_item(r, district, ipinfo_a + 3);
    (ipinfo_u + 3)->len = ngx_strlen(district);
    (ipinfo_u + 3)->data = district;

    ipinfo_decode_item(r, isp, ipinfo_a + 4);
    (ipinfo_u + 4)->len = ngx_strlen(isp);
    (ipinfo_u + 4)->data = isp;

    ipinfo_decode_item(r, type, ipinfo_a + 5);
    (ipinfo_u + 5)->len = ngx_strlen(type);
    (ipinfo_u + 5)->data = type;

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "item array: %V ", ipinfo_u);

    return ipinfo_a_u;
}


static ngx_str_t content_result(ngx_http_request_t *r, ngx_http_iplookup_ipinfo_t *ipinfo, ngx_str_t format, ngx_str_t ipaddr) {
    ngx_str_t content;
    u_char b[1024];
    ngx_str_t *ipinfo_a = ipinfo->a->elts;

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "country: %V, province: %V, type: %V ", ipinfo_a, ipinfo_a + 1, ipinfo_a + 5);

    if (ipinfo->ret == 1) {
        if (format.data != NULL && ngx_strncmp(format.data, (const char *) "js", 2) == 0) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "decode before ");
            ngx_array_t *ipinfo_a_u = ipinfo_decode_array(r, ipinfo->a);
            ngx_str_t *ipinfo_u = ipinfo_a_u->elts;
            if (format.data != NULL && ngx_strncmp(format.data, (const char *) "json", 4) == 0) {
                ngx_snprintf(b, sizeof(b) - 1, "{\"ret\":1,\"start\":-1,\"end\":-1,\"country\":\"%V\",\"province\":\"%V\",\"city\":\"%V\",\"district\":\"%V\",\"isp\":\"%V\",\"type\":\"%V\",\"desc\":\"\"}%Z", ipinfo_u, ipinfo_u + 1, ipinfo_u + 2, ipinfo_u + 3, ipinfo_u + 4, ipinfo_u + 5);
            } else {
                ngx_snprintf(b, sizeof(b) - 1, "var remote_ip_info = {\"ret\":1,\"start\":-1,\"end\":-1,\"country\":\"%V\",\"province\":\"%V\",\"city\":\"%V\",\"district\":\"%V\",\"isp\":\"%V\",\"type\":\"%V\",\"desc\":\"\"}%Z", ipinfo_u, ipinfo_u + 1, ipinfo_u + 2, ipinfo_u + 3, ipinfo_u + 4, ipinfo_u + 5);
            }
        } else {
            ngx_snprintf(b, sizeof(b) - 1, "1\t-1\t-1\t%V\t%V\t%V\t%V\t%V\t%V\t%Z", ipinfo_a, ipinfo_a + 1, ipinfo_a + 2, ipinfo_a + 3, ipinfo_a + 4, ipinfo_a + 5);
        }
    } else {
        ngx_snprintf(b, sizeof(b) - 1, "%d", ipinfo->ret);
    }

    content.data = b;
    content.len = ngx_strlen(b);

    return content;
}
