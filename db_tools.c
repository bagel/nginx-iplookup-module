#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <db.h>


int compare_bt(DB *dbp, const DBT *a, const DBT *b) {
    long ai, bi;
    int rt;

    memcpy(&ai, a->data, sizeof(long));
    memcpy(&bi, b->data, sizeof(long));

    if (ai > bi) {
        rt = 1;
    } else if (ai == bi) {
        rt = 0;
    } else {
        rt = -1;
    }

    return rt;
}


void put_data(DB *dbp, long id, char *s) {
    DBT key, data;
    int rt;

    memset(&key, 0, sizeof(DBT));
    memset(&data, 0, sizeof(DBT));

    key.data = &id;
    key.size = sizeof(long);

    data.data = s;
    data.size = strlen(s) + 1;

    rt = dbp->put(dbp, NULL, &key, &data, 0);
    if (rt != 0) {
        printf("%ld: fail\n", id);
    }
}


void put(const char *db, const char *csv) {
    DB *dbp;
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    char end_id[32];
    char line_new[1024];
    int i, j = 0, k = 0, m = 0, n = 0, h;

    db_create(&dbp, NULL, 0);
    dbp->set_bt_compare(dbp, compare_bt);
    dbp->open(dbp, NULL, db, NULL, DB_BTREE, DB_CREATE, 0);

    fp = fopen(csv, "r");
    getline(&line, &len, fp);
    while (getline(&line, &len, fp) != -1) {
        h = strlen(line) - 1;
        for (i = 0; i < h; i++) {
            if (line[i] == '\t') {
                j++;
            }
            if (j == 1 && line[i] != '\t') {
                end_id[k] = line[i];
                k++;
            }
            if (j == 2) {
                end_id[k] = '\0';
            }
            if (j !=2 && j != 3) {
                line_new[m] = line[i];
                m++;
            }
        }
        line_new[m] = '\0';
        put_data(dbp, atol(end_id), line_new);
        if (n > 1000) {
            dbp->sync(dbp, 0);
            n = 0;
        }
        memset(&end_id, 0, sizeof(end_id));
        memset(&line_new, 0, sizeof(line_new));
        j = m = k = 0;
        n++;
    }

    dbp->sync(dbp, 0);
    dbp->close(dbp, 0);
}


void get_data(DB *dbp, long id) {
    DBT key, data;
    DBC *dbcp;
    char s[1024];
    int rt;

    dbp->cursor(dbp, NULL, &dbcp, 0);

    memset(&key, 0, sizeof(DBT));
    memset(&data, 0, sizeof(DBT));

    key.data = &id;
    key.size = sizeof(long);

    data.data = s;
    data.ulen = 1024;
    data.flags = DB_DBT_USERMEM;

    rt = dbcp->get(dbcp, &key, &data, DB_SET_RANGE);
    if (rt == 0) {
        printf("%ld: %s\n", id, s);
    } else if (rt == DB_NOTFOUND) {
        printf("%ld: not found", id);
    } else {
        printf("%ld: fail %d\n", id, rt);
    }

    dbp->close(dbp, 0);
}


void get(const char *db, long id) {
    DB *dbp;

    db_create(&dbp, NULL, 0);
    dbp->set_bt_compare(dbp, compare_bt);
    dbp->open(dbp, NULL, db, NULL, DB_BTREE, DB_RDONLY, 0);

    get_data(dbp, id);
}


void del(const char *db, long id) {
    DB *dbp;
    DBT key;
    int rt;

    memset(&key, 0, sizeof(DBT));

    key.data = &id;
    key.size = sizeof(long);

    db_create(&dbp, NULL, 0);
    dbp->set_bt_compare(dbp, compare_bt);
    dbp->open(dbp, NULL, db, NULL, DB_BTREE, 0, 0);

    rt = dbp->del(dbp, NULL, &key, 0);

    if (rt == 0) {
        printf("%ld: delete success\n", id);
    } else if (rt == DB_NOTFOUND) {
        printf("%ld: not found\n", id);
    } else {
        printf("%ld: delete fail", id);
    }

    dbp->sync(dbp, 0);
    dbp->close(dbp, 0);
}


int main (int argc, char *argv[]) {
    int opt;
    char *db = NULL, *csv = NULL;
    long id = 0;
    int put_flag = 0, get_flag = 0, del_flag = 0;
    char *usage = "Usage: %s -g -d ip.db -i id, search\n"
                  "       %s -p -c ipdata.csv -d ip.db, convert csv into db\n"
                  "       %s -e -d ip.db -i id, delete\n"
                  "       %s -h, help\n";
                  

    while ((opt = getopt(argc, argv, "d:c:i:pgeh")) != -1) {
        switch (opt) {
            case 'd':
                db = optarg;
                break;
            case 'c':
                csv = optarg;
                break;
            case 'i':
                id = atol(optarg);
                break;
            case 'p':
                put_flag = 1;
                break;
            case 'g':
                get_flag = 1;
                break;
            case 'e':
                del_flag = 1;
                break;
            default:
                fprintf(stderr, usage, argv[0], argv[0], argv[0], argv[0]);
                exit(1);
        }
    }

    if (get_flag == 1) {
        if (id != 0 && db != NULL) {
            get((const char *) db, id);
        } else {
            fprintf(stderr, "Usage: %s -g -d ip.db -i id\n", argv[0], argv[0]);
            exit(1);
        }
    } else if (put_flag == 1) {
        if (db != NULL && csv != NULL) {
            put((const char *) db, (const char *) csv);
        } else {
            fprintf(stderr, "Usage: %s -p -c ipdata.csv -d ip.db\n", argv[0]);
            exit(1);
        }
    } else if (del_flag == 1) {
        if (id != 0 && db != NULL) {
            del((const char *) db, id);
        } else {
            fprintf(stderr, "Usage: %s -e -d ip.db -i id\n", argv[0]);
            exit(1);
        }
    } else {
        printf(usage, argv[0], argv[0], argv[0], argv[0]);
    }
}
