/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2006 Cisco Systems.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#define EX4

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/time.h>
#include <stdlib.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#include <infiniband/verbs.h>

#ifdef EX4
#include <fcntl.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/stat.h>
#endif

int g_argc;
char **g_argv;
uint64_t  id_cnt = 1000;



#define EAGER_PROTOCOL_LIMIT (1 << 12) /* 4KB limit */
#define MAX_TEST_SIZE (0 * EAGER_PROTOCOL_LIMIT)
#define TEST_LOCATION "~/www/"
enum operation_type
{
    SELF_LOCAL_SEND,
    SELF_LOCAL_RECV,
    SELF_RDMA_READ,
    SELF_RDMA_WRITE,
    REMOTE_RDMA_READ,
    REMOTE_RDMA_WRITE,
};
enum packet_type {
    EAGER_GET_REQUEST,
    EAGER_GET_RESPONSE,
    EAGER_SET_REQUEST,
    //EAGER_SET_RESPONSE

    RENDEZVOUS_GET_REQUEST,
    RENDEZVOUS_GET_RESPONSE,
    RENDEZVOUS_SET_REQUEST,
    RENDEZVOUS_SET_RESPONSE,
    RENDEZVOUS_DONE,

#ifdef EX4
    FIND,
    LOCATION,
#endif
};


#define PAYLOAD_SIZE4k 4096 - 4
#define PAYLOAD_SIZE4k_MINUS_UINT PAYLOAD_SIZE4k - 4


/* Added by Oren & Efi */
struct wrnode_t
{
    struct mrnode_t* next;
    struct ibv_mr* p_mr;
    uint64_t    wr_id;
    uint64_t    hash;
    uint8_t    user;
    uint8_t     operation;
    int    counter;
    void*  ctx; // struct pingpong_context*
} typedef wrnode_t;

wrnode_t*   wr_head;
static struct ibv_cq *global_cq = NULL;
static struct ibv_context	*global_context = NULL;

//FILE* my_file = fopen("ex3_test.txt", 'r');
FILE* my_file;
struct kv_file
{
    int type;
    char* key;
    char* value;

};

struct kv_file parse_file(FILE** myfile)
{
    FILE* file = *myfile;
    struct kv_file ret = {0};

    char gs_txt[6] = {0};

    fscanf(file, "%3[^\n]s", gs_txt);
    if (feof(file))
    {
        ret.type = EOF;
        return ret;
    }
    printf("get or set: %s\n", gs_txt);

    fseek(file, 1, SEEK_CUR);
    if (strlen(gs_txt) == 3)
    {
        ret.type = strcmp("set", gs_txt) ? 1 : 0;
    } else {
        assert("error: set or get not found");
    }
    if (ret.type == 0)
    {
        // SET
        int length = 0;
        length = ftell(file);
        while (fgetc(file) != '\n');
        length = ftell(file) - length;
        fseek(file, -length, SEEK_CUR);
        ret.key = (char*)malloc(length);
        assert(ret.key);
        fscanf(file, "%[^\n]s", ret.key);
        fseek(file, 1, SEEK_CUR);
        length = ftell(file);
        while (fgetc(file) != '\n');
        length = ftell(file) - length;
        fseek(file, -length, SEEK_CUR);
        ret.value = (char*)malloc(length);
        assert(ret.value);
        fscanf(file, "%[^\n]s", ret.value);
        fseek(file, 1, SEEK_CUR);

        return ret;
    }
    else if (ret.type == 1)
    {
        // GET
        int length = 0;
        length = ftell(file);
        while (fgetc(file) != '\n');
        length = ftell(file) - length;
        fseek(file, -length, SEEK_CUR);
        ret.key = (char*)malloc(length);
        assert(ret.key);
        fscanf(file, "%[^\n]s", ret.key);
        fseek(file, 1, SEEK_CUR);
        printf("got key: %s\n", ret.key);
        return ret;
    }

}
struct kv_node {
    char *key;
    char *value;
    struct kv_node *next;
} typedef kv_node;

kv_node* kv_head = NULL;
char* get_kv_value(char* key, kv_node *node)
{
    if (node == NULL)
    {
        /* if node does not exist (end) return NULL */
        return NULL;
    }
    if (!strcmp(key,node->key))
    {
        /* get in if node holds the key */
        return node->value;
    } else {
        /* get in if node does not holds the key */
        /* go to the next node */
        return get_kv_value(key, node->next);
    }
}
void free_kv_value(char* key, kv_node *head)
{
    kv_node* prev = head;
    kv_node* node = head->next;
    while (node)
    {
        if (!strcmp(key,node->key))
        {
            prev->next = node->next;
            free(node->value);
            free(node->key);
            free(node);
            break;
        }
        else
        {
            prev = node;
            node = node->next;
        }
    }

}
void set_kv_value(char* key, char* value)
{
    kv_node* kv_object = (kv_node*)malloc(sizeof(kv_node));
    assert(kv_object);
    kv_object->key = key;
    kv_object->value = value;
    kv_object->next = kv_head;
    kv_head = kv_object;
}


struct packet {
    enum packet_type type; /* What kind of packet/protocol is this */
    union {
        /* The actual packet type will determine which struct will be used: */

        struct {
            char value[0];
        } eager_get_request;

        struct {
            unsigned int value_length;
            char value[0];
        } eager_get_response;

        /* EAGER PROTOCOL PACKETS */
        struct {
#ifdef EX4
            unsigned value_length; /* value is binary, so needs to have length! */
#endif
            char key_and_value[0]; /* null terminator between key and value */
        } eager_set_request;

        struct {
            /* TODO */
        } eager_set_response;

        /* RENDEZVOUS PROTOCOL PACKETS */
        struct {
            uint8_t key_addr_and_key_size[0];
        } rndv_get_request;

        struct {
            uint8_t params[0];
        } rndv_get_response;

        struct {
            uint8_t kv_params[0];
        } rndv_set_request;

        struct {
            uint8_t kv_addresses[0];
        } rndv_set_response;

        /* TODO - maybe there are more packet types? */

#ifdef EX4
        struct {
            unsigned num_of_servers;
            char key[0];
        } find;

        struct {
            uint8_t selected_server[0]; //enough 1 byte
        } location;

        struct {
            uint8_t hashvalue[0]; //8 bytes
        } rdma_done;
#endif
    };
};


struct kv_server_address {
    char *servername; /* In the last item of an array this is NULL */
    short port; /* This is useful for multiple servers on a host */
};

enum {
    PINGPONG_RECV_WRID = 1,
    PINGPONG_SEND_WRID = 2,
    PINGPONG_SEND_RDMA_READ_WRID = 3,
    PINGPONG_SEND_RDMA_WRITE_WRID = 4,
};

static int page_size;

struct pingpong_context {
    struct ibv_context	*context;
    struct ibv_comp_channel *channel;
    struct ibv_pd		*pd;
    struct ibv_mr		*mr;
    struct ibv_cq		*cq;
    struct ibv_qp		*qp;
    void			*buf;
    int			 size;
    int			 rx_depth;
    int          routs;
    int			 pending;
    struct ibv_port_attr     portinfo;
};

struct pingpong_dest {
    int lid;
    int qpn;
    int psn;
    union ibv_gid gid;
};

enum ibv_mtu pp_mtu_to_enum(int mtu)
{
    switch (mtu) {
        case 256:  return IBV_MTU_256;
        case 512:  return IBV_MTU_512;
        case 1024: return IBV_MTU_1024;
        case 2048: return IBV_MTU_2048;
        case 4096: return IBV_MTU_4096;
        default:   return -1;
    }
}
uint32_t pp_wait_cq(struct pingpong_context *ctx)
{
    int ne;
    struct ibv_wc wc[1];
    do {
        ne = ibv_poll_cq(ctx->cq, 1, wc);
        if (ne < 0) {
            fprintf(stderr, "poll CQ failed %d\n", ne);
            return 1;
        }

    } while (ne < 1);
    return 0;
}
uint16_t pp_get_local_lid(struct ibv_context *context, int port)
{
    struct ibv_port_attr attr;

    if (ibv_query_port(context, port, &attr))
        return 0;

    return attr.lid;
}

int pp_get_port_info(struct ibv_context *context, int port,
                     struct ibv_port_attr *attr)
{
    return ibv_query_port(context, port, attr);
}

void wire_gid_to_gid(const char *wgid, union ibv_gid *gid)
{
    char tmp[9];
    uint32_t v32;
    int i;

    for (tmp[8] = 0, i = 0; i < 4; ++i) {
        memcpy(tmp, wgid + i * 8, 8);
        sscanf(tmp, "%x", &v32);
        *(uint32_t *)(&gid->raw[i * 4]) = ntohl(v32);
    }
}

void gid_to_wire_gid(const union ibv_gid *gid, char wgid[])
{
    int i;

    for (i = 0; i < 4; ++i)
        sprintf(&wgid[i * 8], "%08x", htonl(*(uint32_t *)(gid->raw + i * 4)));
}

static int pp_connect_ctx(struct pingpong_context *ctx, int port, int my_psn,
                          enum ibv_mtu mtu, int sl,
                          struct pingpong_dest *dest, int sgid_idx)
{
    struct ibv_qp_attr attr = {
            .qp_state		= IBV_QPS_RTR,
            .path_mtu		= mtu,
            .dest_qp_num		= dest->qpn,
            .rq_psn			= dest->psn,
            .max_dest_rd_atomic	= 1,
            .min_rnr_timer		= 12,
            .ah_attr		= {
                    .is_global	= 0,
                    .dlid		= dest->lid,
                    .sl		= sl,
                    .src_path_bits	= 0,
                    .port_num	= port
            }
    };

    if (dest->gid.global.interface_id) {
        attr.ah_attr.is_global = 1;
        attr.ah_attr.grh.hop_limit = 1;
        attr.ah_attr.grh.dgid = dest->gid;
        attr.ah_attr.grh.sgid_index = sgid_idx;
    }
    if (ibv_modify_qp(ctx->qp, &attr,
                      IBV_QP_STATE              |
                      IBV_QP_AV                 |
                      IBV_QP_PATH_MTU           |
                      IBV_QP_DEST_QPN           |
                      IBV_QP_RQ_PSN             |
                      IBV_QP_MAX_DEST_RD_ATOMIC |
                      IBV_QP_MIN_RNR_TIMER)) {
        fprintf(stderr, "Failed to modify QP to RTR\n");
        return 1;
    }

    attr.qp_state	    = IBV_QPS_RTS;
    attr.timeout	    = 14;
    attr.retry_cnt	    = 7;
    attr.rnr_retry	    = 7;
    attr.sq_psn	    = my_psn;
    attr.max_rd_atomic  = 1;
    if (ibv_modify_qp(ctx->qp, &attr,
                      IBV_QP_STATE              |
                      IBV_QP_TIMEOUT            |
                      IBV_QP_RETRY_CNT          |
                      IBV_QP_RNR_RETRY          |
                      IBV_QP_SQ_PSN             |
                      IBV_QP_MAX_QP_RD_ATOMIC)) {
        fprintf(stderr, "Failed to modify QP to RTS\n");
        return 1;
    }

    return 0;
}

static struct pingpong_dest *pp_client_exch_dest(const char *servername, int port,
                                                 const struct pingpong_dest *my_dest)
{
    struct addrinfo *res, *t;
    struct addrinfo hints = {
            .ai_family   = AF_INET,
            .ai_socktype = SOCK_STREAM
    };
    char *service;
    char msg[sizeof "0000:000000:000000:00000000000000000000000000000000"];
    int n;
    int sockfd = -1;
    struct pingpong_dest *rem_dest = NULL;
    char gid[33];

    if (asprintf(&service, "%d", port) < 0)
        return NULL;

    n = getaddrinfo(servername, service, &hints, &res);

    if (n < 0) {
        fprintf(stderr, "%s for %s:%d\n", gai_strerror(n), servername, port);
        free(service);
        return NULL;
    }

    for (t = res; t; t = t->ai_next) {
        sockfd = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
        if (sockfd >= 0) {
            if (!connect(sockfd, t->ai_addr, t->ai_addrlen))
                break;
            close(sockfd);
            sockfd = -1;
        }
    }

    freeaddrinfo(res);
    free(service);

    if (sockfd < 0) {
        fprintf(stderr, "Couldn't connect to %s:%d\n", servername, port);
        return NULL;
    }

    gid_to_wire_gid(&my_dest->gid, gid);
    sprintf(msg, "%04x:%06x:%06x:%s", my_dest->lid, my_dest->qpn, my_dest->psn, gid);
    if (write(sockfd, msg, sizeof msg) != sizeof msg) {
        fprintf(stderr, "Couldn't send local address\n");
        goto out;
    }

    if (read(sockfd, msg, sizeof msg) != sizeof msg) {
        perror("client read");
        fprintf(stderr, "Couldn't read remote address\n");
        goto out;
    }

    write(sockfd, "done", sizeof "done");

    rem_dest = malloc(sizeof *rem_dest);
    if (!rem_dest)
        goto out;

    sscanf(msg, "%x:%x:%x:%s", &rem_dest->lid, &rem_dest->qpn, &rem_dest->psn, gid);
    wire_gid_to_gid(gid, &rem_dest->gid);

    out:
    close(sockfd);
    return rem_dest;
}

static struct pingpong_dest *pp_server_exch_dest(struct pingpong_context *ctx,
                                                 int ib_port, enum ibv_mtu mtu,
                                                 int port, int sl,
                                                 const struct pingpong_dest *my_dest,
                                                 int sgid_idx)
{
    struct addrinfo *res, *t;
    struct addrinfo hints = {
            .ai_flags    = AI_PASSIVE,
            .ai_family   = AF_INET,
            .ai_socktype = SOCK_STREAM
    };
    char *service;
    char msg[sizeof "0000:000000:000000:00000000000000000000000000000000"];
    int n;
    int sockfd = -1, connfd;
    struct pingpong_dest *rem_dest = NULL;
    char gid[33];

    if (asprintf(&service, "%d", port) < 0)
        return NULL;

    n = getaddrinfo(NULL, service, &hints, &res);

    if (n < 0) {
        fprintf(stderr, "%s for port %d\n", gai_strerror(n), port);
        free(service);
        return NULL;
    }

    for (t = res; t; t = t->ai_next) {
        sockfd = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
        if (sockfd >= 0) {
            n = 1;

            setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &n, sizeof n);

            if (!bind(sockfd, t->ai_addr, t->ai_addrlen))
                break;
            close(sockfd);
            sockfd = -1;
        }
    }

    freeaddrinfo(res);
    free(service);

    if (sockfd < 0) {
        fprintf(stderr, "Couldn't listen to port %d\n", port);
        return NULL;
    }

    listen(sockfd, 1);
    connfd = accept(sockfd, NULL, 0);
    close(sockfd);
    if (connfd < 0) {
        fprintf(stderr, "accept() failed\n");
        return NULL;
    }

    n = read(connfd, msg, sizeof msg);
    if (n != sizeof msg) {
        perror("server read");
        fprintf(stderr, "%d/%d: Couldn't read remote address\n", n, (int) sizeof msg);
        goto out;
    }

    rem_dest = malloc(sizeof *rem_dest);
    if (!rem_dest)
        goto out;

    sscanf(msg, "%x:%x:%x:%s", &rem_dest->lid, &rem_dest->qpn, &rem_dest->psn, gid);
    wire_gid_to_gid(gid, &rem_dest->gid);

    if (pp_connect_ctx(ctx, ib_port, my_dest->psn, mtu, sl, rem_dest, sgid_idx)) {
        fprintf(stderr, "Couldn't connect to remote QP\n");
        free(rem_dest);
        rem_dest = NULL;
        goto out;
    }


    gid_to_wire_gid(&my_dest->gid, gid);
    sprintf(msg, "%04x:%06x:%06x:%s", my_dest->lid, my_dest->qpn, my_dest->psn, gid);
    if (write(connfd, msg, sizeof msg) != sizeof msg) {
        fprintf(stderr, "Couldn't send local address\n");
        free(rem_dest);
        rem_dest = NULL;
        goto out;
    }

    read(connfd, msg, sizeof msg);

    out:
    close(connfd);
    return rem_dest;
}

#include <sys/param.h>
#include "hash.h"

static struct pingpong_context *pp_init_ctx(struct ibv_device *ib_dev, int size,
                                            int rx_depth, int port,
                                            int use_event, int is_server)
{
    struct pingpong_context *ctx;

    ctx = calloc(1, sizeof *ctx);
    if (!ctx)
        return NULL;

    ctx->size     = size;
    ctx->rx_depth = rx_depth;
    ctx->routs    = rx_depth;

    ctx->buf = malloc(roundup(size, page_size));
    if (!ctx->buf) {
        fprintf(stderr, "Couldn't allocate work buf.\n");
        return NULL;
    }

    memset(ctx->buf, 0x7b + is_server, size);
    if (global_context == NULL) {
        ctx->context = ibv_open_device(ib_dev);
        global_context = ctx->context;
    }
    ctx->context = global_context;

    if (!ctx->context) {
        fprintf(stderr, "Couldn't get context for %s\n",
                ibv_get_device_name(ib_dev));
        return NULL;
    }
    printf("ctx->context %p\n", ctx->context);
    if (use_event) {
        ctx->channel = ibv_create_comp_channel(ctx->context);
        if (!ctx->channel) {
            fprintf(stderr, "Couldn't create completion channel\n");
            return NULL;
        }
    } else
        ctx->channel = NULL;

    ctx->pd = ibv_alloc_pd(ctx->context);
    if (!ctx->pd) {
        fprintf(stderr, "Couldn't allocate PD\n");
        return NULL;
    }

    ctx->mr = ibv_reg_mr(ctx->pd, ctx->buf, size, IBV_ACCESS_LOCAL_WRITE);
    if (!ctx->mr) {
        fprintf(stderr, "Couldn't register MR\n");
        return NULL;
    }
    if (global_cq == NULL) {
        ctx->cq = ibv_create_cq(ctx->context, rx_depth + 1, NULL,
                                ctx->channel, 0);
        global_cq = ctx->cq;
    }
    else
        ctx->cq = global_cq;
    if (!ctx->cq) {
        fprintf(stderr, "Couldn't create CQ\n");
        return NULL;
    }
    printf("cq %p\n", ctx->cq);
    {
        struct ibv_qp_init_attr attr = {
                .send_cq = ctx->cq,
                .recv_cq = ctx->cq,
                .cap     = {
                        .max_send_wr  = 1,
                        .max_recv_wr  = rx_depth,
                        .max_send_sge = 1,
                        .max_recv_sge = 1
                },
                .qp_type = IBV_QPT_RC
        };

        ctx->qp = ibv_create_qp(ctx->pd, &attr);
        if (!ctx->qp)  {
            fprintf(stderr, "Couldn't create QP\n");
            perror("");
            return NULL;
        }
    }

    {
        struct ibv_qp_attr attr = {
                .qp_state        = IBV_QPS_INIT,
                .pkey_index      = 0,
                .port_num        = port,
                .qp_access_flags = IBV_ACCESS_REMOTE_READ |
                                   IBV_ACCESS_REMOTE_WRITE
        };

        if (ibv_modify_qp(ctx->qp, &attr,
                          IBV_QP_STATE              |
                          IBV_QP_PKEY_INDEX         |
                          IBV_QP_PORT               |
                          IBV_QP_ACCESS_FLAGS)) {
            fprintf(stderr, "Failed to modify QP to INIT\n");
            return NULL;
        }
    }

    return ctx;
}

int pp_close_ctx(struct pingpong_context *ctx)
{
    if (ibv_destroy_qp(ctx->qp)) {
        fprintf(stderr, "Couldn't destroy QP\n");
        return 1;
    }

    if (ibv_destroy_cq(ctx->cq)) {
        fprintf(stderr, "Couldn't destroy CQ\n");
        return 1;
    }

    if (ibv_dereg_mr(ctx->mr)) {
        fprintf(stderr, "Couldn't deregister MR\n");
        return 1;
    }

    if (ibv_dealloc_pd(ctx->pd)) {
        perror("");
        fprintf(stderr, "Couldn't deallocate PD\n");
        return 1;
    }

    if (ctx->channel) {
        if (ibv_destroy_comp_channel(ctx->channel)) {
            fprintf(stderr, "Couldn't destroy completion channel\n");
            return 1;
        }
    }

    if (ibv_close_device(ctx->context)) {
        fprintf(stderr, "Couldn't release context\n");
        return 1;
    }

    free(ctx->buf);
    free(ctx);

    return 0;
}
static int pp_post_recv_user(struct pingpong_context *ctx, int n, uint64_t wrid)
{
    struct ibv_sge list = {
            .addr	= (uintptr_t) ctx->buf,
            .length = ctx->size,
            .lkey	= ctx->mr->lkey
    };
    struct ibv_recv_wr wr = {
            .wr_id	    = wrid,
            .sg_list    = &list,
            .num_sge    = 1,
            .next       = NULL
    };
    struct ibv_recv_wr *bad_wr;
    int i;

    for (i = 0; i < n; ++i)
        if (ibv_post_recv(ctx->qp, &wr, &bad_wr))
            break;
    return i;
}

static int pp_post_recv(struct pingpong_context *ctx, int n)
{
    struct ibv_sge list = {
            .addr	= (uintptr_t) ctx->buf,
            .length = ctx->size,
            .lkey	= ctx->mr->lkey
    };
    struct ibv_recv_wr wr = {
            .wr_id	    = PINGPONG_RECV_WRID,
            .sg_list    = &list,
            .num_sge    = 1,
            .next       = NULL
    };
    struct ibv_recv_wr *bad_wr;
    int i;

    for (i = 0; i < n; ++i)
        if (ibv_post_recv(ctx->qp, &wr, &bad_wr))
            break;
    return i;
}
static int pp_post_send_rdmaread(struct pingpong_context *ctx, enum ibv_wr_opcode opcode, unsigned size, const char *local_ptr, void *remote_ptr, uint32_t remote_key, uint64_t id)
{
    struct ibv_sge list = {
            .addr	= (uintptr_t) (local_ptr ? local_ptr : ctx->buf),
            .length = size,
            .lkey	= ctx->mr->lkey
    };
    struct ibv_send_wr wr = {
            .wr_id	    = id,
            .sg_list    = &list,
            .num_sge    = 1,
            .opcode     = opcode,
            .send_flags = IBV_SEND_SIGNALED,
            .next       = NULL
    };

    struct ibv_send_wr *bad_wr;

    if (remote_ptr) {
        wr.wr.rdma.remote_addr = (uintptr_t) remote_ptr;
        wr.wr.rdma.rkey = remote_key;
    }
    return ibv_post_send(ctx->qp, &wr, &bad_wr);
}
static int pp_post_send(struct pingpong_context *ctx, enum ibv_wr_opcode opcode, unsigned size, const char *local_ptr, void *remote_ptr, uint32_t remote_key)
{
    struct ibv_sge list = {
            .addr	= (uintptr_t) (local_ptr ? local_ptr : ctx->buf),
            .length = size,
            .lkey	= ctx->mr->lkey
    };
    struct ibv_send_wr wr = {
            .wr_id	    = PINGPONG_SEND_WRID,
            .sg_list    = &list,
            .num_sge    = 1,
            .opcode     = opcode,
            .send_flags = IBV_SEND_SIGNALED,
            .next       = NULL
    };

    struct ibv_send_wr *bad_wr;

    if (remote_ptr) {
        wr.wr.rdma.remote_addr = (uintptr_t) remote_ptr;
        wr.wr.rdma.rkey = remote_key;
    }
    return ibv_post_send(ctx->qp, &wr, &bad_wr);
}

static void usage(const char *argv0)
{
    printf("Usage:\n");
    printf("  %s            start a server and wait for connection\n", argv0);
    printf("  %s <host>     connect to server at <host>\n", argv0);
    printf("\n");
    printf("Options:\n");
    printf("  -p, --port=<port>      listen on/connect to port <port> (default 18515)\n");
    printf("  -d, --ib-dev=<dev>     use IB device <dev> (default first device found)\n");
    printf("  -i, --ib-port=<port>   use port <port> of IB device (default 1)\n");
    printf("  -s, --size=<size>      size of message to exchange (default 4096)\n");
    printf("  -m, --mtu=<size>       path MTU (default 1024)\n");
    printf("  -r, --rx-depth=<dep>   number of receives to post at a time (default 500)\n");
    printf("  -n, --iters=<iters>    number of exchanges (default 1000)\n");
    printf("  -l, --sl=<sl>          service level value\n");
    printf("  -e, --events           sleep on CQ events (default poll)\n");
    printf("  -g, --gid-idx=<gid index> local port gid index\n");
}
void add_work_request(uint64_t id, uint8_t user, struct ibv_mr* mr, void* ctx, uint64_t hash, uint8_t operation)
{
    wrnode_t *temp, *prev;
    if (wr_head == NULL)
    {
        //add the first node
        temp = (wrnode_t*)malloc(sizeof(wrnode_t));
        temp->next = NULL;
        temp->wr_id = id;
        temp->counter = 0;
        temp->p_mr = mr;
        temp->user = user;
        temp->ctx = ctx;
        temp->hash = hash;
        temp->operation = operation;
        wr_head = temp;
        return;
    }

    prev = temp = wr_head;
    while(temp)
    {
        prev = temp;
        temp = temp->next;
    }

    temp = (wrnode_t*)malloc(sizeof(wrnode_t));

    if (!temp)
    {
        exit(1);
    }
    prev->next = temp;
    temp->next = NULL;
    temp->wr_id = id;
    temp->counter = 0;
    temp->p_mr = mr;
    temp->user = user;
    temp->ctx = ctx;
}
wrnode_t* pop_wrnode(uint64_t id)
{
    wrnode_t *temp, *prev;
    temp = wr_head;
    while (temp != NULL && temp->wr_id != id)
    {
        prev = temp;
        temp = temp->next;
    }
    if (temp == wr_head)
    {
        //this is the head
        wr_head = wr_head->next;
    } else {
        prev->next = temp->next;
    }
    return temp; //callee is not responsible for free this node, the caller is responsible
}
int wr_exist(uint64_t id)
{
    wrnode_t *temp;
    if(!wr_head)
    {
        return 0;
    }
    else
    {
        temp = wr_head;
        while (temp)
        {
            if (temp->wr_id != id)
            {
                temp = temp->next;
            } else {
                return 1;
            }
        }
        return 0;
    }
}
int rendezvous_set_req_handler(struct pingpong_context *ctx, struct packet *packet, uint8_t user)
{
    uint32_t* remote_key;
    uint64_t* remote_addr;
    uint32_t* remote_size;
    uint8_t*  remote_keyval;

    struct ibv_mr *r_mr;

    // parse the details of the KV to be set from the packet
    remote_key  = (packet->rndv_set_request.kv_params + 0);     //the remote key
    remote_addr = (packet->rndv_set_request.kv_params + 4);     //the remote address
    remote_size = (packet->rndv_set_request.kv_params + 12);    //the remote value size
    remote_keyval = (packet->rndv_set_request.kv_params + 16);  //the remote key (array of chars)

    // allocate the space for KV node
    uint32_t key_size = strlen(remote_keyval) + 1;
    uint8_t* key_str  = (uint8_t*)malloc(key_size);
    if (key_str == NULL) {
        fprintf(stderr, "Failed to allocate memory to key_str\n");
        return 1;
    }
    strcpy(key_str, remote_keyval);
    uint8_t* value_str = (uint8_t*)malloc(*remote_size);
    if (value_str == NULL) {
        fprintf(stderr, "Failed to allocate memory to value_str\n");
        return 1;
    }
    // register the memory region for the KV node LOCAL_WRITE
    struct ibv_mr *mr;
    struct ibv_sge sge;
    struct ibv_send_wr wr, *bad_wr;
    r_mr = ibv_reg_mr(ctx->pd, value_str,*remote_size, IBV_ACCESS_LOCAL_WRITE);
    if (r_mr == NULL) {
        fprintf(stderr, "Failed to register memory region\n");
        return 1;
    }
    struct ibv_mr* temp_mr = ctx->mr; // TODO test if really needed
    ctx->mr = r_mr;

    // post send using REMOTE READ
    pp_post_send_rdmaread(ctx,IBV_ACCESS_REMOTE_READ, *remote_size ,value_str, *remote_addr, *remote_key, id_cnt);
    ctx->mr = temp_mr;

    // register work request
    add_work_request(id_cnt++, user, r_mr, ctx, hash(key_str), SELF_LOCAL_SEND);

    set_kv_value(key_str, value_str);

    free_kv_value(key_str, kv_head);
    return 0;
}
int eager_set_request_handler(struct pingpong_context *ctx, struct packet *packet, uint8_t user)
{
    char* key_str;
    char* value_str;
    uint32_t key_len = strlen(packet->eager_set_request.key_and_value) + 1;
    uint32_t value_len;
    // allocate KV node
    key_str = (char*)malloc(key_len);
    if (key_str == NULL)
    {
        fprintf(stderr, "Failed to allocate memory to key_str\n");
        return 1;
    }
    strcpy(key_str, packet->eager_set_request.key_and_value);

    value_len = strlen((packet->eager_set_request.key_and_value) + key_len)  + 1;
    value_str = (char*)malloc(value_len + 1);
    if (value_str == NULL)
    {
        fprintf(stderr, "Failed to allocate memory to key_str\n");
        return 1;
    }
    strcpy(value_str, packet->eager_set_request.key_and_value + key_len);

    // push the new KV node, and remove the old one
    set_kv_value(key_str, value_str);
    free_kv_value(key_str, kv_head);
    return 0;
}
int rdma_done_handler(struct pingpong_context *ctx, struct packet *packet, uint8_t user)
{
    // received a RDMA_DONE packet, that is the other side done to RDMA READ
    // we need to dereg the memory region for this operation
    return 0;
}
int find_request_handler(struct pingpong_context *ctx, struct packet *packet, uint8_t user)
{
    char* key_str;
    char* value_str;
    unsigned response_size = 0;
    uint64_t  hashvalue = 0;
    uint8_t targetedServer = -1;
    uint32_t key_len = strlen(packet->find.key) + 1;
    hashvalue = hash(packet->find.key);


    //set pakcet type LOCATION and the selected value
    packet->location.selected_server = hashvalue % packet->find.num_of_servers;
    packet->type = LOCATION;
    response_size = sizeof (struct packet) + 12;
    pp_post_send_rdmaread(ctx, IBV_WR_SEND, response_size, NULL, NULL, 0, id_cnt);
    add_work_request(id_cnt++,user, NULL, ctx, hashvalue, SELF_LOCAL_SEND);
    return 0;
}
int get_request_handler(struct pingpong_context *ctx, struct packet *packet, uint8_t user)
{
    char* p_value = get_kv_value(packet->eager_get_request.value, kv_head);

    struct packet* get_r_packet = (struct packet*)ctx->buf;
    uint64_t hashvalue = hash(packet->eager_get_request.value);
    uint32_t value_size;
    unsigned response_size = 0;
    // KV exist?
    if (p_value) {

        value_size; = strlen(p_value) + 1;
        // is greater then EAGER_PROTOCOL_LIMIT
        if (value_size > (EAGER_PROTOCOL_LIMIT - sizeof(struct packet)))
        {
            // register memory region for RDMA REMOTE READ
            struct ibv_mr *r_mr;
            uint32_t* my_key  = get_r_packet->rndv_get_response.params;
            uint64_t* my_addr = get_r_packet->rndv_get_response.params + 4;
            uint32_t* size = get_r_packet->rndv_get_response.params + 12;
            r_mr = ibv_reg_mr(ctx->pd, p_value, value_size, IBV_ACCESS_REMOTE_READ);
            if (r_mr == NULL)
            {
                perror("ibv_reg_mr");
                fprintf(stderr, "Failed allocate memory region\n");
                return 1;
            }

            // set packet type RENDEZVOUS_GET_RESPONSE
            get_r_packet->type = RENDEZVOUS_GET_RESPONSE;

            *my_key  = (uint32_t )r_mr->rkey;
            *my_addr = (uint64_t )r_mr->addr;
            *size    = value_size;

            response_size = sizeof(struct packet) + 4 + 8 + 4; // set the size of the new packet
            pp_post_send_rdmaread(ctx, IBV_WR_SEND,response_size,NULL, NULL, 0, id_cnt);
            add_work_request(id_cnt++, user, r_mr, ctx, hashvalue, REMOTE_RDMA_READ);
            return 0;
        }
        else
        {
            // set packet type EAGER_GET_RESPONSE
            get_r_packet->type = EAGER_GET_RESPONSE;
            strcpy(get_r_packet->eager_get_response.value, p_value);
            get_r_packet->eager_get_response.value_length = value_size;
            response_size = sizeof(struct packet) + get_r_packet->eager_get_response.value_length;
        }
    }
    else
    {
        / set packet type EAGER_GET_RESPONSE
        get_r_packet->type = EAGER_GET_RESPONSE;
        get_r_packet->eager_get_response.value[0] = 0;
        get_r_packet->eager_get_response.value_length = 1;
        response_size = sizeof(struct packet) + get_r_packet->eager_get_response.value_length;
    }
    pp_post_send_rdmaread(ctx, IBV_WR_SEND,response_size,NULL, NULL, 0, id_cnt);
    add_work_request(id_cnt++, user, r_mr, ctx, hashvalue, SELF_LOCAL_SEND);
    return 0;

}
int handle_completions_wr(wrnode_t* wrnode)
{
    struct pingpong_context *ctx = (struct pingpong_context *)wrnode->ctx;
    struct packet *packet = (struct packet*)ctx->buf;
    uint8_t user = wrnode->user;

    if (wrnode->operation == PINGPONG_SEND_WRID)
    {

    }
    else if (wrnode->operation == PINGPONG_RECV_WRID)
    {
        switch (packet->type)
        {
            case RENDEZVOUS_SET_REQUEST:
                return rendezvous_set_req_handler(wrnode->ctx, packet, user);
                break; //TODO replace with return of function
            case EAGER_SET_REQUEST:
                return eager_set_request_handler(wrnode->ctx, packet, user);
                break; //TODO replace with return of function
            case EAGER_GET_REQUEST:
                return get_request_handler(wrnode->ctx, packet, user);
                break; //TODO replace with return of function
            case FIND:
                return find_request_handler(wrnode->ctx, packet, user);
                break; //TODO replace with return of function
            case RENDEZVOUS_DONE:
                break; //TODO replace with return of function

            default:
                fprintf(stderr, "No Such packet type is supported %d\n", packet->type);
                return 1;
        }
    }
    else
    {
        fprintf(stderr, "No Such Operation %d\n", wrnode->operation);
        return 1;
    }




}
void handle_server_packets_only(struct pingpong_context *ctx, struct packet *packet)
{
    uint32_t response_size = 0;
    struct ibv_mr *r_mr;
    switch (packet->type) {
        /* Only handle packets relevant to the server here - client will handle inside get/set() calls */
        case EAGER_GET_REQUEST: /* TODO (10LOC): handle a short GET() on the server */
            {
                char* p_value = get_kv_value(packet->eager_get_request.value, kv_head);
                struct packet* get_r_packet = (struct packet*)ctx->buf;
                uint32_t value_size = strlen(p_value) + 1;
                printf("EAGER_GET_REQUEST\n");
                printf("get key: %s\n", packet->eager_get_request.value);
                printf("value size is: %d\n", strlen(p_value));
                if (p_value) {

                    /* TODO: send eager_get_response */
                    if (value_size > (EAGER_PROTOCOL_LIMIT - sizeof(struct packet)))
                    {

                        uint32_t* my_key  = get_r_packet->rndv_get_response.params;
                        uint64_t* my_addr = get_r_packet->rndv_get_response.params + 4;
                        uint32_t* size = get_r_packet->rndv_get_response.params + 12;

                        printf("entered here\n");
                        r_mr = ibv_reg_mr(ctx->pd, p_value, value_size, IBV_ACCESS_REMOTE_READ);
                        get_r_packet->type = RENDEZVOUS_GET_RESPONSE;
                        if (r_mr == NULL)
                        {
                            perror("");
                            assert(0);
                        }

                        printf("r_mr %p\n", r_mr);
                        *my_key  = (uint32_t )r_mr->rkey;


                        *my_addr = (uint64_t )r_mr->addr;

                        *size    = value_size;
                        printf("local key: %p\n", *my_key);
                        printf("local addr: %p\n", *my_addr);
                        printf("local size: %p\n", *size);
                        response_size = sizeof(struct packet) + 4 + 8 + 4;
                    } else {
                        get_r_packet->type = EAGER_GET_RESPONSE;
                        strcpy(get_r_packet->eager_get_response.value, p_value);
                        get_r_packet->eager_get_response.value_length = value_size;
                        printf("EAGER server reached here\n");
                        response_size = sizeof(struct packet) + get_r_packet->eager_get_response.value_length;
                        }
                } else {
                    /* TODO: define what to do when key does not exist */
                    get_r_packet->type = EAGER_GET_RESPONSE;
                    get_r_packet->eager_get_response.value[0] = 0;
                    get_r_packet->eager_get_response.value_length = 1;
                    response_size = sizeof(struct packet) + get_r_packet->eager_get_response.value_length;
                }

            }
            break;
        case EAGER_SET_REQUEST: /* TODO (10LOC): handle a short SET() on the server */
            {
                printf("EAGER_SET_REQUEST\n");
                char* key_str;
                char* value_str;
                uint32_t key_len = strlen(packet->eager_set_request.key_and_value) + 1;
                uint32_t value_len;
                key_str = (char*)malloc(key_len);
                assert(key_str);
                strcpy(key_str, packet->eager_set_request.key_and_value);

                value_len = strlen((packet->eager_set_request.key_and_value) + key_len)  + 1;
                value_str = (char*)malloc(value_len + 1);
                assert(value_str);
                strcpy(value_str, packet->eager_set_request.key_and_value + key_len);
                set_kv_value(key_str, value_str);
                free_kv_value(key_str, kv_head);
            }
            break;
        case RENDEZVOUS_GET_REQUEST: /* TODO (10LOC): handle a long GET() on the server */
            {

            }
            break;
        case RENDEZVOUS_SET_REQUEST: /* TODO (20LOC): handle a long SET() on the server */
            {
                uint32_t* remote_key;
                uint64_t* remote_addr;
                uint32_t* remote_size;
                uint8_t*  remote_keyval;
                remote_key  = (packet->rndv_set_request.kv_params + 0);
                remote_addr = (packet->rndv_set_request.kv_params + 4);
                remote_size = (packet->rndv_set_request.kv_params + 12);
                remote_keyval = (packet->rndv_set_request.kv_params + 16);

                uint32_t key_size = strlen(remote_keyval) + 1;
                uint8_t* key_str  = (uint8_t*)malloc(key_size);
                assert(key_str);
                strcpy(key_str, remote_keyval);

                uint8_t* value_str = (uint8_t*)malloc(*remote_size);
                assert(value_str);
                struct ibv_mr *mr;
                struct ibv_sge sge;
                struct ibv_send_wr wr, *bad_wr;

                printf("my remote_size: %x\n", *remote_size);
                printf("my rkey: %x\n", *remote_key);
                printf("my addr: %x\n", *remote_addr);
                r_mr = ibv_reg_mr(ctx->pd, value_str,*remote_size, IBV_ACCESS_LOCAL_WRITE);
                struct ibv_mr* temp_mr = ctx->mr;
                ctx->mr = r_mr;
                pp_post_send_rdmaread(ctx,IBV_ACCESS_REMOTE_READ, *remote_size ,value_str, *remote_addr, *remote_key, 2);
                //^^^^ This is a problem: there is no poll for cq after this verb.
                add_work_request(id_cnt, 0/*user*/, r_mr, ctx, 0, IBV_ACCESS_REMOTE_READ);
                printf("server reached after remote read\n");

                //ibv_post_send(ctx->qp, &wr, &bad_wr);
                ctx->mr = temp_mr;
                pp_post_recv(ctx, 1); // Wait for RDMA Read to end
                //pp_wait_cq(ctx);
                struct packet* packet_ack = (struct packet*)ctx->buf;
                packet_ack->type = RENDEZVOUS_DONE;
                pp_post_send(ctx, IBV_WR_SEND, sizeof(struct packet),NULL, NULL, NULL);
                //pp_wait_cq(ctx);
                pp_wait_completions(ctx, 2);
                printf("%.10s : %.10s\n", key_str, value_str);
                set_kv_value(key_str, value_str);
                free_kv_value(key_str, kv_head);
            }
            break;

#ifdef EX4
            case FIND: /* TODO (2LOC): use some hash function */
#endif
        default:
            break;
    }
    if (response_size) {
        printf("response_size: %d\n", response_size);

        pp_post_send(ctx, IBV_WR_SEND, response_size, NULL, NULL, 0);
        printf("server pp_post_send\n");
        //pp_wait_cq(ctx);
        printf("server after response\n");
    }
}

int orig_main(struct kv_server_address *server, unsigned size, int argc, char *argv[], struct pingpong_context **result_ctx)
{
    struct ibv_device      **dev_list;
    struct ibv_device	    *ib_dev;
    struct pingpong_context *ctx;
    struct pingpong_dest     my_dest;
    struct pingpong_dest    *rem_dest;
    struct timeval           start, end;
    char                    *ib_devname = NULL;
    char                    *servername = server->servername;
    static int              port;
    int                      ib_port = 1;
    enum ibv_mtu		    mtu = IBV_MTU_1024;
    int                      rx_depth = 1;
    int                      iters = 1000;
    int                      use_event = 0;
    int                      routs;
    int                      rcnt, scnt;
    int                      num_cq_events = 0;
    int                      sl = 0;
    static int			             gidx = -1;
    char			         gid[33];

    srand48(getpid() * time(NULL));
    while (1) {
        int c;

        static struct option long_options[] = {
                { .name = "port",     .has_arg = 1, .val = 'p' },
                { .name = "ib-dev",   .has_arg = 1, .val = 'd' },
                { .name = "ib-port",  .has_arg = 1, .val = 'i' },
                { .name = "size",     .has_arg = 1, .val = 's' },
                { .name = "mtu",      .has_arg = 1, .val = 'm' },
                { .name = "rx-depth", .has_arg = 1, .val = 'r' },
                { .name = "iters",    .has_arg = 1, .val = 'n' },
                { .name = "sl",       .has_arg = 1, .val = 'l' },
                { .name = "events",   .has_arg = 0, .val = 'e' },
                { .name = "gid-idx",  .has_arg = 1, .val = 'g' },
                { 0 }
        };

        c = getopt_long(argc, argv, "p:q:d:i:s:m:r:n:l:eg:", long_options, NULL);
        if (c == -1)
            break;

        switch (c) {
            case 'p':
                port = strtol(optarg, NULL, 0);
                if (port < 0 || port > 65535) {
                    usage(argv[0]);
                    return 1;
                }
                break;
            case 'd':
                ib_devname = strdup(optarg);
                break;

            case 'i':
                ib_port = strtol(optarg, NULL, 0);
                if (ib_port < 0) {
                    usage(argv[0]);
                    return 1;
                }
                break;

            case 's':
                size = strtol(optarg, NULL, 0);
                break;

            case 'm':
                mtu = pp_mtu_to_enum(strtol(optarg, NULL, 0));
                if (mtu < 0) {
                    usage(argv[0]);
                    return 1;
                }
                break;

            case 'r':
                rx_depth = strtol(optarg, NULL, 0);
                break;

            case 'n':
                iters = strtol(optarg, NULL, 0);
                break;

            case 'l':
                sl = strtol(optarg, NULL, 0);
                break;

            case 'e':
                ++use_event;
                break;

            case 'g':
                gidx = strtol(optarg, NULL, 0);
                break;

            default:
                usage(argv[0]);
                return 1;
        }
    }
    if (optind == argc - 1)
        servername = strdup(argv[optind]);
    else if (optind < argc) {
        usage(argv[0]);
        return 1;
    }

    page_size = sysconf(_SC_PAGESIZE);

    dev_list = ibv_get_device_list(NULL);
    if (!dev_list) {
        perror("Failed to get IB devices list");
        return 1;
    }

    if (!ib_devname) {
        ib_dev = *dev_list;
        if (!ib_dev) {
            fprintf(stderr, "No IB devices found\n");
            return 1;
        }
    } else {
        int i;
        for (i = 0; dev_list[i]; ++i)
            if (!strcmp(ibv_get_device_name(dev_list[i]), ib_devname))
                break;
        ib_dev = dev_list[i];
        if (!ib_dev) {
            fprintf(stderr, "IB device %s not found\n", ib_devname);
            return 1;
        }
    }

    ctx = pp_init_ctx(ib_dev, size, rx_depth, ib_port, use_event, !servername);
    if (!ctx)
        return 1;

    routs = pp_post_recv(ctx, ctx->rx_depth);
    if (routs < ctx->rx_depth) {
        fprintf(stderr, "Couldn't post receive (%d)\n", routs);
        return 1;
    }

    if (use_event)
        if (ibv_req_notify_cq(ctx->cq, 0)) {
            fprintf(stderr, "Couldn't request CQ notification\n");
            return 1;
        }


    if (pp_get_port_info(ctx->context, ib_port, &ctx->portinfo)) {
        fprintf(stderr, "Couldn't get port info\n");
        return 1;
    }

    my_dest.lid = ctx->portinfo.lid;
    if (ctx->portinfo.link_layer == IBV_LINK_LAYER_INFINIBAND && !my_dest.lid) {
        fprintf(stderr, "Couldn't get local LID\n");
        return 1;
    }

    if (gidx >= 0) {
        if (ibv_query_gid(ctx->context, ib_port, gidx, &my_dest.gid)) {
            fprintf(stderr, "Could not get local gid for gid index %d\n", gidx);
            return 1;
        }
    } else
        memset(&my_dest.gid, 0, sizeof my_dest.gid);

    my_dest.qpn = ctx->qp->qp_num;
    my_dest.psn = lrand48() & 0xffffff;
    inet_ntop(AF_INET6, &my_dest.gid, gid, sizeof gid);
    printf("  local address:  LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n",
           my_dest.lid, my_dest.qpn, my_dest.psn, gid);



    if (servername) {

        rem_dest = pp_client_exch_dest(servername, port, &my_dest);
    }
    else {
        rem_dest = pp_server_exch_dest(ctx, ib_port, mtu, port, sl, &my_dest, gidx);
    }

    if (!rem_dest)
        return 1;

    inet_ntop(AF_INET6, &rem_dest->gid, gid, sizeof gid);

    printf("  remote address: LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n",
           rem_dest->lid, rem_dest->qpn, rem_dest->psn, gid);

    if (servername)
        if (pp_connect_ctx(ctx, ib_port, my_dest.psn, mtu, sl, rem_dest, gidx))
            return 1;

    ibv_free_device_list(dev_list);
    free(rem_dest);
    *result_ctx = ctx;
    return 0;
}
int manager(struct pingpong_context **ctxs, int numClients, int num) {
    unsigned i, ne;
    struct pingpong_context *ctx;
    struct ibv_wc wc[2];
    do {
        ne = ibv_poll_cq(global_cq, 2, wc);
        if (ne < 0) {
            fprintf(stderr, "poll CQ failed %d\n", ne);
            return 1;
        }
    } while (ne < 1);
    for (i = 0; i < ne; ++i) {
        if (wc[i].status != IBV_WC_SUCCESS) {

            fprintf(stderr, "Failed status %s (%d) for wr_id %d\n",
                    ibv_wc_status_str(wc[i].status),
                    wc[i].status, (int) wc[i].wr_id);
            return 1;
        }
        if (wr_exist(wc[i].wr_id))
        {
            //TODO take care the completeion
            wrnode_t *node_wr = pop_wrnode(wc[i].wr_id);
            handle_completions_wr(node_wr);
            free(node_wr); // free after free all the relevant pointers inside that struct
        } else {
            fprintf(stderr, "Completion for unknown wr_id %d\n",
                    (int) wc[i].wr_id);
            return 1;
        }
    }
}

int pp_wait_completions(struct pingpong_context *ctx, int iters)
{
    int rcnt, scnt, num_cq_events, use_event = 0;
    rcnt = scnt = 0;
    while (rcnt + scnt < iters) {
        struct ibv_wc wc[2];
        int ne, i;

        do {
            ne = ibv_poll_cq(ctx->cq, 2, wc);
            if (ne < 0) {
                fprintf(stderr, "poll CQ failed %d\n", ne);
                return 1;
            }

        } while (ne < 1);

        for (i = 0; i < ne; ++i) {
            if (wc[i].status != IBV_WC_SUCCESS) {

                fprintf(stderr, "Failed status %s (%d) for wr_id %d\n",
                        ibv_wc_status_str(wc[i].status),
                        wc[i].status, (int) wc[i].wr_id);
                return 1;
            }

            switch ((int) wc[i].wr_id) {
                case PINGPONG_SEND_WRID:
                    ++scnt;
                    break;
                case PINGPONG_RECV_WRID:
                    handle_server_packets_only(ctx, (struct packet *) ctx->buf);
                    pp_post_recv(ctx, 1);
                    ++rcnt;
                    break;
                default:
                    fprintf(stderr, "Completion for unknown wr_id %d\n",
                            (int) wc[i].wr_id);
                    return 1;
            }
        }
    }

    return 0;
}

int kv_open(struct kv_server_address *server, void **kv_handle)
{
    return orig_main(server, EAGER_PROTOCOL_LIMIT, g_argc, g_argv, (struct pingpong_context **)kv_handle);
}

int kv_set(void *kv_handle, const char *key, const char *value) {
    struct pingpong_context *ctx = kv_handle;
    struct packet *set_packet = (struct packet *) ctx->buf;

    uint32_t packet_size = strlen(key) + strlen(value) + sizeof(struct packet);
    if (packet_size < (EAGER_PROTOCOL_LIMIT)) {
        /* Eager protocol - exercise part 1 */
        set_packet->type = EAGER_SET_REQUEST;

        strcpy(set_packet->eager_set_request.key_and_value, key);
        strcpy(set_packet->eager_set_request.key_and_value + strlen(key) + 1, value);

        pp_post_send(ctx, IBV_WR_SEND, packet_size, NULL, NULL, 0); /* Sends the packet to the server */
        return pp_wait_completions(ctx, 1); /* await EAGER_SET_REQUEST completion */
    }

    /* Otherwise, use RENDEZVOUS - exercise part 2 */
    set_packet->type = RENDEZVOUS_SET_REQUEST;

    uint32_t *my_key = set_packet->rndv_set_request.kv_params + 0;
    uint64_t *my_addr = set_packet->rndv_set_request.kv_params + 4;
    uint32_t *my_size = set_packet->rndv_set_request.kv_params + 12;
    char *key_value = (set_packet->rndv_set_request.kv_params + 16);
    struct ibv_mr *r_mr;
    uint32_t key_size = strlen(key) + 1;
    strcpy(key_value, key);

    *my_size = strlen(value) + 1;


    r_mr = ibv_reg_mr(ctx->pd, value, *my_size, IBV_ACCESS_REMOTE_READ);
    printf("my_size: %x\n", *my_size);
    //*my_key  = ctx->mr->rkey;
    //*my_addr = ctx->mr->addr;

    *my_key = r_mr->rkey;
    *my_addr = r_mr->addr;
    //*my_addr = value;
    packet_size = sizeof(struct packet) + 16 + key_size;
    printf("my rkey: %x\n", *my_key);
    printf("my addr: %x\n", *my_addr);



    pp_post_send(ctx, IBV_WR_SEND, packet_size, NULL, NULL, 0);

    struct packet* packet_ack;

    do
    {
        pp_post_recv(ctx, 1);
        packet_ack = (struct packet*)ctx->buf;
    }
    while(packet_ack->type != RENDEZVOUS_DONE);

    ibv_dereg_mr(r_mr);

    /* TODO (4LOC): fill in the rest of the set_packet - request peer address & remote key */
    return  pp_wait_completions(ctx, 1); /* wait for both to complete */
}

int kv_get(void *kv_handle, const char *key, char **value)
{
    struct pingpong_context *ctx = kv_handle;
    struct packet *get_packet = (struct packet*)ctx->buf;

    uint32_t packet_size = strlen(key) + 1 + sizeof(struct packet);
    if (packet_size < (EAGER_PROTOCOL_LIMIT)) {
        /* Eager protocol - exercise part 1 */
        get_packet->type = EAGER_GET_REQUEST;

        strcpy(get_packet->eager_get_request.value, key);

        pp_post_send(ctx, IBV_WR_SEND, packet_size, NULL, NULL, 0); /* Sends the packet to the server */

        {
            //pp_post_recv(ctx, EAGER_PROTOCOL_LIMIT); /* Receives the packet from the server */
            struct packet *get_r_packet;
            do {
                int n = pp_post_recv(ctx, 1); /* Receives the packet from the server */
                get_r_packet = (struct packet*)ctx->buf;

            } while ((get_r_packet->type != RENDEZVOUS_GET_RESPONSE) && (get_r_packet->type != EAGER_GET_RESPONSE));
            if (get_r_packet->type == EAGER_GET_RESPONSE) {
                *value = (char*)malloc(get_r_packet->eager_get_response.value_length);
                assert(*value);
                memcpy(*value, get_r_packet->eager_get_response.value, get_r_packet->eager_get_response.value_length);

            } else if (get_r_packet->type == RENDEZVOUS_GET_RESPONSE) {

                struct ibv_mr *r_mr;
                uint32_t* peer_key  = get_r_packet->rndv_get_response.params;
                uint64_t* peer_addr = get_r_packet->rndv_get_response.params + 4;
                uint32_t* size = get_r_packet->rndv_get_response.params + 12;
                *value = (uint8_t*)malloc(*size);
                assert(*value);
                r_mr = ibv_reg_mr(ctx->pd, *value, *size, IBV_ACCESS_LOCAL_WRITE);

                printf("remote key %p\n", *peer_key);
                printf("remote addr %p\n", *peer_addr);
                printf("remote size %x\n", *size);
                struct ibv_mr* temp_mr = ctx->mr;
                ctx->mr = r_mr;
                pp_post_send(ctx, IBV_ACCESS_REMOTE_READ, *size, *value, *peer_addr, *peer_key);

                //pp_post_recv(ctx,2);
                struct ibv_wc wc[1];
                int ne;

                do {
                    ne = ibv_poll_cq(ctx->cq, 1, wc);
                    if (ne < 0) {
                        fprintf(stderr, "poll CQ failed %d\n", ne);
                        return 1;
                    }

                } while (wc[0].opcode != IBV_WC_RDMA_READ);

                ctx->mr = temp_mr;
                ibv_dereg_mr(r_mr);
                printf("value: %.10s with len %d\n", *value, strlen(*value));
                return 0;

            } else {
                printf("Here\t");
                switch (get_r_packet->type)
                {
                    case EAGER_SET_REQUEST:
                        printf("EAGER_SET_REQUEST\n");
                        break;
                    case EAGER_GET_REQUEST:
                        printf("EAGER_GET_REQUEST %s\n", get_packet->eager_get_request.value);
                        break;
                    case EAGER_GET_RESPONSE:
                        printf("EAGER_GET_RESPONSE\n");
                        break;
                    default:
                        printf("DEFAULT\n");
                        break;
                }
                /* TODO */
            }
        }
        return pp_wait_completions(ctx, 2); /* await EAGER_GET_REQUEST completion */
    }

    /* Otherwise, use RENDEZVOUS - exercise part 2 */
    get_packet->type = RENDEZVOUS_GET_REQUEST;
    /* TODO (4LOC): fill in the rest of the set_packet - request peer address & remote key */

    pp_post_recv(ctx, 1); /* Posts a receive-buffer for RENDEZVOUS_SET_RESPONSE */
    pp_post_send(ctx, IBV_WR_SEND, packet_size, NULL, NULL, 0); /* Sends the packet to the server */
    assert(pp_wait_completions(ctx, 2)); /* wait for both to complete */

    assert(get_packet->type == RENDEZVOUS_SET_RESPONSE);
    pp_post_send(ctx, IBV_WR_RDMA_WRITE, packet_size, value, NULL, 0/* TODO (1LOC): replace with remote info for RDMA_WRITE from packet */);
    return pp_wait_completions(ctx, 1); /* wait for both to complete */

    //return 0; /* TODO (25LOC): similar to SET, only no n*/
}

void kv_release(char *value)
{
    free(value);
}

int kv_close(void *kv_handle)
{
    return pp_close_ctx((struct pingpong_context*)kv_handle);
}

#ifdef EX3
#define my_open  kv_open
#define set      kv_set
#define get      kv_get
#define release  kv_release
#define my_close kv_close
#endif /* EX3 */










#ifdef EX4
struct mkv_ctx {
	unsigned num_servers;
	struct pingpong_context *kv_ctxs[0];
};

int mkv_open(struct kv_server_address *servers, void **mkv_h)
{
	struct mkv_ctx *ctx;
	unsigned count = 0;
	while (servers[count++].servername); /* count servers */
	ctx = malloc(sizeof(*ctx) + count * sizeof(void*));
	if (!ctx) {
		return 1;
	}

	ctx->num_servers = count;
	for (count = 0; count < ctx->num_servers; count++) {
		if (orig_main(&servers[count], EAGER_PROTOCOL_LIMIT, g_argc, g_argv, &ctx->kv_ctxs[count])) {
			return 1;
		}
	}

	*mkv_h = ctx;
	return 0;
}

int mkv_set(void *mkv_h, unsigned kv_id, const char *key, const char *value)
{
	struct mkv_ctx *ctx = mkv_h;
	return kv_set(ctx->kv_ctxs[kv_id], key, value);
}

int mkv_get(void *mkv_h, unsigned kv_id, const char *key, char **value)
{
	struct mkv_ctx *ctx = mkv_h;
	return kv_get(ctx->kv_ctxs[kv_id], key, value);
}

void mkv_release(char *value)
{
	kv_release(value);
}

void mkv_close(void *mkv_h)
{
	unsigned count;
	struct mkv_ctx *ctx = mkv_h;
	for (count = 0; count < ctx->num_servers; count++) {
		pp_close_ctx((struct pingpong_context*)ctx->kv_ctxs[count]);
	}
	free(ctx);
}









struct dkv_ctx {
	struct mkv_ctx *mkv;
	struct pingpong_context *indexer;
};

int dkv_open(struct kv_server_address *servers, /* array of servers */
             struct kv_server_address *indexer, /* single indexer */
             void **dkv_h)
{
	struct dkv_ctx *ctx = malloc(sizeof(*ctx));
	if (orig_main(indexer, EAGER_PROTOCOL_LIMIT, g_argc, g_argv, &ctx->indexer)) {
		return 1;
	}
	if (mkv_open(servers, (void**)&ctx->mkv)) {
		return 1;
	}
	*dkv_h = ctx;
}

int dkv_set(void *dkv_h, const char *key, const char *value, unsigned length)
{
	struct dkv_ctx *ctx = dkv_h;
    struct packet *set_packet = (struct packet*)&ctx->indexer->buf;
    unsigned packet_size = strlen(key) + sizeof(struct packet);

    /* Step #1: The client sends the Index server FIND(key, #kv-servers) */
    set_packet->type = FIND;
	set_packet->find.num_of_servers = ctx->mkv->num_servers;
	strcpy(set_packet->find.key, key);

    pp_post_recv(ctx->indexer, 1); /* Posts a receive-buffer for LOCATION */
    pp_post_send(ctx->indexer, IBV_WR_SEND, packet_size, NULL, NULL, 0); /* Sends the packet to the server */
    assert(pp_wait_completions(ctx->indexer, 2)); /* wait for both to complete */

    /* Step #2: The Index server responds with LOCATION(#kv-server-id) */
    assert(set_packet->type == LOCATION);

    /* Step #3: The client contacts KV-server with the ID returned in LOCATION, using SET/GET messages. */
	return mkv_set(ctx->mkv, set_packet->location.selected_server, key, value);
		//length); /* TODO (10LOC): Add this value length parameter to all the relevant functions... including kv_set()/kv_get() */
}

int dkv_get(void *dkv_h, const char *key, char **value, unsigned *length)
{
	/* TODO (20LOC): implement similarly to dkv_get() */
}

void dkv_release(char *value)
{
	mkv_release(value);
}

int dkv_close(void *dkv_h)
{
	struct dkv_ctx *ctx = dkv_h;
	pp_close_ctx(ctx->indexer);
	mkv_close(ctx->mkv);
	free(ctx);
}

void recursive_fill_kv(char const* dirname, void *dkv_h) {
	struct dirent *curr_ent;
	DIR* dirp = opendir(dirname);
	if (dirp == NULL) {
		return;
	}

	while ((curr_ent = readdir(dirp)) != NULL) {
		if (!((strcmp(curr_ent->d_name, ".") == 0) ||
		(strcmp(curr_ent->d_name, "..") == 0))) {
			char* path = malloc(strlen(dirname) + strlen(curr_ent->d_name) + 2);
			strcpy(path, dirname);
			strcat(path, "/");
			strcat(path, curr_ent->d_name);
			if (curr_ent->d_type == DT_DIR) {
				recursive_fill_kv(path, dkv_h);
			} else if (curr_ent->d_type == DT_REG) {
				int fd = open(path, O_RDONLY);
				size_t fsize = lseek(fd, (size_t)0, SEEK_END);
				void *p = mmap(0, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
				/* TODO (1LOC): Add a print here to see you found the full paths... */
				dkv_set(dkv_h, path, p, fsize);
				munmap(p, fsize);
				close(fd);
			}
			free(path);
		}
	}
	closedir(dirp);
}

#define my_open    dkv_open
#define set(a,b,c) dkv_set(a,b,c,strlen(c))
#define get(a,b,c) dkv_get(a,b,c,&g_argc)
#define release    dkv_release
#define my_close   dkv_close
#endif /* EX4 */









void run_server()
{
    struct pingpong_context *ctx[2];
    struct kv_server_address server[2] = {0};
    wr_head = NULL;

    int i;
    for (i = 0; i < g_argc; i++)
    {
        printf("%s\n", g_argv[i]);
    }
    assert(0 == orig_main(&server[0], EAGER_PROTOCOL_LIMIT, g_argc, g_argv, &ctx[0]));
    for (i = 0; i < g_argc; i++)
    {
        printf("%s\n", g_argv[i]);
    }
    assert(0 == orig_main(&server[1], EAGER_PROTOCOL_LIMIT, g_argc, g_argv, &ctx[1]));
    while (0 <= pp_wait_completions(ctx[0], 1));

    pp_close_ctx(ctx);
}




int main(int argc, char **argv)
{
    void *kv_ctx; /* handle to internal KV-client context */

    char send_buffer[MAX_TEST_SIZE] = {0};
    char *recv_buffer;

    struct kv_server_address servers[2] = {
            {
                    .servername = "localhost",
                    .port = 12345
            },
            {0}
    };

#ifdef EX4
    struct kv_server_address indexer[2] = {
            {
                    .servername = "localhost",
                    .port = 12346
            },
            {0}
    };
#endif

    g_argc = argc;
    g_argv = argv;
    if (strcmp(argv[0], "./server") == 0) {
        run_server();
    }

#ifdef EX4
        assert(0 == my_open(servers, indexer, &kv_ctx));
#else
    assert(0 == my_open(&servers[0], &kv_ctx));
#endif
    FILE* dictFile = fopen("ex3_test.txt", "r");
    struct kv_file parsed = {0};
    int cnt = 0;
    while (1)
    {
        parsed = parse_file(&dictFile);
        if (parsed.type == EOF)
        {
            my_close(kv_ctx);
            return 0;
        }
        switch (parsed.type)
        {
            case 0:
                printf("%s\n%s\n%.*s\n", "set", parsed.key, 10 ,parsed.value);
                printf("%d\n%d\n",strlen(parsed.key), strlen(parsed.value));
                assert(0 == set(kv_ctx, parsed.key, parsed.value));
                free(parsed.key);
                free(parsed.value);
                printf("Counter %d\n", cnt++);
                break;
            case 1:
                printf("before get\n");
                assert(0 == get(kv_ctx, parsed.key, &parsed.value));
                printf("get\t%s : %.*s\n", parsed.key, 10, parsed.value);
                kv_release(parsed.value);
                free(parsed.key);
                printf("Counter %d\n", cnt++);
                break;
            default:
                my_close(kv_ctx);
                return 0;
        }
    }
    /* Test small size */
    assert(100 < MAX_TEST_SIZE);
    memset(send_buffer, 'a', 100);
    assert(0 == set(kv_ctx, "1", send_buffer));
    assert(0 == get(kv_ctx, "1", &recv_buffer));
    assert(0 == strcmp(send_buffer, recv_buffer));
    release(recv_buffer);
    printf("after Test small size\n");
    /* Test logic */
    assert(0 == get(kv_ctx, "1", &recv_buffer));
    assert(0 == strcmp(send_buffer, recv_buffer));
    release(recv_buffer);
    memset(send_buffer, 'b', 100);
    assert(0 == set(kv_ctx, "1", send_buffer));
    memset(send_buffer, 'c', 100);
    assert(0 == set(kv_ctx, "22", send_buffer));
    memset(send_buffer, 'b', 100);
    assert(0 == get(kv_ctx, "1", &recv_buffer));
    assert(0 == strcmp(send_buffer, recv_buffer));
    printf("recv_buffer: %s\n", recv_buffer);
    release(recv_buffer);
    printf("after Test Logic\n");
    /* Test large size */
    memset(send_buffer, 'a', MAX_TEST_SIZE - 1);
    assert(0 == set(kv_ctx, "1", send_buffer));
    assert(0 == set(kv_ctx, "333", send_buffer));
    assert(0 == get(kv_ctx, "1", &recv_buffer));

    assert(0 == strcmp(send_buffer, recv_buffer));
    memset(send_buffer, 'o', MAX_TEST_SIZE - 1);
    assert(0 == set(kv_ctx, "oren", send_buffer));
    assert(0 == get(kv_ctx, "oren", &recv_buffer));
    release(recv_buffer);
    printf("after Test large size\n");
    skip:

#ifdef EX4
    recursive_fill_kv(TEST_LOCATION, kv_ctx);
#endif

    my_close(kv_ctx);
    return 0;
}