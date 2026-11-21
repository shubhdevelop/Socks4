#define _GNU_SOURCE
#include <arpa/inet.h>
#include <liburing.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SOCKS_METADATA_SIZE 8;
#define SOCKS_VERSION_4 0x04
#define SOCKS_VERSION_5 0x05
#define SOCKS_CMD_CONNECT 0x01
#define SOCKS_CMD_BIND 0x02
#define SOCKS_AUTH_GSSAPIS_DEST_IP 0x04;
#define SOCKS_DEST_PORT 0x02

#define SOCKS_REQ_GRANTED 0x5a
#define SOCKS_REQ_REJECTED 0x5b
#define SOCKS_IDENTD_UNREACHABLE 0x5c
#define SOCKS_IDENTD_VERIFICATION_FAILED 0x5d

#define SOCKS_AUTH_NO 0x00
#define SOCKS_AUTH_GSSAPI 0x01
#define SOCKS_AUTH_USER_PASS 0x02
#define SOCKS_AUTH_CHA_PROTOCOL 0x03
#define SOCKS_AUTH_UNASSIGNED 0x04
#define SOCKS_AUTH_CRA_PROTOCOL 0x05
#define SOCKS_AUTH_SSL 0x06
#define SOCKS_AUTH_NDS 0x07
#define SOCKS_AUTH_MFA 0x08
#define SOCKS_JSON_PARAMETER 0x09

#define SOCKS_MAX_BACKLOG 20
#define SOCKS_MAX_BUF_SIZE 256
#define SOCKS_MAX_ID_SIZE 64
#define SOCKS_MAX_DOMAIN_SIZE 64

#define PRINT_NTOP_IPv4(sa)                                                    \
  do {                                                                         \
    char ntop_ip4[INET_ADDRSTRLEN];                                            \
    if (inet_ntop(AF_INET, &((sa).sin_addr), ntop_ip4, sizeof ntop_ip4)) {     \
      printf("The IPv4 address is: %s\n", ntop_ip4);                           \
    } else {                                                                   \
      perror("inet_ntop");                                                     \
    }                                                                          \
  } while (0)

#define PRINT_NTOP_IPv6(sa6)                                                   \
  do {                                                                         \
    char ntop_ip6[INET6_ADDRSTRLEN];                                           \
    if (inet_ntop(AF_INET6, &((sa6).sin6_addr), ntop_ip6, sizeof ntop_ip6)) {  \
      printf("The IPv6 address is: %s\n", ntop_ip6);                           \
    } else {                                                                   \
      perror("inet_ntop");                                                     \
    }                                                                          \
  } while (0)

enum ops {
  OP_ACCEPT,
  OP_BIND,
  OP_BIND_ACCEPT,
  OP_LISTEN,
  OP_CONNECT,
  OP_RECV,
  OP_SEND,
};

enum stage {
  STAGE_GREETING,
  STAGE_HANDSHAKE,
  STAGE_BIND,
  STAGE_RELAY,
};

enum handshake_stage {
  HS_METADATA,
  HS_ID,
  HS_DOMAIN,
};

enum bind_phase {
  BIND_NONE,
  BIND_FIRST_REPLY,
  BIND_WAIT_PEER,
  BIND_SECOND_REPLY,
  BIND_REJECT_REPLY,
};

struct connection;

struct request {
  enum ops op;
  enum stage stage;
  enum handshake_stage hs;
  enum bind_phase bind_phase;
  int version;
  int cmd;
  int dest_port;
  struct sockaddr_in destination;
  struct sockaddr_in peer_address;
  struct sockaddr_in bound_address;
  socklen_t peer_address_len;
  char id[SOCKS_MAX_ID_SIZE];
  int src_fd;
  int dst_fd;
  struct connection *connection;
  size_t sent;
  size_t len;
  char buf[SOCKS_MAX_BUF_SIZE];
  char domain[SOCKS_MAX_BUF_SIZE];
  size_t id_len;
  size_t domain_len;
  bool connect_succeeded;
};

struct connection {
  int client_fd;
  int upstream_fd;
  int bind_fd;
  unsigned int pending;
  bool closing;
  struct request directions[2];
};

int getHostSocket(const char *host, int family, const char *port, int socktype,
                  int flags, int max_backlog) {
  struct addrinfo hints, *serverinfo, *p;
  int host_fd;
  int yes = 1;
  int rv;
  memset(&hints, 0, sizeof(hints));

  hints.ai_family = family;
  hints.ai_socktype = socktype;
  hints.ai_flags = flags;
  if ((rv = getaddrinfo(host, port, &hints, &serverinfo)) != 0) {
    fprintf(stderr, "Error resolving %s:%s: %s\n", host, port,
            gai_strerror(rv));
    exit(EXIT_FAILURE);
  }

  for (p = serverinfo; p != NULL; p = p->ai_next) {
    host_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (host_fd < 0) {
      continue;
    }

    setsockopt(host_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    if (bind(host_fd, p->ai_addr, p->ai_addrlen) < 0) {
      close(host_fd);
      continue;
    }
    break;
  }

  if (p == NULL) {
    freeaddrinfo(serverinfo);
    return -1;
  }

  if (listen(host_fd, max_backlog) == -1) {
    freeaddrinfo(serverinfo);
    return -1;
  }

  if (p->ai_family == AF_INET) {
    struct sockaddr_in *sa = (struct sockaddr_in *)p->ai_addr;
    PRINT_NTOP_IPv4(*sa);
  } else {
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)p->ai_addr;
    PRINT_NTOP_IPv6(*sa6);
  }

  printf("listening on %s:%s\n", host, port);

  freeaddrinfo(serverinfo);
  return host_fd;
}

static const char *requestOpName(enum ops op) {
  switch (op) {
  case OP_ACCEPT:
    return "OP_ACCEPT";
  case OP_LISTEN:
    return "OP_LISTEN";
  case OP_BIND:
    return "OP_BIND";
  case OP_BIND_ACCEPT:
    return "OP_BIND_ACCEPT";
  case OP_CONNECT:
    return "OP_CONNECT";
  case OP_RECV:
    return "OP_RECV";
  case OP_SEND:
    return "OP_SEND";
  }

  return "OP_UNKNOWN";
}

static const char *requestStageName(enum stage stage) {
  switch (stage) {
  case STAGE_GREETING:
    return "STAGE_GREETING";
  case STAGE_HANDSHAKE:
    return "STAGE_HANDSHAKE";
  case STAGE_BIND:
    return "STAGE_BIND";
  case STAGE_RELAY:
    return "STAGE_RELAY";
  }

  return "STAGE_UNKNOWN";
}

static const char *requestHandshakeName(enum handshake_stage hs) {
  switch (hs) {
  case HS_METADATA:
    return "HS_METADATA";
  case HS_ID:
    return "HS_ID";
  case HS_DOMAIN:
    return "HS_DOMAIN";
  }

  return "HS_STAGE_UNKNOWN";
}

static void printEscapedBytes(const char *bytes, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    unsigned char byte = (unsigned char)bytes[i];

    if (byte == '\\' || byte == '"')
      printf("\\%c", byte);
    else if (byte >= ' ' && byte <= '~')
      putchar(byte);
    else
      printf("\\x%02X", byte);
  }
}

void printRequest(const struct request *req) {
  if (req == NULL) {
    puts("request: (null)");
    return;
  }

  size_t buf_len = req->len;
  size_t id_len = req->id_len;
  size_t domain_len = req->domain_len;
  if (buf_len > sizeof req->buf)
    buf_len = sizeof req->buf;
  if (id_len > sizeof req->id)
    id_len = sizeof req->id;
  if (domain_len > sizeof req->domain)
    domain_len = sizeof req->domain;

  char destination_address[INET_ADDRSTRLEN];
  const char *address = "<invalid>";
  if (req->destination.sin_family == AF_INET &&
      inet_ntop(AF_INET, &req->destination.sin_addr, destination_address,
                sizeof destination_address) != NULL)
    address = destination_address;

  printf("request {\n"
         "  op: %s (%d)\n"
         "  stage: %s (%d)\n"
         "  handshake_stage: %s (%d)\n"
         "  version: %d\n"
         "  cmd: %d\n"
         "  dest_port: %d\n"
         "  dest_ip: %s\n"
         "  destination: { family: %d, port: %u }\n"
         "  src_fd: %d\n"
         "  dst_fd: %d\n"
         "  connection: %p\n"
         "  sent: %zu\n"
         "  len: %zu\n"
         "  id_len: %zu\n"
         "  domain_len: %zu\n"
         "  connect_succeeded: %s\n"
         "  buf[%zu]: \"",
         requestOpName(req->op), req->op, requestStageName(req->stage),
         req->stage, requestHandshakeName(req->hs), req->hs, req->version,
         req->cmd, req->dest_port, address, req->destination.sin_family,
         (unsigned int)ntohs(req->destination.sin_port), req->src_fd,
         req->dst_fd, (void *)req->connection, req->sent, req->len, req->id_len,
         req->domain_len, req->connect_succeeded ? "true" : "false", buf_len);
  printEscapedBytes(req->buf, buf_len);
  printf("\"\n  id[%zu]: \"", id_len);
  printEscapedBytes(req->id, id_len);
  printf("\"\n  domain[%zu]: \"", domain_len);
  printEscapedBytes(req->domain, domain_len);
  puts("\"\n}");
}

void check(int result, const char *operation) {
  if (result < 0) {
    fprintf(stderr, "%s: %s\n", operation, strerror(-result));
    exit(EXIT_FAILURE);
  }
}

/* A completion still owns its request until every queued operation finishes. */
void release_connection(struct connection *connection) {
  if (connection->pending == 0) {
    if (connection->client_fd >= 0)
      close(connection->client_fd);
    if (connection->upstream_fd >= 0)
      close(connection->upstream_fd);
    if (connection->bind_fd >= 0)
      close(connection->bind_fd);
    free(connection);
  }
}

void abort_connection(struct connection *connection) {
  connection->closing = true;
  shutdown(connection->client_fd, SHUT_RDWR);
  shutdown(connection->upstream_fd, SHUT_RDWR);
  release_connection(connection);
}

void submitPending(struct io_uring *ring) {
  while (io_uring_sq_ready(ring) != 0) {
    int result = io_uring_submit(ring);
    if (result == -EINTR)
      continue;
    check(result, "submit");
    if (result == 0)
      check(-EIO, "submit made no progress");
  }
}

void prepareRequest(struct io_uring *ring, struct request *req) {
  if (req->op == OP_RECV && req->stage == STAGE_HANDSHAKE &&
      req->hs == HS_METADATA && req->len >= 8) {
    req->version = (uint8_t)req->buf[0];
    req->cmd = (uint8_t)req->buf[1];
    if (req->version != 0x04 || (req->cmd != 0x01 && req->cmd != 0x02)) {
      shutdown(req->src_fd, SHUT_RDWR);
      close(req->src_fd);
      return;
    }

    uint16_t port_network;
    memcpy(&port_network, req->buf + 2, sizeof port_network);
    req->dest_port = ntohs(port_network);
    req->destination = (struct sockaddr_in){
        .sin_family = AF_INET,
        .sin_port = port_network,
    };
    memcpy(&req->destination.sin_addr, req->buf + 4,
           sizeof req->destination.sin_addr);

    bool isSocks4a = req->buf[4] == 0 && req->buf[5] == 0 && req->buf[6] == 0 &&
                     req->buf[7] != 0;
    char *user_end = memchr(req->buf + 8, '\0', req->len - 8);
    if (user_end != NULL) {
      bool request_complete = !isSocks4a;
      size_t user_len = (size_t)(user_end - (req->buf + 8));
      if (user_len >= sizeof req->id) {
        shutdown(req->src_fd, SHUT_RDWR);
        close(req->src_fd);
        return;
      }
      memcpy(req->id, req->buf + 8, user_len);
      req->id[user_len] = '\0';
      req->id_len = user_len;
      if (isSocks4a) {
        size_t remaining = req->len - (size_t)(user_end + 1 - req->buf);
        char *domain = user_end + 1;
        char *domain_end = memchr(domain, '\0', remaining);
        if (domain_end != NULL) {
          size_t domain_len = (size_t)(domain_end - domain);
          if (domain_len == 0 || domain_len >= sizeof req->domain) {
            shutdown(req->src_fd, SHUT_RDWR);
            close(req->src_fd);
            return;
          }
          memcpy(req->domain, domain, domain_len);
          req->domain[domain_len] = '\0';
          req->domain_len = domain_len;

          struct addrinfo hints = {
              .ai_family = AF_INET,
              .ai_socktype = SOCK_STREAM,
          };
          struct addrinfo *resolved;
          if (getaddrinfo(req->domain, NULL, &hints, &resolved) != 0) {
            shutdown(req->src_fd, SHUT_RDWR);
            close(req->src_fd);
            return;
          }
          req->destination.sin_addr =
              ((struct sockaddr_in *)resolved->ai_addr)->sin_addr;
          freeaddrinfo(resolved);
          request_complete = true;
        }
      }
      if (request_complete && req->cmd == 0x01) {
        req->dst_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (req->dst_fd < 0) {
          shutdown(req->src_fd, SHUT_RDWR);
          close(req->src_fd);
          return;
        }
        req->connection->upstream_fd = req->dst_fd;
        req->op = OP_CONNECT;
      } else if (request_complete && req->cmd == 0x02) {
        req->stage = STAGE_BIND;
        socklen_t len = sizeof req->bound_address;
        if (getsockname(req->src_fd,
                        (struct sockaddr *)&req->bound_address, &len) == 0) {
          req->bound_address.sin_family = AF_INET;
          req->bound_address.sin_port = 0;
          req->connection->bind_fd =
              socket(AF_INET, SOCK_CLOEXEC | SOCK_STREAM, 0);
        }

        if (req->connection->bind_fd < 0) {
          memset(req->buf, 0, 8);
          req->buf[1] = SOCKS_REQ_REJECTED;
          req->dst_fd = req->src_fd;
          req->sent = 0;
          req->len = 8;
          req->bind_phase = BIND_REJECT_REPLY;
          req->op = OP_SEND;
        } else {
          req->op = OP_BIND;
        }
      }
    }
  }

  // handles buffer overflow!
  if (req->op == OP_RECV && req->len == sizeof req->buf) {
    shutdown(req->src_fd, SHUT_RDWR);
    close(req->src_fd);
    return;
  }

  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  if (sqe == NULL) {
    submitPending(ring);
    sqe = io_uring_get_sqe(ring);
    if (sqe == NULL)
      check(-EBUSY, "submission queue full");
  }
  printRequest(req);
  switch (req->op) {
  case OP_ACCEPT:
    io_uring_prep_accept(sqe, req->src_fd, NULL, NULL, SOCK_CLOEXEC);
    break;
  case OP_BIND_ACCEPT:
    io_uring_prep_accept(sqe, req->connection->bind_fd,
                         (struct sockaddr *)&req->peer_address,
                         &req->peer_address_len, SOCK_CLOEXEC);
    break;
  case OP_RECV:
    io_uring_prep_recv(sqe, req->src_fd, req->buf + req->len,
                       sizeof req->buf - req->len, 0);
    break;
  case OP_CONNECT:
    io_uring_prep_connect(sqe, req->dst_fd,
                          (struct sockaddr *)&req->destination,
                          sizeof req->destination);
    break;
  case OP_BIND:
    io_uring_prep_bind(sqe, req->connection->bind_fd,
                       (struct sockaddr *)&req->bound_address,
                       sizeof req->bound_address);
    break;
  case OP_LISTEN:
    io_uring_prep_listen(sqe, req->connection->bind_fd, SOCKS_MAX_BACKLOG);
    break;
  case OP_SEND:
    io_uring_prep_send(sqe, req->dst_fd, req->buf + req->sent,
                       req->len - req->sent, MSG_NOSIGNAL);
    break;
  }

  io_uring_sqe_set_data(sqe, req);
  if (req->connection != NULL)
    req->connection->pending++;
}
