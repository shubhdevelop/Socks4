#include "socks.h"
#include <stdlib.h>
#include <sys/socket.h>

static void send_bind_reply(struct io_uring *ring, struct request *req,
                            uint8_t response, const struct sockaddr_in *address,
                            enum bind_phase phase) {
  memset(req->buf, 0, 8);
  req->buf[1] = response;
  if (address != NULL) {
    memcpy(req->buf + 2, &address->sin_port, sizeof address->sin_port);
    memcpy(req->buf + 4, &address->sin_addr, sizeof address->sin_addr);
  }
  req->dst_fd = req->connection->client_fd;
  req->sent = 0;
  req->len = 8;
  req->bind_phase = phase;
  req->op = OP_SEND;
  prepareRequest(ring, req);
}

static void start_relay(struct io_uring *ring, struct connection *connection) {
  connection->directions[0] = (struct request){
      .op = OP_RECV,
      .stage = STAGE_RELAY,
      .src_fd = connection->client_fd,
      .dst_fd = connection->upstream_fd,
      .connection = connection,
  };
  connection->directions[1] = (struct request){
      .op = OP_RECV,
      .stage = STAGE_RELAY,
      .src_fd = connection->upstream_fd,
      .dst_fd = connection->client_fd,
      .connection = connection,
  };
  prepareRequest(ring, &connection->directions[0]);
  prepareRequest(ring, &connection->directions[1]);
}

int main(int argc, char *argv[]) {
  const char *host = "127.0.0.1";
  const char *port = "1080";
  if (argc > 1)
    host = argv[1];
  if (argc > 2)
    port = argv[2];
  if (argc > 3) {
    fprintf(stderr, "Usage: %s [bind-address] [port]\n", argv[0]);
    return EXIT_FAILURE;
  }

  struct io_uring ring;
  int rv =
      getHostSocket(host, AF_INET, port, SOCK_STREAM, 0, SOCKS_MAX_BACKLOG);
  if (rv == -1) {
    perror("host_creation");
    return EXIT_FAILURE;
  }
  int result = io_uring_queue_init(64, &ring, 0);

  if (result < 0) {
    fprintf(stderr, "io_uring_queue_init: %s\n", strerror(-result));
    close(rv);
    return EXIT_FAILURE;
  }
  struct request socks_listner = {
      .src_fd = rv,
      .op = OP_ACCEPT,
  };
  prepareRequest(&ring, &socks_listner);
  for (;;) {
    submitPending(&ring);
    struct io_uring_cqe *cqe;
    result = io_uring_wait_cqe(&ring, &cqe);

    if (result == -EINTR)
      continue;
    check(result, "wait_cqe");

    result = cqe->res;
    struct request *req = io_uring_cqe_get_data(cqe);
    io_uring_cqe_seen(&ring, cqe);

    if (req->connection != NULL) {
      req->connection->pending--;
      if (req->connection->closing) {
        release_connection(req->connection);
        continue;
      }
    }

    if (req->op == OP_ACCEPT) {
      prepareRequest(&ring, &socks_listner);
      if (result < 0) {
        if (result != -ECONNABORTED && result != -EINTR && result != -EPROTO)
          check(result, "accept");
        continue;
      }
      struct connection *connection = malloc(sizeof *connection);
      if (connection == NULL) {
        perror("malloc");
        close(result);
        continue;
      }
      memset(connection, 0, sizeof *connection);
      connection->client_fd = result;
      connection->upstream_fd = -1;
      connection->bind_fd = -1;
      req = &connection->directions[0];
      req->src_fd = result;
      req->connection = connection;
      req->stage = STAGE_HANDSHAKE;
      req->hs = HS_METADATA;
      req->op = OP_RECV;
      prepareRequest(&ring, req);
      continue;
    }

    switch (req->op) {
    case OP_CONNECT: {
      struct sockaddr_in bound = {0};
      socklen_t bound_len = sizeof bound;
      req->connect_succeeded =
          result == 0 &&
          getsockname(req->dst_fd, (struct sockaddr *)&bound, &bound_len) == 0;

      memset(req->buf, 0, 8);
      req->buf[1] =
          req->connect_succeeded ? SOCKS_REQ_GRANTED : SOCKS_REQ_REJECTED;
      if (req->connect_succeeded) {
        memcpy(req->buf + 2, &bound.sin_port, sizeof bound.sin_port);
        memcpy(req->buf + 4, &bound.sin_addr, sizeof bound.sin_addr);
      }
      req->dst_fd = req->src_fd;
      req->sent = 0;
      req->len = 8;
      req->op = OP_SEND;
      prepareRequest(&ring, req);
      break;
    }
    case OP_BIND:
      if (result < 0) {
        close(req->connection->bind_fd);
        req->connection->bind_fd = -1;
        send_bind_reply(&ring, req, SOCKS_REQ_REJECTED, NULL,
                        BIND_REJECT_REPLY);
      } else {
        req->op = OP_LISTEN;
        prepareRequest(&ring, req);
      }
      break;
    case OP_LISTEN:
      if (result < 0) {
        close(req->connection->bind_fd);
        req->connection->bind_fd = -1;
        send_bind_reply(&ring, req, SOCKS_REQ_REJECTED, NULL,
                        BIND_REJECT_REPLY);
        break;
      }

      socklen_t len = sizeof req->bound_address;
      if (getsockname(req->connection->bind_fd,
                      (struct sockaddr *)&req->bound_address, &len) != 0) {
        close(req->connection->bind_fd);
        req->connection->bind_fd = -1;
        send_bind_reply(&ring, req, SOCKS_REQ_REJECTED, NULL,
                        BIND_REJECT_REPLY);
        break;
      }
      send_bind_reply(&ring, req, SOCKS_REQ_GRANTED, &req->bound_address,
                      BIND_FIRST_REPLY);
      break;
    case OP_BIND_ACCEPT:
      if (result < 0) {
        close(req->connection->bind_fd);
        req->connection->bind_fd = -1;
        send_bind_reply(&ring, req, SOCKS_REQ_REJECTED, NULL,
                        BIND_REJECT_REPLY);
        break;
      }

      if (req->peer_address.sin_addr.s_addr !=
              req->destination.sin_addr.s_addr ||
          (req->destination.sin_port != 0 &&
           req->peer_address.sin_port != req->destination.sin_port)) {
        close(result);
        req->peer_address_len = sizeof req->peer_address;
        req->op = OP_BIND_ACCEPT;
        prepareRequest(&ring, req);
        break;
      }

      req->connection->upstream_fd = result;
      close(req->connection->bind_fd);
      req->connection->bind_fd = -1;
      send_bind_reply(&ring, req, SOCKS_REQ_GRANTED, &req->peer_address,
                      BIND_SECOND_REPLY);
      break;
    case OP_RECV:
      if (result <= 0) {
        abort_connection(req->connection);
      } else {
        req->len += (size_t)result;
        if (req->stage == STAGE_RELAY) {
          req->op = OP_SEND;
          req->sent = 0;
        }
        prepareRequest(&ring, req);
      }
      break;
    case OP_SEND:
      if (result <= 0) {
        abort_connection(req->connection);
      } else {
        req->sent += (size_t)result;
        if (req->sent < req->len) {
          prepareRequest(&ring, req);
        } else if (req->stage == STAGE_HANDSHAKE) {
          if (!req->connect_succeeded) {
            abort_connection(req->connection);
            break;
          }

          start_relay(&ring, req->connection);
        } else if (req->stage == STAGE_BIND &&
                   req->bind_phase == BIND_FIRST_REPLY) {
          req->bind_phase = BIND_WAIT_PEER;
          req->peer_address_len = sizeof req->peer_address;
          req->op = OP_BIND_ACCEPT;
          prepareRequest(&ring, req);
        } else if (req->stage == STAGE_BIND &&
                   req->bind_phase == BIND_SECOND_REPLY) {
          start_relay(&ring, req->connection);
        } else if (req->stage == STAGE_BIND &&
                   req->bind_phase == BIND_REJECT_REPLY) {
          abort_connection(req->connection);
        } else if (req->stage == STAGE_RELAY) {
          req->op = OP_RECV;
          req->sent = 0;
          req->len = 0;
          prepareRequest(&ring, req);
        } else {
          abort_connection(req->connection);
        }
      }
      break;
    case OP_ACCEPT:
      break;
    }
  }

  return EXIT_SUCCESS;
}
