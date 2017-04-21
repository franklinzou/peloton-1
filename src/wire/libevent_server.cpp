//===----------------------------------------------------------------------===//
//
//                         Peloton
//
// libevent_server.cpp
//
// Identification: src/wire/libevent_server.cpp
//
// Copyright (c) 2015-16, Carnegie Mellon University Database Group
//
//===----------------------------------------------------------------------===//

#include "wire/libevent_server.h"

#include <fcntl.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <fstream>

#include "common/init.h"
#include "common/macros.h"
#include "common/thread_pool.h"

namespace peloton {
namespace wire {

int LibeventServer::recent_connfd = -1;
SSL_CTX *LibeventServer::ssl_context = nullptr;

std::unordered_map<int, std::unique_ptr<LibeventSocket>> &
LibeventServer::GetGlobalSocketList() {
  // mapping from socket id to socket object.
  static std::unordered_map<int, std::unique_ptr<LibeventSocket>>
      global_socket_list;

  return global_socket_list;
}

LibeventSocket *LibeventServer::GetConn(const int &connfd) {
  auto &global_socket_list = GetGlobalSocketList();
  if (global_socket_list.find(connfd) != global_socket_list.end()) {
    return global_socket_list.at(connfd).get();
  } else {
    return nullptr;
  }
}

void LibeventServer::CreateNewConn(const int &connfd, short ev_flags,
                                   LibeventThread *thread,
                                   ConnState init_state,
                                   SSL *conn_SSL_context) {
  auto &global_socket_list = GetGlobalSocketList();
  recent_connfd = connfd;
  if (global_socket_list.find(connfd) == global_socket_list.end()) {
    LOG_INFO("create new connection: id = %d", connfd);
  }
  global_socket_list[connfd].reset(
      new LibeventSocket(connfd, ev_flags, thread, init_state, conn_SSL_context));
  LOG_INFO("out create new connection: id = %d", connfd);
}

/**
 * Stop signal handling
 */
void Signal_Callback(UNUSED_ATTRIBUTE evutil_socket_t fd,
                     UNUSED_ATTRIBUTE short what, void *arg) {
  struct event_base *base = (event_base *)arg;
  LOG_INFO("stop");
  event_base_loopexit(base, NULL);
}

void Status_Callback(UNUSED_ATTRIBUTE evutil_socket_t fd,
                     UNUSED_ATTRIBUTE short what, void *arg) {
  LibeventServer *server = (LibeventServer *)arg;
  if (server->is_started == false) {
    server->is_started = true;
  }
  if (server->is_closed == true) {
    event_base_loopexit(server->base, NULL);
  }
}

LibeventServer::LibeventServer() {
  base = event_base_new();

  // Create our event base
  if (!base) {
    throw ConnectionException("Couldn't open event base");
  }

  // Add hang up signal event
  evstop = evsignal_new(base, SIGHUP, Signal_Callback, base);
  evsignal_add(evstop, NULL);

  struct timeval two_seconds = {2, 0};
  ev_timeout =
      event_new(base, -1, EV_TIMEOUT | EV_PERSIST, Status_Callback, this);
  event_add(ev_timeout, &two_seconds);

  // a master thread is responsible for coordinating worker threads.
  master_thread =
      std::make_shared<LibeventMasterThread>(CONNECTION_THREAD_COUNT, base);

  port_ = FLAGS_port;
  // TODO: find the way to input ssl_port parameter
  ssl_port_ = FLAGS_ssl_port;
  max_connections_ = FLAGS_max_connections;

  private_key_file_ = FLAGS_private_key_file;
  certificate_file_ = FLAGS_certificate_file;

  // For logging purposes
  //  event_enable_debug_mode();
  //  event_set_log_callback(LogCallback);

  // Commented because it's not in the libevent version we're using
  // When we upgrade this should be uncommented
  //  event_enable_debug_logging(EVENT_DBG_ALL);

  // Ignore the broken pipe signal
  // We don't want to exit on write when the client disconnects
  signal(SIGPIPE, SIG_IGN);
}

void LibeventServer::StartServer() {
  LOG_INFO("Begin to start server\n");
  if (FLAGS_socket_family == "AF_INET") {
    struct sockaddr_in sin, ssl_sin;

    PL_MEMSET(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(port_);

    int listen_fd, ssl_listen_fd;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (listen_fd < 0) {
      throw ConnectionException("Failed to create listen socket");
    }

    int reuse = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    if (bind(listen_fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
      throw ConnectionException("Failed to bind socket to port: " +
                                std::to_string(port_));
    }

    int conn_backlog = 12;
    if (listen(listen_fd, conn_backlog) < 0) {
      throw ConnectionException("Failed to listen to socket");
    }

    LibeventServer::CreateNewConn(listen_fd, EV_READ | EV_PERSIST,
                                  master_thread.get(), CONN_LISTENING, nullptr);

    LOG_INFO("Listening on port %lu", port_);

    /* Initialize SSL listener connection */
    SSL_load_error_strings();
    SSL_library_init();


    if ((ssl_context = SSL_CTX_new(TLSv1_server_method())) == NULL)
    {
      throw ConnectionException("Error creating SSL context.\n");
    }

    LOG_INFO("private key file path %s", private_key_file_.c_str());
    /* register private key */
    if (SSL_CTX_use_PrivateKey_file(ssl_context, private_key_file_.c_str(),
                                    SSL_FILETYPE_PEM) == 0)
    {
      SSL_CTX_free(ssl_context);
      ERR_print_errors_fp(stderr);
      throw ConnectionException("Error associating private key.\n");
    }
    LOG_INFO("certificate file path %s", certificate_file_.c_str());
    /* register public key (certificate) */
    if (SSL_CTX_use_certificate_file(ssl_context, certificate_file_.c_str(),
                                     SSL_FILETYPE_PEM) == 0)
    {
      SSL_CTX_free(ssl_context);
      ERR_print_errors_fp(stderr);
      throw ConnectionException("Error associating certificate.\n");
    }

    if ((ssl_listen_fd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    {
      SSL_CTX_free(ssl_context);
      throw ConnectionException("Failed creating ssl socket.\n");
    }

//    setsockopt(ssl_listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    ssl_sin.sin_family = AF_INET;
    ssl_sin.sin_port = htons(ssl_port_);
    ssl_sin.sin_addr.s_addr = INADDR_ANY;

    if (bind(ssl_listen_fd,
        (struct sockaddr *) &ssl_sin, sizeof(ssl_sin)))
    {
      SSL_CTX_free(ssl_context);
      throw ConnectionException("Failed binding ssl socket.\n");
    }

    if (listen(ssl_listen_fd, conn_backlog) < 0)
    {
      SSL_CTX_free(ssl_context);
      throw ConnectionException("Error listening on ssl socket.\n");
    }

    LibeventServer::CreateNewConn(ssl_listen_fd, EV_READ | EV_PERSIST,
                                  master_thread.get(), CONN_SSL_LISTENING, nullptr);
    LOG_INFO("SSL listening on port %lu", ssl_port_);

    event_base_dispatch(base);
    event_free(evstop);
    event_free(ev_timeout);
    event_base_free(base);
    static_cast<LibeventMasterThread *>(master_thread.get())->CloseConnection();
    LibeventServer::GetConn(listen_fd)->CloseSocket();
    LibeventServer::GetConn(ssl_listen_fd)->CloseSocket();
    LOG_INFO("Server Closed");
  }

  // This socket family code is not implemented yet
  else {
    throw ConnectionException("Unsupported socket family");
  }
}

void LibeventServer::CloseServer() {
  LOG_INFO("Begin to stop server");
  is_closed = true;
  // event_base_loopbreak(base);
  // static_cast<LibeventMasterThread
  // *>(master_thread.get())->CloseConnection();
}
}
}
