#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define PROTO_MAXLEN 10
#define URL_MAXLEN 6144
#define HOSTNAME_MAXLEN 255
#define MAXDATASIZE 16384

#include "log.h"

#define EPOLL_ERRS (EPOLLRDHUP | EPOLLERR | EPOLLHUP)

void *get_in_addr(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in *)sa)->sin_addr);
  }
  return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int set_nonblk(int fd) {
  return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

typedef struct conn_info {
  int connfd;
  int filefd;
  unsigned short len;
  unsigned short offset;
  char buf[PIPE_BUF];
} conn_info_t;

ssize_t sendall(int sockfd, void *buffer, size_t length) {
  size_t sent = 0;
  ssize_t ret;
  do {
    ret = send(sockfd, buffer + sent, length - sent, 0);
    if (ret > 0) {
      sent += ret;
    } else {
      if (errno == EINTR)
        continue;
      else {
        L_PERROR();
        return -1;
      }
    }
  } while (sent < length);
  return sent;
}

ssize_t recvall(int sockfd, void *buffer, size_t length) {
  size_t recved = 0;
  ssize_t ret;
  do {
    ret = recv(sockfd, buffer + recved, length - recved, 0);
    if (ret > 0) {
      recved += ret;
    } else if (ret == 0) {
      break;
    } else {
      if (errno == EINTR) {
        ret = 0;
        continue;
      } else {
        L_PERROR();
        return -1;
      }
    }
  } while (recved < length);
  return recved;
}

char *urldecode(const char *str) {
  if (!str) {
    L_ERR("str = NULL");
    return NULL;
  }
  size_t len = strlen(str);
  if (len < 3) {
    L_INFO("No need to escape.");
    return strdup(str);
  }
  char *new_str = calloc(sizeof(char), len + 1);
  if (!new_str) {
    L_PERROR();
    L_ERR("Failed to allocate temporary array.")
    return NULL;
  }
  char to_escape[3] = {0, 0, 0};
  size_t last_cpy_dst = 0, last_cpy_src = 0;
  for (size_t i = 0; i < len - 2; i++) {
    if (str[i] == '%') {
      strncpy(to_escape, str + i + 1, 2);
      strncpy(new_str + last_cpy_dst, str + last_cpy_src, i - last_cpy_src);
      last_cpy_dst += i - last_cpy_src + 1;
      last_cpy_src = i + 3;
      dbg(last_cpy_src);
      dbg(last_cpy_dst);
      unsigned int x;
      sscanf(to_escape, "%x", &x);
      new_str[last_cpy_dst - 1] = (char)x;
      dbg(new_str);
    }
  }
  strncpy(new_str + last_cpy_dst, str + last_cpy_src, len - last_cpy_src);
  return new_str;
}

ssize_t recv_line(int sockfd, char *buf, size_t bufsize) {
  char *ptr = buf;
  ssize_t ret = 0;
  do {
    ptr += ret;
    if (ptr - buf > (ssize_t)bufsize) return -1;
    ret = recv(sockfd, ptr, 1, 0);
    if (ret < 0) {
      if (errno == EINTR) {
        ret = 0;
        continue;
      } else {
        L_PERROR();
        return -1;
      }
    }
  } while (!strstr(buf, "\r\n"));
  return (ptr - buf) + ret;
}

bool is_whitelist_param(char *param) {
  if (strstr(param, "p=") == param) return true;
  if (strstr(param, "page=") == param) return true;
  if (strstr(param, "t=") == param) return true;
  if (strstr(param, "itemsId=") == param) return true;
  if (strstr(param, "tab=") == param) return true;
  if (strstr(param, "topic_id=") == param) return true;
  if (strstr(param, "vote_id=") == param) return true;
  return false;
}

int generic_params_filter(char *str_params) {
  char *ptr = str_params + 1, *saveptr = str_params + 1;
  char *new_param_list = malloc(strlen(str_params));
  if (!new_param_list) {
    L_PERROR();
    goto err;
  }
  char *writeptr = new_param_list;
  while ((ptr = strtok_r(saveptr, "&", &saveptr))) {
    if (is_whitelist_param(ptr)) {
      if (writeptr != new_param_list) {
        *writeptr = '&';
        writeptr++;
      }
      memcpy(writeptr, ptr, strlen(ptr));
      writeptr += strlen(ptr);
    }
  }
  *writeptr = '\0';
  memcpy(str_params + 1, new_param_list, writeptr - new_param_list + 1);
  return 0;
err:
  return 1;
}

char *recv_url(int sockfd) {
  char *buf = calloc(MAXDATASIZE, 1);
  if (!buf) {
    L_PERROR();
    return NULL;
  }
  char *ptr = buf;
  char *url_found = NULL;
  // read http status line
  ssize_t ret = recv_line(sockfd, buf, MAXDATASIZE);
  if (ret < 0) {
    free(buf);
    return NULL;
  }
  char *spliter;
  if (!(spliter = strchr(buf, ' '))) {
    L_ERR("Invalid HTTP Response.\n");
    free(buf);
    return NULL;
  }
  char tmp[20];
  memset(tmp, 0, 20);
  strncpy(tmp, spliter + 1, strchr(spliter, '\r') - spliter - 1);
  L_INFOF("Server responsed: %s", tmp);
  if (!(strcasestr(spliter, "302 Found") ||
        strcasestr(spliter, "301 Moved Permanently"))) {
    free(buf);
    return NULL;
  }
  ret = 0;
  while (!strstr(ptr - 2, "\r\n\r\n")) {
    ptr += ret;
    ret = recv_line(sockfd, ptr, MAXDATASIZE - (buf - ptr));
    if (ret < 0) {
      free(buf);
      return NULL;
    }
    if (strcasestr(ptr, "Location:")) {
      char *url_start = strcasestr(ptr + strlen("Location:"), "http");
      if (!url_start) {
        free(buf);
        return NULL;
      }
      int url_len = strchr(url_start, '\r') - url_start;
      if (url_len <= 0) {
        free(buf);
        return NULL;
      }
      url_found = strndup(url_start, url_len);
      L_INFOF("URL captured: %s", url_found);
      break;
    }
  }
  ptr += ret;
  L_DEBUGF("Header Length read: %ld bytes", (ptr - buf));
  if (url_found) {
    char *hostname = NULL, *hostname_end = NULL;
    if (!(hostname = strstr(url_found, "://"))) {
      L_ERR("Invalid HTTP Response.\n");
      free(buf);
      return NULL;
    }
    hostname += 3;
    if (!(hostname_end = strchr(hostname, '/'))) {
      L_ERR("Invalid HTTP Response.\n");
      free(buf);
      return NULL;
    }
    hostname = strndup(hostname, hostname_end - hostname);
    int is_taobao = 0;
    if (!strcmp(hostname, "d.bilibili.com")) {
      // issue #1: fix handle share_source_ugc_download
      char *real_location = strcasestr(url_found, "preUrl=");
      if (real_location) {
        real_location += 7;
        char *real_location_end = strchr(real_location, '&');
        if (real_location_end) *real_location_end = '\0';
        char *new_url = urldecode(real_location);
        if (!new_url) {
          L_ERR("Unexpected urldecode() failure.");
        } else {
          free(url_found);
          url_found = new_url;
        }
      }
    } else if (!strcmp(hostname, "s.click.taobao.com")) {
      // issue #9: b23.tv/mall- => s.click.taobao.com
      // char *new_url = taobao_fetcher(url_found);
      // free(url_found);
      is_taobao = 1;
    }
    char *have_params = strchr(url_found, '?');
    if (have_params && !is_taobao) {
      if (generic_params_filter(have_params) || strlen(have_params) == 1)
        *have_params = '\0';
      L_INFOF("Rewritten URL: %s", url_found);
    } else {
      L_INFOF("Kept original URL: %s", url_found);
    }
    free(buf);
    return url_found;
    free(hostname);
  }
  free(buf);
  return NULL;
}

void *fetch_b23tv(void *args_) {
  struct {
    conn_info_t *info;
    char *url;
  } args;
  memcpy(&args, args_, sizeof(args));
  free(args_);

  struct addrinfo hints, *servinfo, *p;
  int rv;
  char s[INET6_ADDRSTRLEN];

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if ((rv = getaddrinfo("bili2233.cn", "80", &hints, &servinfo)) != 0) {
    L_ERRF("getaddrinfo: %s", gai_strerror(rv));
    return NULL;
  }
  int sockfd;
  // loop through all the results and connect to the first we can
  for (p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      L_PERROR();
      continue;
    }

    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      L_PERROR();
      continue;
    }

    break;
  }
  if (p == NULL) {
    L_ERR("failed to connect.\n");
    return NULL;
  }

  inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s,
            sizeof s);
  L_DEBUGF("connecting to %s...", s);

  freeaddrinfo(servinfo);  // all done with this structure

  char *buf = calloc(MAXDATASIZE, 1);
  if (!buf) {
    L_PERROR();
    return NULL;
  }
  if (strstr(args.url, "/api?full=") == args.url) {
    char *decoded_url = urldecode(args.url);
    if (decoded_url) {
      char *hostname_in_full = strcasestr(decoded_url, "b23.tv/");
      if (!hostname_in_full)
        hostname_in_full = strcasestr(decoded_url, "bili2233.cn/");
      char *real_get_location;
      if (hostname_in_full) {
        real_get_location = strchr(hostname_in_full, '/');
      } else {
        real_get_location = strrchr(decoded_url, '/');
      }
      if (real_get_location && strlen(real_get_location) > 1 &&
          strlen(real_get_location) <= strlen(args.url))
        strcpy(args.url, real_get_location);
      free(decoded_url);
    }
  }
  snprintf(buf, MAXDATASIZE,
           "GET %s HTTP/1.1\r\n"
           "Host: bili2233.cn\r\n"
           "Connection: close\r\n"
           "Accept: */*\r\n\r\n",
           args.url);
  if (sendall(sockfd, buf, strlen(buf)) < 0) {
    L_ERR("Error occured when sending HTTP Request.");
    return NULL;
  }
  free(buf);
  buf = NULL;
  char *prepared_response = recv_url(sockfd);
  close(sockfd);
  if (prepared_response) {
    snprintf(
        args.info->buf, PIPE_BUF,
        "HTTP/1.1 200 OK\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "Cache-Control: public, max-age=31536000, stale-if-error=86400\r\n\r\n"
        "<html><head><meta charset=\"gbk\"><meta name=\"viewport\" "
        "content=\"width=device-width, "
        "initial-scale=1\"> <title>b23.wtf</title> <link rel=\"stylesheet\" "
        "href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/"
        "bootstrap.min.css\" "
        "integrity=\"sha384-Gn5384xqQ1aoWXA+"
        "058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm\" "
        "crossorigin=\"anonymous\"> <link rel=\"icon\" type=\"image/x-icon\" "
        "href=\"https://raw.githubusercontent.com/nicholascw/b23.wtf/master/"
        "favicon.ico\"> <link rel=\"icon\" type=\"image/png\" "
        "href=\"https://raw.githubusercontent.com/nicholascw/b23.wtf/master/"
        "favicon.png\"> <meta name=\"theme-color\" content=\"#7952b3\"> <meta "
        "property=\"og:image\" "
        "content=\"https://raw.githubusercontent.com/nicholascw/b23.wtf/master/"
        "demo.png\"> <meta property=\"og:title\" content=\"bilibili "
        "短链接追踪信息解决方案\"> <style>.bd-placeholder-img{font-size: "
        "1.125rem; text-anchor: middle; -webkit-user-select: none; "
        "-moz-user-select: none; user-select: none;}@media (min-width: "
        "768px){.bd-placeholder-img-lg{font-size: 3.5rem;}}</style> "
        "<style>.btn-secondary, .btn-secondary:hover, "
        ".btn-secondary:focus{text-shadow: none;}body{text-shadow: 0 .05rem "
        ".1rem rgba(0, 0, 0, .5); box-shadow: inset 0 0 5rem rgba(0, 0, 0, "
        ".5);}.cover-container{max-width: 60em;}.nav-masthead "
        ".nav-link{padding: .25rem 0; font-weight: 700; color: rgba(255, 255, "
        "255, .5); background-color: transparent; border-bottom: .25rem solid "
        "transparent;}.nav-masthead .nav-link:hover, .nav-masthead "
        ".nav-link:focus{border-bottom-color: rgba(255, 255, 255, "
        ".25);}.nav-masthead .nav-link + .nav-link{margin-left: "
        "1rem;}.nav-masthead .active{color: #fff; border-bottom-color: "
        "#fff;}</style></head><body class=\"d-flex h-100 text-center "
        "text-white bg-dark\"> <script>function "
        "c(){navigator.clipboard.writeText(\"%s\"); "
        "document.getElementById(\"cc\").removeAttribute(\"hidden\")}</script> "
        "<div class=\"cover-container d-flex w-100 h-100 p-3 mx-auto "
        "flex-column\"> <header class=\"mb-auto\"> <div> <a "
        "href=\"https://b23.wtf\"><h3 "
        "class=\"float-md-start mb-0\"><img "
        "src=\"https://raw.githubusercontent.com/nicholascw/b23.wtf/master/"
        "logo.png\" style=\"height:1em; postion:relative\"></a> b23.wtf</h3> "
        "<nav "
        "class=\"nav nav-masthead justify-content-center float-md-end\"> <a "
        "class=\"nav-link\" href=\"https://status.b23.wtf\">服务状态</a> <a "
        "class=\"nav-link\" "
        "href=\"https://github.com/nicholascw/b23.wtf/issues/new\">错误报告</"
        "a> </nav> </header> <main class=\"px-3\"> <h2>真实目的地址为</h2> "
        "<div class=\"input-group input-group-lg\"> <input type=\"text\" "
        "class=\"form-control\" value=\"%s\" id=\"x\" readonly> <div "
        "class=\"input-group-append\"> <button class=\"btn btn-secondary\" "
        "type=\"button\" onclick=\"c()\" id=\"c\">复制 <br><span class=\"badge "
        "badge-success\" id=\"cc\" hidden>已复制</span></button> <a "
        "class=\"btn btn-info\" href=\"%s\">前往</a> </div></div></main> "
        "<footer class=\"mt-auto\"> <p>Powered by <a "
        "href=\"https://www.nicholas.wang/\">Nicholas Wang</a>. Project "
        "licensed under GPLv3. <a "
        "href=\"https://github.com/nicholascw/b23.wtf\">Source</a> "
        "</p></footer></div></body></html>",
        prepared_response, prepared_response, prepared_response);
    L_INFOF("Responded fd=%d 200 OK", args.info->connfd);
  } else {
    strcpy(args.info->buf,
           "HTTP/1.1 400 Bad Request\r\n\r\n400 Bad Request -- b23.wtf\r\n");
    L_INFOF("Responded fd=%d 400 Bad Request", args.info->connfd);
  }
  args.info->len = strlen(args.info->buf);
  args.info->filefd = -1;
  free(prepared_response);
  return NULL;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("Usage: %s [PORT]\n", argv[0]);
    return 0;
  }
  int sockfd, new_fd;
  struct addrinfo hints, *servinfo, *p;
  struct sockaddr_storage their_addr;  // connector's address information
  socklen_t sin_size;
  int yes = 1;
  char s[INET6_ADDRSTRLEN];
  int rv;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;  // use my IP

  if ((rv = getaddrinfo(NULL, argv[1], &hints, &servinfo)) != 0) {
    L_ERRF("getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }

  // loop through all the results and bind to the first we can
  for (p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      L_PERROR();
      continue;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
      L_PERROR();
      exit(1);
    }
    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      L_PERROR();
      continue;
    }
    break;
  }
  if (!p) {
    L_ERR("failed to bind.");
    return 2;
  }
  freeaddrinfo(servinfo);  // all done with this structure

  if (listen(sockfd, SOMAXCONN) == -1) {
    L_PERROR();
    exit(1);
  }

  if (set_nonblk(sockfd) == -1) {
    L_PERROR();
  }
  int epollfd = epoll_create1(0);
  if (epollfd == -1) {
    L_PERROR();
    return 1;
  }
  struct epoll_event ev;
  ev.data.fd = sockfd;
  ev.events = EPOLLIN;
  if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
    L_PERROR();
    return 1;
  }
  struct epoll_event events[1024];
  memset(events, 0, sizeof(events));

  L_INFO("waiting for connections...");

  while (1) {
    int cnt_fd = epoll_wait(epollfd, events, 1024, -1);
    if (cnt_fd > 0) {
      for (int i = 0; i < cnt_fd; i++) {
        int this_evfd = events[i].data.fd == sockfd
                            ? sockfd
                            : ((conn_info_t *)events[i].data.ptr)->connfd;
        if (events[i].events & EPOLL_ERRS) {
          L_ERRF("Error occured on fd=%d, closing...", this_evfd);
          free(events[i].data.ptr);
          close(this_evfd);
          epoll_ctl(epollfd, EPOLL_CTL_DEL, this_evfd, NULL);
          continue;
        }
        if (this_evfd == sockfd) {
          // new connection
          sin_size = sizeof their_addr;
          new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
          if (new_fd == -1) {
            L_PERROR();
          } else {
            inet_ntop(their_addr.ss_family,
                      get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
            L_INFOF("fd=%d got connection from %s", new_fd, s);
          }
          if (set_nonblk(sockfd) == -1) {
            L_PERROR();
          }
          conn_info_t *new_conn = calloc(1, sizeof(conn_info_t));
          if (!new_conn) {
            L_PERROR();
            L_ERRF("failed to allocate space for fd=%d, closing socket...",
                   new_fd);
            close(new_fd);
          } else {
            ev.data.ptr = new_conn;
            new_conn->connfd = new_fd;
            ev.events = EPOLLIN | EPOLL_ERRS;
            if (epoll_ctl(epollfd, EPOLL_CTL_ADD, new_fd, &ev) == -1) {
              L_PERROR();
              L_ERRF("failed to add fd=%d into epoll, closing socket...",
                     new_fd);
              free(new_conn);
              close(new_fd);
            } else {
              L_INFOF("fd=%d added %s to epoll succesfully.", new_fd, s);
            }
          }
        } else {
          // existing connection
          conn_info_t *this_conn = events[i].data.ptr;
          if (events[i].events & EPOLLIN) {
            if (this_conn->filefd == -1) continue;
            // read in header
            int ret = recv(this_evfd, this_conn->buf + this_conn->len,
                           PIPE_BUF - this_conn->len - 1, 0);
            if (ret < 0) {
              if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
                continue;
              else {
                L_PERROR();
                L_ERRF(
                    "Error when receiving HTTP header from fd=%d, closing...",
                    this_evfd);
                free(this_conn);
                epoll_ctl(epollfd, EPOLL_CTL_DEL, this_evfd, NULL);
                close(this_evfd);
                continue;
              }
            }
            this_conn->buf[this_conn->len + ret] = '\0';
            if (!strstr(this_conn->buf, "\r\n\r\n")) {
              // end-of-header not met
              this_conn->len += ret;
              if (this_conn->len >= PIPE_BUF) {
                // 413 Entity Too Large
                strcpy(this_conn->buf, "HTTP/1.1 413 Entity Too Large\r\n\r\n");
                L_INFOF("Responded fd=%d 413 Entity Too Large", this_evfd);
                this_conn->len = strlen(this_conn->buf);
                this_conn->filefd = -1;
                ev.data.fd = this_evfd;
                ev.data.ptr = events[i].data.ptr;
                ev.events = EPOLLOUT | EPOLL_ERRS;
                if (epoll_ctl(epollfd, EPOLL_CTL_MOD, this_evfd, &ev) == -1) {
                  L_PERROR();
                }
              }
              continue;
            }
            if (strcasestr(this_conn->buf, "GET ") != this_conn->buf &&
                strcasestr(this_conn->buf, "HEAD ") != this_conn->buf) {
              strcpy(this_conn->buf,
                     "HTTP/1.1 501 Not Implemented\r\n"
                     "Allow: GET, HEAD\r\n\r\n");
              L_INFOF("Responded fd=%d 501 Not Implemented", this_evfd);
              this_conn->len = strlen(this_conn->buf);
              this_conn->filefd = -1;
            } else {
              char *req_start_line_crlf = strstr(this_conn->buf, "\r\n");
              if (!req_start_line_crlf) L_ERR("Unexpected buffer change.");
              *req_start_line_crlf = '\0';
              char *first_sp, *last_sp;
              first_sp = strchr(this_conn->buf, ' ');
              last_sp = strrchr(this_conn->buf, ' ');
              if (!first_sp || !last_sp || first_sp == last_sp) {
                strcpy(this_conn->buf,
                       "HTTP/1.1 400 Bad Request\r\n\r\n400 Bad Request -- "
                       "b23.wtf\r\n");
                L_INFOF("Responded fd=%d 400 Bad Request", this_evfd);
                this_conn->len = strlen(this_conn->buf);
                this_conn->filefd = -1;
              } else {
                *last_sp = '\0';
                first_sp++;
                if (strlen(first_sp) == 1 && *first_sp == '/') {
                  // return index.html
                  int file_ret = open("./index.html", O_RDONLY | O_NONBLOCK);
                  if (file_ret == -1) {
                    if (errno == EACCES) {
                      strcpy(this_conn->buf, "HTTP/1.1 403 Forbidden\r\n\r\n");
                      L_INFOF("Responded fd=%d 403 Forbidden", this_evfd);
                      this_conn->len = strlen(this_conn->buf);
                      this_conn->filefd = -1;
                    } else if (errno == ENOENT) {
                      strcpy(this_conn->buf, "HTTP/1.1 404 Not Found\r\n\r\n");
                      L_INFOF("Responded fd=%d 404 Not Found", this_evfd);
                      this_conn->len = strlen(this_conn->buf);
                      this_conn->filefd = -1;
                    } else {
                      strcpy(this_conn->buf,
                             "HTTP/1.1 400 Bad Request\r\n\r\n400 Bad Request "
                             "-- b23.wtf\r\n");
                      L_INFOF("Responded fd=%d 400 Bad Request", this_evfd);
                      this_conn->len = strlen(this_conn->buf);
                      this_conn->filefd = -1;
                    }
                  } else {
                    this_conn->filefd = file_ret;
                    struct stat file_stat = {.st_size = -1};
                    if (fstat(file_ret, &file_stat) == -1) {
                      L_PERROR();
                    }
                    if (S_ISDIR(file_stat.st_mode)) {
                      close(file_ret);
                      this_conn->filefd = -1;
                      strcpy(this_conn->buf, "HTTP/1.1 403 Forbidden\r\n\r\n");
                      L_INFOF(
                          "Responded fd=%d 403 Forbidden due to is "
                          "requesting "
                          "a directory",
                          this_evfd);
                      this_conn->len = strlen(this_conn->buf);
                      this_conn->filefd = -1;
                    } else {
                      int written_header_len;
                      if (file_stat.st_size > 0) {
                        written_header_len = snprintf(
                            this_conn->buf, PIPE_BUF,
                            "HTTP/1.1 200 OK\r\nContent-Length: %ld\r\n\r\n",
                            file_stat.st_size);
                        L_INFOF("Responded fd=%d 200 OK, len=%ld", this_evfd,
                                file_stat.st_size);
                      } else {
                        written_header_len =
                            snprintf(this_conn->buf, PIPE_BUF,
                                     "HTTP/1.1 200 OK\r\n\r\n");
                        L_INFOF("Responded fd=%d 200 OK", this_evfd);
                      }
                      if (written_header_len > 0) {
                        this_conn->len = written_header_len;
                      } else {
                        L_ERR("error when generating header");
                        close(file_ret);
                        strcpy(this_conn->buf,
                               "HTTP/1.1 400 Bad Request\r\n\r\n400 Bad "
                               "Request -- b23.wtf\r\n");
                        L_INFOF("Responded fd=%d 400 Bad Request", this_evfd);
                        this_conn->len = strlen(this_conn->buf);
                        this_conn->filefd = -1;
                      }
                    }
                  }
                } else {
                  this_conn->filefd = -23232323;
                  void *thread_args = malloc(sizeof(struct {
                    conn_info_t *info;
                    char *url;
                  }));
                  if (!thread_args) {
                    L_PERROR();
                    strcpy(this_conn->buf,
                           "HTTP/1.1 503 Service Unavailable\r\n\r\n");
                    L_INFOF("Responded fd=%d 503 Service Unavailable",
                            this_evfd);
                    this_conn->len = strlen(this_conn->buf);
                    this_conn->filefd = -1;
                  }
                  memcpy(thread_args, &this_conn, sizeof(conn_info_t *));
                  memcpy(thread_args + sizeof(conn_info_t *), &first_sp,
                         sizeof(char *));
                  pthread_t id;
                  pthread_create(&id, NULL, fetch_b23tv, thread_args);
                }
              }
            }
            ev.data.ptr = events[i].data.ptr;
            ev.events = EPOLLOUT | EPOLL_ERRS;
            if (epoll_ctl(epollfd, EPOLL_CTL_MOD, this_evfd, &ev) == -1) {
              L_PERROR();
            }
          } else if (events[i].events & EPOLLOUT) {
            // write out file
            if (this_conn->filefd == -23232323) continue;  // not ready
            if (this_conn->len > 0) {
              int send_ret =
                  send(this_evfd, this_conn->buf,
                       this_conn->len + this_conn->offset, MSG_DONTWAIT);
              if (send_ret > 0) {
                L_DEBUGF("sent fd=%d %d byte(s)", this_evfd, send_ret);
                if (send_ret < this_conn->len - this_conn->offset) {
                  this_conn->offset += send_ret;
                } else {
                  if (this_conn->filefd > 0) {
                    // read more file in
                    int read_ret =
                        read(this_conn->filefd, this_conn->buf, PIPE_BUF);
                    if (read_ret > 0) {
                      L_DEBUGF("read in %d bytes to fd=%d buffer from fd=%d",
                               read_ret, this_evfd, this_conn->filefd);
                      this_conn->len = read_ret;
                      this_conn->offset = 0;
                    } else if (read_ret == 0) {
                      // close connection
                      epoll_ctl(epollfd, EPOLL_CTL_DEL, this_evfd, NULL);
                      close(this_evfd);
                      close(this_conn->filefd);
                      free(this_conn);
                    } else {
                      if (errno == EAGAIN || errno == EINTR ||
                          errno == EWOULDBLOCK)
                        continue;
                      else
                        L_PERROR();
                    }
                  } else {
                    // close connection
                    L_INFOF("close fd=%d due to eof@fd=%d.", this_evfd,
                            this_conn->filefd);
                    epoll_ctl(epollfd, EPOLL_CTL_DEL, this_evfd, NULL);
                    close(this_evfd);
                    close(this_conn->filefd);
                    free(this_conn);
                  }
                }
              } else {
                if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
                  continue;
                else
                  L_PERROR();
              }
            } else {
              // close connection
              L_INFOF("close fd=%d due to buffer len=0.", this_evfd);
              epoll_ctl(epollfd, EPOLL_CTL_DEL, this_evfd, NULL);
              close(this_evfd);
              close(this_conn->filefd);
              free(this_conn);
            }
          } else {
            L_DEBUG("Unkown epoll events returned.");
          }
        }
      }
    } else if (cnt_fd < 0) {
      L_PERROR();
    }
  }

  return 0;
}
