//===-- KTest.h --------------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __COMMON_KTEST_H__
#define __COMMON_KTEST_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <time.h>
#include <netdb.h>

#include <openssl/ec.h>
#include <openssl/bn.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KTEST_DEBUG 1

enum { MONITOR_VERIFY_SENDSOCKET=0, MONITOR_VERIFY_READSOCKET,
  NET_VERIFY_SENDSOCKET, NET_VERIFY_READSOCKET, RNG, PRNG, TIME, STDIN, SELECT,
       MASTER_SECRET, KTEST_GET_PEER_NAME, WAIT_PID, RECV_MSG_FD,
       READSOCKET_OR_ERROR, READSOCKET, WRITESOCKET, TTYNAME, ARC4RNG,
       PTY_DUP_VERIFY_SENDSOCKET, PTY_DUP_VERIFY_READSOCKET};
static char* ktest_object_names[] = {
  "monitor_verify_sendsocket", "monitor_verify_readsocket", "net_verify_sendsocket", "net_verify_readsocket", "rng", "prng", "time", "stdin", "select", "master_secret", "get_peer_name",
  "waitpid", "recvmsg_fd", "readsocket_or_error", "readsocket", "writesocket", "ttyname",
  "arc4rng", "pty_dup_verify_sendsocket", "pty_dup_verify_readsocket"
};

  int monitor_socket;
  int net_socket;
  int pty_socket;
  int pty_dup_socket;
  typedef struct KTestObject KTestObject;
  struct KTestObject {
    int record;
    char *name;
    struct timeval timestamp;
    unsigned numBytes;
    unsigned char *bytes;
  };
  
  typedef struct KTest KTest;
  struct KTest {
    /* file format version */
    unsigned version; 
    
    unsigned numArgs;
    char **args;

    unsigned symArgvs;
    unsigned symArgvLen;

    unsigned numObjects;
    unsigned numUnrecordedObjects;
    KTestObject *objects;
  };

  void do_not_record_this_record(void);
  /* returns the current .ktest file format version */
  unsigned kTest_getCurrentVersion();
  
  /* return true iff file at path matches KTest header */
  int   kTest_isKTestFile(const char *path);

  /* returns NULL on (unspecified) error */
  KTest* kTest_fromFile(const char *path);

  /* returns 1 on success, 0 on (unspecified) error */
  int   kTest_toFile(KTest *, const char *path, int unrecording);
  
  /* returns total number of object bytes */
  unsigned kTest_numBytes(KTest *);

  void  kTest_free(KTest *);

  // Capture mode
  enum kTestMode {KTEST_NONE, KTEST_RECORD, KTEST_PLAYBACK};
  //put these back in c file and access with getters and setters...
  void ktest_set_mode_none(void);
  enum kTestMode ktest_get_mode(void);
  void ktest_set_mode_off(void);
  void ktest_set_mode_on(void);

typedef struct KTestObjectVector {
  KTestObject *objects;
  int size;
  int unrecorded;
  int capacity; // capacity >= size
  int playback_index; // starts at 0
} KTestObjectVector;
  KTestObjectVector ktov;  // contains network, time, and prng captures
  KTestObject* KTOV_next_object(KTestObjectVector *ov, const char *name);
  void KTOV_append(KTestObjectVector *ov, const char *name,
    int num_bytes, const void *bytes);

  int ktest_shutdown(int socket, int how);
  enum KTEST_FORK {PARENT, CHILD};
  int  ktest_waitpid(pid_t pid, int *status, int options);
  pid_t ktest_fork(enum KTEST_FORK which);
  void ktest_record_signal(int sig_num);
  int  ktest_register_signal_handler(int (*a)(int));
  void insert_ktest_sockfd(int sockfd);
  // Network capture for Cliver
  int ktest_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
  int ktest_socket(int domain, int type, int protocol);
  int ktest_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
  int ktest_listen(int sockfd, int backlog);
  int ktest_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  int ktest_select(int nfds, fd_set *readfds, fd_set *writefds,
		  fd_set *exceptfds, struct timeval *timeout);
  int bssl_stdin_ktest_select(int nfds, fd_set *readfds, fd_set *writefds,
            fd_set *exceptfds, struct timeval *timeout);
  ssize_t ktest_writesocket(int fd, const void *buf, size_t count);
  ssize_t ktest_readsocket(int fd, void *buf, size_t count);
  int     ktest_record_readbuf(int fd, char* buf, int num_bytes);
  ssize_t ktest_recvmsg_fd(int sockfd, struct msghdr *msg, int flags);

  // stdin capture for Cliver
  int ktest_raw_read_stdin(void *buf, int siz);

  // Random number generator capture for Cliver
  int ktest_RAND_status(void);
  int ktest_RAND_bytes(unsigned char *buf, int num);
  int ktest_RAND_pseudo_bytes(unsigned char *buf, int num);

  // Time capture for Cliver (actually unnecessary!)
  time_t ktest_time(time_t *t);

  // TLS Master Secret capture for Cliver
  void ktest_master_secret(unsigned char *ms, int len);

  void ktest_start(const char *filename, enum kTestMode mode);
  void ktest_finish();		     // write capture to file

  int ktest_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints, struct addrinfo **res);

  void ktest_freeaddrinfo(struct addrinfo *res);
  int ktest_getpeername(int sockfd, struct sockaddr *addr, socklen_t
       *addrlen);
  int ktest_fcntl(int socket, int flags, int not_sure);

int bssl_EC_POINT_mul( const EC_GROUP *group, EC_POINT *r,
    const BIGNUM *n, const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif
