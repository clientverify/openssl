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

  typedef struct KTestObject KTestObject;
  struct KTestObject {
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
    KTestObject *objects;
  };

  /* returns the current .ktest file format version */
  unsigned kTest_getCurrentVersion();
  
  /* return true iff file at path matches KTest header */
  int   kTest_isKTestFile(const char *path);

  /* returns NULL on (unspecified) error */
  KTest* kTest_fromFile(const char *path);

  /* returns 1 on success, 0 on (unspecified) error */
  int   kTest_toFile(KTest *, const char *path);
  
  /* returns total number of object bytes */
  unsigned kTest_numBytes(KTest *);

  void  kTest_free(KTest *);

  // Capture mode
  enum kTestMode {KTEST_NONE, KTEST_RECORD, KTEST_PLAYBACK};
  const char *arg_ktest_filename;
  enum kTestMode arg_ktest_mode;

  // Network capture for Cliver
  int ktest_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
  int ktest_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
  int ktest_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  int ktest_select(int nfds, fd_set *readfds, fd_set *writefds,
		  fd_set *exceptfds, struct timeval *timeout);
  int bssl_stdin_ktest_select(int nfds, fd_set *readfds, fd_set *writefds,
            fd_set *exceptfds, struct timeval *timeout);
  ssize_t ktest_writesocket(int fd, const void *buf, size_t count);
  ssize_t ktest_readsocket(int fd, void *buf, size_t count);

  // stdin capture for Cliver
  int ktest_raw_read_stdin(void *buf, int siz);

  // Random number generator capture for Cliver
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
  int ktest_fcntl(int socket, int flags, int not_sure);

int bssl_EC_POINT_mul( const EC_GROUP *group, EC_POINT *r,
    const BIGNUM *n, const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif
