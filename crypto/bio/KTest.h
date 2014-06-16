//===-- KTest.h --------------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include <sys/types.h>
#include <time.h>

#ifndef __COMMON_KTEST_H__
#define __COMMON_KTEST_H__


#ifdef __cplusplus
extern "C" {
#endif

  typedef struct KTestObject KTestObject;
  struct KTestObject {
    char *name;
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

  // Network capture for Cliver
  enum kTestMode {KTEST_NONE, KTEST_RECORD, KTEST_PLAYBACK};
  ssize_t ktest_writesocket(int fd, const void *buf, size_t count);
  ssize_t ktest_readsocket(int fd, void *buf, size_t count);
  int ktest_RAND_bytes(unsigned char *buf, int num);
  int ktest_RAND_pseudo_bytes(unsigned char *buf, int num);
  time_t ktest_time(time_t *t);

  void ktest_start(const char *filestem, enum kTestMode mode);
  void ktest_finish();		     // write capture to file

#ifdef __cplusplus
}
#endif

#endif
