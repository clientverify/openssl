//===-- KTest.cpp ---------------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
// Modified for Cliver.
//
//===----------------------------------------------------------------------===//

#include "KTest.h"
#include "e_os.h"

#include <openssl/rand.h>
#undef RAND_bytes
#undef RAND_pseudo_bytes

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <assert.h>

#define KTEST_VERSION 3
#define KTEST_MAGIC_SIZE 5
#define KTEST_MAGIC "KTEST"

// for compatibility reasons
#define BOUT_MAGIC "BOUT\n"

/***/

static int read_uint32(FILE *f, unsigned *value_out) {
  unsigned char data[4];
  if (fread(data, 4, 1, f)!=1)
    return 0;
  *value_out = (((((data[0]<<8) + data[1])<<8) + data[2])<<8) + data[3];
  return 1;
}

static int write_uint32(FILE *f, unsigned value) {
  unsigned char data[4];
  data[0] = value>>24;
  data[1] = value>>16;
  data[2] = value>> 8;
  data[3] = value>> 0;
  return fwrite(data, 1, 4, f)==4;
}

static int read_string(FILE *f, char **value_out) {
  unsigned len;
  if (!read_uint32(f, &len))
    return 0;
  *value_out = (char*) malloc(len+1);
  if (!*value_out)
    return 0;
  if (fread(*value_out, len, 1, f)!=1)
    return 0;
  (*value_out)[len] = 0;
  return 1;
}

static int write_string(FILE *f, const char *value) {
  unsigned len = strlen(value);
  if (!write_uint32(f, len))
    return 0;
  if (fwrite(value, len, 1, f)!=1)
    return 0;
  return 1;
}

/***/


unsigned kTest_getCurrentVersion() {
  return KTEST_VERSION;
}


static int kTest_checkHeader(FILE *f) {
  char header[KTEST_MAGIC_SIZE];
  if (fread(header, KTEST_MAGIC_SIZE, 1, f)!=1)
    return 0;
  if (memcmp(header, KTEST_MAGIC, KTEST_MAGIC_SIZE) &&
      memcmp(header, BOUT_MAGIC, KTEST_MAGIC_SIZE))
    return 0;
  return 1;
}

int kTest_isKTestFile(const char *path) {
  FILE *f = fopen(path, "rb");
  int res;

  if (!f)
    return 0;
  res = kTest_checkHeader(f);
  fclose(f);
  
  return res;
}

KTest *kTest_fromFile(const char *path) {
  FILE *f = fopen(path, "rb");
  KTest *res = 0;
  unsigned i, version;

  if (!f) 
    goto error;
  if (!kTest_checkHeader(f)) 
    goto error;

  res = (KTest*) calloc(1, sizeof(*res));
  if (!res) 
    goto error;

  if (!read_uint32(f, &version)) 
    goto error;
  
  if (version > kTest_getCurrentVersion())
    goto error;

  res->version = version;

  if (!read_uint32(f, &res->numArgs)) 
    goto error;
  res->args = (char**) calloc(res->numArgs, sizeof(*res->args));
  if (!res->args) 
    goto error;
  
  for (i=0; i<res->numArgs; i++)
    if (!read_string(f, &res->args[i]))
      goto error;

  if (version >= 2) {
    if (!read_uint32(f, &res->symArgvs)) 
      goto error;
    if (!read_uint32(f, &res->symArgvLen)) 
      goto error;
  }

  if (!read_uint32(f, &res->numObjects))
    goto error;
  res->objects = (KTestObject*) calloc(res->numObjects, sizeof(*res->objects));
  if (!res->objects)
    goto error;
  for (i=0; i<res->numObjects; i++) {
    KTestObject *o = &res->objects[i];
    if (!read_string(f, &o->name))
      goto error;
    if (!read_uint32(f, &o->numBytes))
      goto error;
    o->bytes = (unsigned char*) malloc(o->numBytes);
    if (fread(o->bytes, o->numBytes, 1, f)!=1)
      goto error;
  }

  fclose(f);

  return res;
 error:
  if (res) {
    if (res->args) {
      for (i=0; i<res->numArgs; i++)
        if (res->args[i])
          free(res->args[i]);
      free(res->args);
    }
    if (res->objects) {
      for (i=0; i<res->numObjects; i++) {
        KTestObject *bo = &res->objects[i];
        if (bo->name)
          free(bo->name);
        if (bo->bytes)
          free(bo->bytes);
      }
      free(res->objects);
    }
    free(res);
  }

  if (f) fclose(f);

  return 0;
}

int kTest_toFile(KTest *bo, const char *path) {
  FILE *f = fopen(path, "wb");
  unsigned i;

  if (!f) 
    goto error;
  if (fwrite(KTEST_MAGIC, strlen(KTEST_MAGIC), 1, f)!=1)
    goto error;
  if (!write_uint32(f, KTEST_VERSION))
    goto error;
      
  if (!write_uint32(f, bo->numArgs))
    goto error;
  for (i=0; i<bo->numArgs; i++) {
    if (!write_string(f, bo->args[i]))
      goto error;
  }

  if (!write_uint32(f, bo->symArgvs))
    goto error;
  if (!write_uint32(f, bo->symArgvLen))
    goto error;
  
  if (!write_uint32(f, bo->numObjects))
    goto error;
  for (i=0; i<bo->numObjects; i++) {
    KTestObject *o = &bo->objects[i];
    if (!write_string(f, o->name))
      goto error;
    if (!write_uint32(f, o->numBytes))
      goto error;
    if (fwrite(o->bytes, o->numBytes, 1, f)!=1)
      goto error;
  }

  fclose(f);

  return 1;
 error:
  if (f) fclose(f);
  
  return 0;
}

unsigned kTest_numBytes(KTest *bo) {
  unsigned i, res = 0;
  for (i=0; i<bo->numObjects; i++)
    res += bo->objects[i].numBytes;
  return res;
}

void kTest_free(KTest *bo) {
  unsigned i;
  for (i=0; i<bo->numArgs; i++)
    free(bo->args[i]);
  free(bo->args);
  for (i=0; i<bo->numObjects; i++) {
    free(bo->objects[i].name);
    free(bo->objects[i].bytes);
  }
  free(bo->objects);
  free(bo);
}

///////////////////////////////////////////////////////////////////////////////
// Local to this file
///////////////////////////////////////////////////////////////////////////////

typedef struct KTestObjectVector {
  KTestObject *objects;
  int size;
  int capacity; // capacity >= size
  int playback_index; // starts at 0
} KTestObjectVector;

// KTOV = "KTestObjectVector"
static void KTOV_init(KTestObjectVector *ov) {
  memset(ov, 0, sizeof(*ov));
}

static void KTOV_done(KTestObjectVector *ov) {
  if (ov && (ov->objects)) {
    int i;
    for (i = 0; i < ov->size; i++) {
      free(ov->objects[i].name);
      if (ov->objects[i].bytes != NULL) {
	free(ov->objects[i].bytes);
      }
    }
    free(ov->objects);
  }
  memset(ov, 0, sizeof(*ov));
}

static void KTOV_check_mem(KTestObjectVector *ov) {
  if (ov->size + 1 > ov->capacity) {
    size_t new_capacity = (ov->size + 1)*2;
    ov->objects = (KTestObject*) realloc(ov->objects,
					 sizeof(KTestObject) * new_capacity);
    if (!ov->objects) {
      perror("KTOV_check_mem error");
      exit(1);
    }
    ov->capacity = new_capacity;
  }
}

// Print hex and ascii side-by-side
static void KTO_print(FILE *f, const KTestObject *o) {
  unsigned int i, j;
  const unsigned int WIDTH = 16;
  fprintf(f, "%s [%u]\n", o->name, o->numBytes);
  for (i = 0; WIDTH*i <  o->numBytes; i++) {
    for (j = 0; j < 16 && WIDTH*i+j < o->numBytes; j++) {
      fprintf(f, " %2.2x", o->bytes[WIDTH*i+j]);
    }
    for (; j < 17; j++) {
      fprintf(f, "   ");
    }
    for (j = 0; j < 16 && WIDTH*i+j < o->numBytes; j++) {
      unsigned char c = o->bytes[WIDTH*i+j];
      fprintf(f, "%c", isprint(c)?c:'.');
    }
    fprintf(f, "\n");
  }
  fprintf(f, "\n");
}

// Deep copy of KTestObject
static void KTO_deepcopy(KTestObject *dest, KTestObject *src) {
  dest->name = strdup(src->name);
  dest->numBytes = src->numBytes;
  dest->bytes = (unsigned char*)malloc(sizeof(unsigned char)*src->numBytes);
  memcpy(dest->bytes, src->bytes, src->numBytes);
}

static void KTOV_print(FILE *f, const KTestObjectVector *ov) {
  int i;
  fprintf(f, "KTestObjectVector of size %d and capacity %d:\n\n",
	  ov->size, ov->capacity);
  for (i = 0; i < ov->size; i++) {
    fprintf(f, "#%d: ", i);
    KTO_print(f, &ov->objects[i]);
  }
}

static void KTOV_append(KTestObjectVector *ov,
			const char *name,
			int num_bytes,
			const void *bytes)
{
  int i;
  assert(ov != NULL);
  assert(name != NULL);
  assert(num_bytes == 0 || bytes != NULL);
  i = ov->size;
  KTOV_check_mem(ov); // allocate more memory if necessary
  ov->objects[i].name = strdup(name);
  ov->objects[i].numBytes = num_bytes;
  ov->objects[i].bytes = NULL;
  if (num_bytes > 0) {
      ov->objects[i].bytes =
          (unsigned char*)malloc(sizeof(unsigned char)*num_bytes);
      memcpy(ov->objects[i].bytes, bytes, num_bytes);
  }
  ov->size++;
  // KTO_print(stdout, &ov->objects[i]);
}

static void print_fd_set(int nfds, fd_set *fds) {
  int i;
  for (i = 0; i < nfds; i++) {
      printf(" %d", FD_ISSET(i, fds));
  }
  printf("\n");
}

enum { CLIENT_TO_SERVER=0, SERVER_TO_CLIENT, RNG, PRNG, TIME, STDIN, SELECT };
static char* ktest_object_names[] = {
  "c2s", "s2c", "rng", "prng", "time", "stdin", "select"
};

static KTestObjectVector ktov;  // contains network, time, and prng captures
static enum kTestMode ktest_mode = KTEST_NONE;
static const char *ktest_output_file = "s_client.ktest";
static const char *ktest_network_file = "s_client.net.ktest";
static int ktest_sockfd = -1; // descriptor of the socket we're capturing
//static const char *ktest_prng_file = "prng_capture.ktest"; // TODO: use this
//static const char *ktest_time_file = "time_capture.ktest"; // TODO: use this

///////////////////////////////////////////////////////////////////////////////
// Exported functionality
///////////////////////////////////////////////////////////////////////////////

int ktest_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  if (ktest_mode == KTEST_NONE) { // passthrough
      return connect(sockfd, addr, addrlen);
  }
  else if (ktest_mode == KTEST_RECORD) {
      int ret;
      ktest_sockfd = sockfd; // record the socket descriptor of interest
      ret = connect(sockfd, addr, addrlen);
      return ret;
  }
  else if (ktest_mode == KTEST_PLAYBACK) {
      // TODO: determine result manually based on stored messages
      perror("ktest_connect playback not implemented yet");
      exit(2);
  }
  else {
      perror("ktest_connect error - should never get here");
      exit(4);
  }
}

int ktest_select(int nfds, fd_set *readfds, fd_set *writefds,
		  fd_set *exceptfds, struct timeval *timeout)
{
  if (ktest_mode == KTEST_NONE) { // passthrough
      return select(nfds, readfds, writefds, exceptfds, timeout);
  }
  else if (ktest_mode == KTEST_RECORD) {
      // select input/output is stored as ASCII text in the format:
      // "sockfd 3 nfds 4 inR 1001 inW 0000 ret 1 outR 1000 outW 0000"
      //    sockfd - just for reference, not part of the select call
      //    nfds - number of active fds in fdset, usually sockfd+1
      //    inR - readfds input value
      //    inW - writefds input value
      //    ret - return value from select()
      //    outR - readfds output value
      //    outW - writefds output value
    
      int ret, i;
      unsigned int size = 4*nfds + 40 /*text*/ + 3*4 /*3 fd's*/ + 1 /*null*/;
      char *record = (char *)calloc(size, sizeof(char));
      unsigned int pos = 0;

      pos += snprintf(&record[pos], size-pos,
		      "sockfd %d nfds %d inR ", ktest_sockfd, nfds);
      for (i = 0; i < nfds; i++) {
	pos += snprintf(&record[pos], size-pos, "%d", FD_ISSET(i, readfds));
      }
      pos += snprintf(&record[pos], size-pos, " inW ");
      for (i = 0; i < nfds; i++) {
	pos += snprintf(&record[pos], size-pos, "%d", FD_ISSET(i, writefds));
      }
      
      ret = select(nfds, readfds, writefds, exceptfds, timeout);

      pos += snprintf(&record[pos], size-pos, " ret %d outR ", ret);
      for (i = 0; i < nfds; i++) {
	pos += snprintf(&record[pos], size-pos, "%d", FD_ISSET(i, readfds));
      }
      pos += snprintf(&record[pos], size-pos, " outW ");
      for (i = 0; i < nfds; i++) {
	pos += snprintf(&record[pos], size-pos, "%d", FD_ISSET(i, writefds));
      }

      record[size-1] = '\0'; // just in case we ran out of room.
      KTOV_append(&ktov, ktest_object_names[SELECT], strlen(record)+1, record);
      free(record);
      return ret;
  }
  else if (ktest_mode == KTEST_PLAYBACK) {
      // TODO: determine result manually based on stored messages
      perror("ktest_select playback not implemented yet");
      exit(2);
  }
  else {
      perror("ktest_select error - should never get here");
      exit(4);
  }
}

ssize_t ktest_writesocket(int fd, const void *buf, size_t count)
{
  if (ktest_mode == KTEST_NONE) { // passthrough
    return writesocket(fd, buf, count);
  }
  else if (ktest_mode == KTEST_RECORD) {
    ssize_t num_bytes = writesocket(fd, buf, count);
    if (num_bytes > 0) {
      KTOV_append(&ktov, ktest_object_names[CLIENT_TO_SERVER], num_bytes, buf);
    } else if (num_bytes < 0) {
      perror("ktest_writesocket error");
      exit(1);
    }
    return num_bytes;
  }
  else if (ktest_mode == KTEST_PLAYBACK) {
    perror("ktest_writesocket playback not implemented yet");
    exit(2);
  }
  else {
    perror("ktest_writesocket coding error - should never get here");
    exit(4);
  }
}

ssize_t ktest_readsocket(int fd, void *buf, size_t count)
{
  if (ktest_mode == KTEST_NONE) { // passthrough
    return readsocket(fd, buf, count);
  }
  else if (ktest_mode == KTEST_RECORD) {
    ssize_t num_bytes = readsocket(fd, buf, count);
    if (num_bytes > 0) {
      KTOV_append(&ktov, ktest_object_names[SERVER_TO_CLIENT], num_bytes, buf);
    } else if (num_bytes < 0) {
      perror("ktest_readsocket error");
      exit(1);
    }
    return num_bytes;
  }
  else if (ktest_mode == KTEST_PLAYBACK) {
    perror("ktest_readsocket playback not implemented yet");
    exit(2);
  }
  else {
    perror("ktest_readsocket coding error - should never get here");
    exit(4);
  }
}

int ktest_raw_read_stdin(void *buf,int siz)
{
  if (ktest_mode == KTEST_NONE) {
      return read(fileno(stdin), buf, siz);
  }
  else if (ktest_mode == KTEST_RECORD) {
      int ret;
      ret = read(fileno(stdin), buf, siz);
      if (ret > 0) {
          KTOV_append(&ktov, ktest_object_names[STDIN], ret, buf);
      }
      return ret;
  }
  else if (ktest_mode == KTEST_PLAYBACK) {
      perror("ktest_raw_read_stdin playback not implemented yet");
      exit(2);
  }
  else {
      perror("ktest_raw_read_stdin coding error - should never get here");
      exit(4);
  }
}

time_t ktest_time(time_t *t)
{
  if (ktest_mode == KTEST_NONE) {
    return time(t);
  }
  else if (ktest_mode == KTEST_RECORD) {
    time_t ret = time(t);
    KTOV_append(&ktov, ktest_object_names[TIME], sizeof(ret), &ret);
    return ret;
  }
  else if (ktest_mode == KTEST_PLAYBACK) {
    perror("ktest_time playback not implemented yet");
    exit(2);
  }
  else {
    perror("ktest_time coding error - should never get here");
    exit(4);
  }
}

int ktest_RAND_bytes(unsigned char *buf, int num)
{
  if (ktest_mode == KTEST_NONE) {
    return RAND_bytes(buf, num);
  }
  else if (ktest_mode == KTEST_RECORD) {
    int ret = RAND_bytes(buf, num);
    KTOV_append(&ktov, ktest_object_names[RNG], num, buf);
    return ret;
  }
  else if (ktest_mode == KTEST_PLAYBACK) {
    perror("ktest_RAND_bytes playback not implemented yet");
    exit(2);
  }
  else {
    perror("ktest_RAND_bytes coding error - should never get here");
    exit(4);
  }
}

int ktest_RAND_pseudo_bytes(unsigned char *buf, int num)
{
  if (ktest_mode == KTEST_NONE) {
    return RAND_pseudo_bytes(buf, num);
  }
  else if (ktest_mode == KTEST_RECORD) {
    int ret = RAND_pseudo_bytes(buf, num);
    KTOV_append(&ktov, ktest_object_names[PRNG], num, buf);
    return ret;
  }
  else if (ktest_mode == KTEST_PLAYBACK) {
    perror("ktest_RAND_pseudo_bytes playback not implemented yet");
    exit(2);
  }
  else {
    perror("ktest_RAND_pseudo_bytes coding error - should never get here");
    exit(4);
  }
}

void ktest_start(const char *filename, enum kTestMode mode) {
  KTOV_init(&ktov);
  ktest_mode = mode;

  // set ktest output filename and ktest network-only filename
  if (filename != NULL) {
    char *network_file = NULL;
    const char *suffix = ".net.ktest";
    const char *ext = ".ktest";
    int n_ext = strlen(ext);
    int n_f = strlen(filename);
    int n_suf = strlen(suffix);
    ktest_output_file = filename;
    network_file = (char *)malloc(sizeof(char) * (n_f + n_suf + 1));
    strcpy(network_file, filename);
    if (n_f > n_ext && strcmp(&filename[n_f-n_ext], ext) == 0) {
      strcpy(&network_file[n_f-n_ext], suffix);
    } else {
      strcat(network_file, suffix);
    }
    ktest_network_file = network_file;
  }

  // Load capture from file if playback mode
  if (ktest_mode == KTEST_PLAYBACK) {
    KTest *ktest;
    ktest = kTest_fromFile(filename);
    if (!ktest) {
      fprintf(stderr, "Error reading ktest file: %s\n", filename);
      exit(1);
    }
    ktov.size = ktov.capacity = ktest->numObjects;
    ktov.objects = (KTestObject*)malloc(sizeof(KTestObject) * ktov.size);
    int i;
    for (i = 0; i < ktov.size; i++) {
      KTO_deepcopy(&ktov.objects[i], &ktest->objects[i]);
    }
    kTest_free(ktest);
  }
}

void ktest_finish() {
  KTest ktest;

  if (ktest_mode == KTEST_NONE) {
    return;
  }

  else if (ktest_mode == KTEST_RECORD) {
    memset(&ktest, 0, sizeof(KTest));
    ktest.numObjects = ktov.size;
    ktest.objects = ktov.objects;

    KTOV_print(stdout, &ktov);

    int result = kTest_toFile(&ktest, ktest_output_file);
    if (!result) {
      perror("ktest_finish error");
      exit(1);
    }
    printf("KTest full capture written to %s.\n", ktest_output_file);

    // Filter network events and write as separate file.
    int i, filtered_i;
    for (i = 0, filtered_i = 0; i < ktest.numObjects; i++) {
      if (strcmp(ktest.objects[i].name, "s2c") == 0 ||
	  strcmp(ktest.objects[i].name, "c2s") == 0) {
	KTestObject temp;
	temp = ktest.objects[filtered_i];
	ktest.objects[filtered_i] = ktest.objects[i];
	ktest.objects[i] = temp;
	filtered_i++;
      }
    }
    ktest.numObjects = filtered_i;

    result = kTest_toFile(&ktest, ktest_network_file);
    if (!result) {
      perror("ktest_finish error");
      exit(1);
    }
    printf("KTest network capture written to %s.\n", ktest_network_file);

    KTOV_done(&ktov);
  }

  else if (ktest_mode == KTEST_PLAYBACK) {
    // TODO: nothing except maybe cleanup?
  }
}
