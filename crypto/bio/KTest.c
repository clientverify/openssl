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

#include <openssl/KTest.h>
// The following macros were used by openssl, so while boring does not need them
// our code relies on them.
#  define readsocket(s,b,n)       read((s),(b),(n))
#  define writesocket(s,b,n)      write((s),(b),(n))

#include <openssl/rand.h>
#undef RAND_bytes
#undef RAND_pseudo_bytes

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>
#include <sys/time.h>
#include <errno.h>
#include <signal.h>

#include <fcntl.h>

#define KTEST_VERSION 4 // Cliver-specific (incompatible with normal klee)
#define KTEST_MAGIC_SIZE 5
#define KTEST_MAGIC "KTEST"

// for compatibility reasons
#define BOUT_MAGIC "BOUT\n"


// override inline assembly version of FD_ZERO from
// /usr/include/x86_64-linux-gnu/bits/select.h
#ifdef FD_ZERO
#undef FD_ZERO
#endif
#define FD_ZERO(p)        memset((char *)(p), 0, sizeof(*(p)))

static int my_pid = -1;

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

static int read_uint64(FILE *f, uint64_t *value_out) {
  unsigned char data[8];
  if (fread(data, 8, 1, f)!=1)
    return 0;
  *value_out = (((((((((((( (data[0]<<8) + data[1])<<8) + data[2])<<8) + data[3])<<8) + data[4])<<8) + data[5])<<8) + data[6])<<8) + data[7];
  return 1;
}

static int write_uint64(FILE *f, uint64_t value) {
  unsigned char data[8];
  data[0] = value>>56;
  data[1] = value>>48;
  data[2] = value>>40;
  data[3] = value>>32;
  data[4] = value>>24;
  data[5] = value>>16;
  data[6] = value>> 8;
  data[7] = value>> 0;
  return fwrite(data, 1, 8, f)==8;
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
    if (res->version >= 4) { // Cliver-specific version 4
      if (!read_uint64(f, (uint64_t*)&o->timestamp.tv_sec))
	goto error;
      if (!read_uint64(f, (uint64_t*)&o->timestamp.tv_usec))
	goto error;
    }
    if (!read_uint32(f, &o->numBytes))
      goto error;
    o->bytes = (unsigned char*) malloc(o->numBytes);
    if (o->numBytes > 0 && fread(o->bytes, o->numBytes, 1, f)!=1)
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
    if (!write_uint64(f, o->timestamp.tv_sec))
      goto error;
    if (!write_uint64(f, o->timestamp.tv_usec))
      goto error;
    if (!write_uint32(f, o->numBytes))
      goto error;
    if (o->numBytes > 0 && fwrite(o->bytes, o->numBytes, 1, f)!=1)
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

static void timeval2str(char *out, int outlen, const struct timeval *tv) {
  time_t nowtime;
  struct tm *nowtm;
  char tmbuf[64];

  nowtime = tv->tv_sec;
  nowtm = localtime(&nowtime);
  strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
  snprintf(out, outlen, "%s.%06ld", tmbuf, tv->tv_usec);
}

// Print hex and ascii side-by-side
static void KTO_print(FILE *f, const KTestObject *o) {
  unsigned int i, j;
  const unsigned int WIDTH = 16;
  char timebuf[64];

  timeval2str(timebuf, sizeof(timebuf), &o->timestamp);
  fprintf(f, "%s | ", timebuf);
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
  dest->timestamp = src->timestamp;
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

void KTOV_append(KTestObjectVector *ov,
			const char *name,
			int num_bytes,
			const void *bytes)
{
  assert(my_pid == getpid());
  int i;
  assert(ov != NULL);
  assert(name != NULL);
  assert(num_bytes == 0 || bytes != NULL);
  i = ov->size;
  KTOV_check_mem(ov); // allocate more memory if necessary
  ov->objects[i].name = strdup(name);
  ov->objects[i].numBytes = num_bytes;
  ov->objects[i].bytes = NULL;
  gettimeofday(&ov->objects[i].timestamp, NULL);
  if (num_bytes > 0) {
      ov->objects[i].bytes =
          (unsigned char*)malloc(sizeof(unsigned char)*num_bytes);
      memcpy(ov->objects[i].bytes, bytes, num_bytes);
  }
  ov->size++;
  // KTO_print(stdout, &ov->objects[i]);
}


static int (*signal_handler)(int);
int ktest_register_signal_handler(int (*a)(int)){
  signal_handler = a;
}


KTestObject* KTOV_next_object(KTestObjectVector *ov, const char *name)
{
  assert(my_pid == getpid());
  if (ov->playback_index >= ov->size) {
    fprintf(stderr, "ERROR: ktest playback %s - no more recorded events", name);
    exit(2);
  }
  KTestObject *o = &ov->objects[ov->playback_index];
  ov->playback_index++;

  if (strcmp(o->name, name) != 0) {
    fprintf(stderr,
	    "ERROR: ktest playback needed '%s', but recording had '%s'\n",
	    name, o->name);
    exit(2);
  }
  return o;
}


static void print_fd_set(int nfds, fd_set *fds) {
  int i;
  for (i = 0; i < nfds; i++) {
      printf(" %d", FD_ISSET(i, fds));
  }
  printf("\n");
}

static enum kTestMode ktest_mode = KTEST_NONE;
//We want this to be the origional
static enum kTestMode arg_ktest_mode = KTEST_NONE;
static const char *arg_ktest_filename = NULL;
static const char *ktest_output_file = "s_client.ktest";
static const char *ktest_network_file = "s_client.net.ktest";

//Called on fork.  No reverting from this.
void ktest_set_mode_none(void){
  arg_ktest_filename = NULL;
  ktest_mode         = KTEST_NONE;
  arg_ktest_mode     = KTEST_NONE;
}

//To be used to figure out the mode outside this file.
enum kTestMode ktest_get_mode(void){
  return ktest_mode;
}

//To turn off recording while executing functions we're modeling as on the
//monitor when in record mode.
void ktest_set_mode_off(void){
  ktest_mode = KTEST_NONE;
}

//To turn back on recording.
void ktest_set_mode_on(void){
  ktest_mode = arg_ktest_mode;
}


#define MAX_FDS 32  //total number of socket file descriptors we will support
static int ktest_nfds = 0; //total number of socket file descriptors in system
static int ktest_sockfds[MAX_FDS]; // descriptor of the sockets we're capturing
                                  //values initialized to -1 in ktest_start.
static int ktest_bind_sockfd = -1;

///////////////////////////////////////////////////////////////////////////////
// Exported functionality
///////////////////////////////////////////////////////////////////////////////

char *ktest_ttyname(int fd){
  if (ktest_mode == KTEST_NONE){
    return ttyname(fd);
  }else if(ktest_mode == KTEST_RECORD) { // passthrough
    char* ret = ttyname(fd);
    KTOV_append(&ktov, ktest_object_names[TTYNAME], strlen(ret)+1, ret);
    return ret;
  } else if (ktest_mode == KTEST_PLAYBACK) {
    //read from ktest here...
    KTestObject *o = KTOV_next_object(&ktov, ktest_object_names[TTYNAME]);
    char *ret = strdup((const char*)o->bytes);
    return ret;
  } else {
    perror("ktest_ttyname error - should never get here");
    exit(4);
  }
}

//Return the same fake pid everytime for debugging.
#define KTEST_FORK_DUMMY_CHILD_PID 37

int ktest_waitpid_or_error(pid_t pid, int *status, int options){
  if(KTEST_DEBUG) printf("openssl's ktest_waitpid 0\n");

  assert(pid == -1);
  assert(options == WNOHANG);
  if (ktest_mode == KTEST_NONE){
    return waitpid(pid, status, options);
  } else if(arg_ktest_mode == KTEST_PLAYBACK) {
    KTestObject *o = KTOV_next_object(&ktov, ktest_object_names[WAIT_PID]);
    char *recorded_select = strdup((const char*)o->bytes);

    char* tmp = strtok(recorded_select, " ");
    assert(strcmp(tmp, "ret_val") == 0);
    int ret_val = atoi(strtok(NULL, " "));

    if(ret_val >= 0){
      tmp = strtok(NULL, " ");
      assert(strcmp(tmp, "status") == 0);
      *status = atoi(strtok(NULL, " "));
      if(KTEST_DEBUG) printf("ktest_waitpid status %d\n", *status);
    } else {
      tmp = strtok(NULL, " ");
      assert(strcmp(tmp, "errno") == 0);
      errno = atoi(strtok(NULL, " "));
      if(KTEST_DEBUG) printf("ktest_waitpid error %d\n", errno);
    }
    free(recorded_select);
    if(ret_val == 0){
      if(KTEST_DEBUG) printf("ktest_waitpid returning 0\n");
      return 0;
    } else if(ret_val <  0){
      return -1;
    } else {
       if(KTEST_DEBUG) printf("ktest_waitpid returning pid %d status %d\n",
           KTEST_FORK_DUMMY_CHILD_PID, *status);
      return KTEST_FORK_DUMMY_CHILD_PID;

    }
  } else if(arg_ktest_mode == KTEST_RECORD) {
    unsigned int size = 100;
    char *record = (char*) calloc(size, sizeof(char));
    unsigned int pos = 0;

    int tmp = waitpid(pid, status, options);

    pos += snprintf(&record[pos], size-pos, "ret_val %d ", tmp);
    if(tmp >= 0){
      pos += snprintf(&record[pos], size-pos, "status %d ", *status);
      if(KTEST_DEBUG) printf("ktest_waitpid appending retval %d status %d\n", tmp, *status);
    } else {
      pos += snprintf(&record[pos], size-pos, "errno %d ", errno);
      if(KTEST_DEBUG) printf("ktest_waitpid appending error %d\n", errno);
    }
    assert(pos < size);
    record[size-1] = '\n';
    KTOV_append(&ktov, ktest_object_names[WAIT_PID], strlen(record)+1, record);
    return tmp;
  } else {
    perror("ktest_signal error - should never get here");
    exit(4);
  }
}

int ktest_shutdown(int socket, int how){
  return shutdown(socket, how);
}

//which is the parent or child--whichever we wish to continue
//recording or playing back from
pid_t ktest_fork(enum KTEST_FORK which){
  enum kTestMode ktest_mode = arg_ktest_mode;
  if (ktest_mode == KTEST_NONE){
    pid_t pid = fork();
    return pid;
  } else if(arg_ktest_mode == KTEST_RECORD){
    pid_t pid = fork();
    assert(pid >= 0);
    //This is the case where we no longer wish to record.
    if((pid != 0 && which == CHILD) || (pid == 0 && which == PARENT)){
      my_pid = -1;
      ktest_set_mode_none();
      return pid;
    }else if ((pid == 0 && which == CHILD) || (pid != 0 && which == PARENT)) {
      //Keep recording.
      my_pid = getpid();
      return pid;
    } else {
      perror("ktest_fork error - should never get here");
      exit(4);
    }
  } else if (arg_ktest_mode == KTEST_PLAYBACK){
    if(which == PARENT){ //we recorded the parent
      //return a positive non-0 value.
      //Note: we assume there is no communication between
      //parent and child in the recorded case.  If there is,
      //then we're in trouble.
      //Must correspond with the pid eventually returned from
      //ktest_waitpid.
      return KTEST_FORK_DUMMY_CHILD_PID;
    } else { //we recorded the child, return current pid.
      //not guarenteed to be the same as when recorded.
      return 0;
    }
  } else {
    perror("ktest_fork error - should never get here");
    exit(4);
  }
}

//We assume that we only get signals we need to handle while in another call
//e.g. ktest_accept/ktest_select.  We then record the signal.  Playback
//signals are handled in the KTOV_next_object() function.
static int signal_indicator = 0;
static int signal_val = 0;
void ktest_record_signal(int sig_num){
  if (ktest_mode == KTEST_NONE)
    return;
  else if (arg_ktest_mode == KTEST_PLAYBACK){
    return;
  } else if(arg_ktest_mode == KTEST_RECORD){
    if(KTEST_DEBUG) printf("ktest_record_signal setting signal_indicator\n");
    signal_indicator = 1;
    signal_val = sig_num;
  } else {
    perror("ktest_signal error - should never get here");
    exit(4);
  }
}



//This overaproximates the filedescriptors in the system.  We don't support
//a close model at the moment--which is probably going to bite us at some point.
void insert_ktest_sockfd(int sockfd){
  int i;
  for(i = 0; i < ktest_nfds; i++){
    if(ktest_sockfds[i] == sockfd){
      if(KTEST_DEBUG) printf("insert_ktest_sockfd attempting to add duplicate sockfd %d\n", sockfd);
      assert(0);
    }
  }
  if(KTEST_DEBUG) printf("insert_ktest_sockfd adding %d to ktest_sockfds ktest_nfds %d\n", sockfd, ktest_nfds);
  assert(ktest_nfds + 1 < MAX_FDS);
  ktest_sockfds[ktest_nfds] = sockfd; // record the socket descriptor of interest
  ktest_nfds++; //incriment the counter recording the number of sockets we're tracking
}

int ktest_verification_socket(int domain, int type, int protocol){
  assert(verification_socket = -1);
  verification_socket = 0; //set it to 0 so that ktest_socket won't blow up
  verification_socket = ktest_socket(domain, type, protocol);
  return verification_socket;
}

int ktest_socket(int domain, int type, int protocol){
  assert(verification_socket != -1); //should be called after ktest_verification_socket
  if (ktest_mode == KTEST_NONE) {
    return socket(domain, type, protocol);
  } else if  (ktest_mode == KTEST_PLAYBACK || ktest_mode == KTEST_RECORD) {
    int sockfd = socket(domain, type, protocol);
    if(KTEST_DEBUG) printf("ktest_sock adding %d to ktest_sockfds\n", sockfd);
    assert(ktest_nfds + 1< MAX_FDS);
    insert_ktest_sockfd(sockfd);
    return sockfd;
  }else
    assert(0);
}

int ktest_dup(int oldfd){

  if (ktest_mode == KTEST_NONE) { // passthrough
    return dup(oldfd);
  } else if(ktest_mode == KTEST_PLAYBACK || ktest_mode == KTEST_RECORD){
    int newfd = dup(oldfd);
    assert(ktest_nfds + 1< MAX_FDS);
    insert_ktest_sockfd(newfd);
    if(KTEST_DEBUG) printf("ktest_dup returning %d\n", newfd);
    return newfd;
  } else {
    assert(0);
  }
}

int ktest_stat(const char *path, struct stat *buf){
  int ret = stat(path, buf);
  assert(ret == 0);
  return ret;
}

int ktest_chown(const char *path, uid_t owner, gid_t group){
  int ret = chown(path, owner, group);
  assert(ret == 0);
  return ret;
}

int ktest_initgroups( const char *user, gid_t group){
  int ret = initgroups(user, group);
  assert(ret == 0);
  return ret;
}

int ktest_setgroups(size_t size, const gid_t *list){
  int ret = setgroups(size, list);
  assert(ret == 0);
  return ret;
}

int ktest_close(int fd){
//  if(KTEST_DEBUG) printf("ktest_close removing %d from ktest_sockfds pid %d\n", fd, getpid());

  if (ktest_mode == KTEST_NONE) { // passthrough
    return close(fd);
  } else if (ktest_mode == KTEST_RECORD) {
    int ret = close(fd);
    assert(ret == 0);

    int i;
    int done = 0;
    for(i = 0; i < ktest_nfds; i++){
      if(ktest_sockfds[i] == fd){
        if(!done){
          ktest_sockfds[i] = -1;
          done = 1;
        } else {
          assert(0);
        }
      }
    }
    return 0;
  } else if (ktest_mode == KTEST_PLAYBACK) {
    int i;
    int done = 0;
    for(i = 0; i < ktest_nfds; i++){
      if(ktest_sockfds[i] == fd){
        if(!done){
          ktest_sockfds[i] = -1;
          done = 1;
        } else {
          assert(0);
        }
      }
    }
    return 0;

  } else {
      perror("ktest_bind error - should never get here");
      exit(4);
  }
}

int ktest_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  if (ktest_mode == KTEST_NONE || ktest_mode == KTEST_RECORD) { // passthrough
    int ret = connect(sockfd, addr, addrlen);
    assert(ret == 0);
    return ret;
  }else{
    return 0; // assume success
  }
}

/* We assume that any given program has only successful call to bind.
 * This is enforced with the ktest_bind_sockfd variable
 */
int ktest_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  printf("nerp ktest_bind(%d...)\n", sockfd);
  if (ktest_mode == KTEST_NONE) { // passthrough
      return bind(sockfd, addr, addrlen);
  }
  else if (ktest_mode == KTEST_RECORD) {
      int ret;
      ret = bind(sockfd, addr, addrlen);
      if(ktest_bind_sockfd != -1){
        assert(ret != 0);
        return ret;
      }
      if(KTEST_DEBUG) printf("ktest_bind binding to %d (openssl model)\n", sockfd);
      ktest_bind_sockfd = sockfd; // record the socket descriptor of interest
      if (KTEST_DEBUG) {
        printf("bind() called on socket for TLS traffic (%d)\n", sockfd);
      }
      return ret;
  }
  else if (ktest_mode == KTEST_PLAYBACK) {
      if( ktest_bind_sockfd != -1) //if ktest_bind_sockfd is already assigned, return error
        return -1;
      if(KTEST_DEBUG) printf("ktest_bind binding to %d (openssl model)\n", sockfd);
      ktest_bind_sockfd = sockfd; // record the socket descriptor of interest
      if (KTEST_DEBUG) {
        printf("bind() called on socket for TLS traffic (%d)\n", sockfd);
      }
      return 0; // assume success
  }
  else {
      perror("ktest_bind error - should never get here");
      exit(4);
  }
}

int ktest_listen(int sockfd, int backlog){
    int ret = listen(sockfd, backlog);
    assert(ret == 0);
    return ret;
}

int ktest_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen){
  assert(ktest_nfds + 1 < MAX_FDS);
  if (ktest_mode == KTEST_NONE){
    return accept(sockfd, addr, addrlen);
  }else if(ktest_mode == KTEST_RECORD) { // passthrough
      int accept_sock = accept(sockfd, addr, addrlen);
      if(KTEST_DEBUG) printf("ktest_accept adding %d to ktest_sockfds\n", accept_sock);
      insert_ktest_sockfd(accept_sock);
      return accept_sock;
  } else if (ktest_mode == KTEST_PLAYBACK) {
    int accept_sock = socket(AF_INET, SOCK_STREAM, 0);
    assert(accept_sock >= 0);
    if(KTEST_DEBUG) printf("ktest_accept adding %d to ktest_sockfds\n", accept_sock);
    insert_ktest_sockfd(accept_sock);
    if (KTEST_DEBUG) {
      printf("accept() called on socket for TLS traffic (%d)\n", accept_sock);
    }
    return accept_sock;
  } else{
    perror("ktest_bind error - should never get here");
    exit(4);
  }
}


/**
 * Note that ktest_select playback is slightly brittle in that it
 * assumes that the only socket descriptors we care about are
 * stdin(0), stdout(1), stderr(2), and ktest_sockfd (this is allowed
 * to differ between recording and playback).  If this assumption is
 * not true, then playback could break.
 */
int ktest_select(int nfds, fd_set *readfds, fd_set *writefds,
		  fd_set *exceptfds, struct timeval *timeout)
{
  if(KTEST_DEBUG && (ktest_mode == KTEST_RECORD || ktest_mode == KTEST_PLAYBACK)){
    printf("ktest_sockfds: ");
    int i;
    for(i = 0; i < ktest_nfds; i ++)
      printf("%d, ", ktest_sockfds[i]);
    printf("\n");
  }
  assert(readfds != NULL);
  assert(exceptfds == NULL);
  assert(ktest_nfds <= MAX_FDS);
  if (ktest_mode == KTEST_NONE) { // passthrough
      return select(nfds, readfds, writefds, exceptfds, timeout);
  } else if (ktest_mode == KTEST_RECORD) {
      // select input/output is stored as ASCII text in the format:
      // "sockfd 3 nfds 4 inR 1001 inW 0000 ret 1 outR 1000 outW 0000"
      //    sockfd - just for reference, not part of the select call
      //    nfds - number of active fds in fdset, usually sockfd+1
      //    inR - readfds input value
      //    inW - writefds input value
      //    ret - return value from select()
      //    outR - readfds output value
      //    outW - writefds output value

      int ret, i, active_fd_count = 0;
      unsigned int size = 4*nfds + 40 /*text*/ + 3*4 /*3 fd's*/ + 1 /*null*/ + 500 /*added to get signal stuff to work*/;
      char *record = (char *)calloc(size, sizeof(char));
      unsigned int pos = 0;


      if (KTEST_DEBUG) {
        printf("\n");
        printf("IN readfds  = ");
        print_fd_set(nfds, readfds);
        if(writefds != NULL) printf("IN writefds = ");
        if(writefds != NULL) print_fd_set(nfds, writefds);
        fflush(stdout);
      }



      ret = select(nfds, readfds, writefds, exceptfds, timeout);

      pos += snprintf(&record[pos], size-pos,
		      "signal_indicator %d signal_val %d ", signal_indicator, signal_val);
      signal_indicator = 0;
      signal_val = 0;

      pos += snprintf(&record[pos], size-pos,
		      "ktest_nfds %d nfds %d ", ktest_nfds, nfds);

      if (KTEST_DEBUG) {
	    printf("Select returned %d (ktest_nfds = %d)\n", ret, ktest_nfds);
	    printf("OUT readfds   = ");
    	print_fd_set(nfds, readfds);
    	if(writefds != NULL) printf("OUT writefds  = ");
        if(writefds != NULL) print_fd_set(nfds, writefds);
        printf("\n");
        fflush(stdout);
      }

      //record the read fds set on return
      pos += snprintf(&record[pos], size-pos, " outR ");
      for (i = 0; i < 3; i++) { //record the 0, 1, 2 fds set on return
        if(FD_ISSET(i, readfds)) active_fd_count++;
	    pos += snprintf(&record[pos], size-pos, "%d", FD_ISSET(i, readfds));
      }

      for (i = 0; i < ktest_nfds; i++) {
        if(FD_ISSET(ktest_sockfds[i], readfds)) active_fd_count++;
	    pos += snprintf(&record[pos], size-pos, "%d", FD_ISSET(ktest_sockfds[i], readfds));
      }

      if(writefds != NULL) {
        pos += snprintf(&record[pos], size-pos, " outW ");
        for (i = 0; i < 3; i++) { //record the 0, 1, 2 fds set on return
             if(FD_ISSET(i, writefds)) active_fd_count++;
	         pos += snprintf(&record[pos], size-pos, "%d", FD_ISSET(i, writefds));
        }
        for (i = 0; i < ktest_nfds; i++) {
            if(FD_ISSET(ktest_sockfds[i], writefds)) active_fd_count++;
	        pos += snprintf(&record[pos], size-pos, "%d", FD_ISSET(ktest_sockfds[i], writefds));
        }
      }

      pos += snprintf(&record[pos], size-pos, " active_fd_count %d ", ret);
      if(KTEST_DEBUG && ret != active_fd_count) printf("select ret = %d active_fd_count = %d\n", ret, active_fd_count);
      assert(pos < size);
      record[size-1] = '\0'; // just in case we ran out of room.
      KTOV_append(&ktov, ktest_object_names[SELECT], strlen(record)+1, record);
      free(record);
      return ret;
  }
  else if (ktest_mode == KTEST_PLAYBACK) {
    KTestObject *o = KTOV_next_object(&ktov, ktest_object_names[SELECT]);

    // Make sure we have included the socket for TLS traffic
    //TODO: figure out how to represent this?: assert(ktest_sockfd < nfds);
    // Parse the recorded select input/output.
    char *recorded_select = strdup((const char*)o->bytes);
    char *item, *tmp;
    int ret = 0, recorded_ktest_nfds = 0, recorded_nfds = 0, active_fd_count = 0, i = 0;

    FD_ZERO(readfds); // output of select
    if(writefds != NULL){ FD_ZERO(writefds);}// output of select

    tmp = strtok(recorded_select, " ");

    //figure out if we have to handle a signal.
    assert(strcmp(tmp, "signal_indicator") == 0);
    int my_signal_indicator = atoi(strtok(NULL, " ")); // socket for TLS traffic

    tmp = strtok(NULL, " ");
    assert(strcmp(tmp, "signal_val") == 0);
    int my_signal_val = atoi(strtok(NULL, " "));

    if(my_signal_indicator){
      if(KTEST_DEBUG) printf("select signal %d active_fd_count = %d\n", ret, active_fd_count);
      signal_handler(my_signal_val);
    }

    tmp = strtok(NULL, " ");
    assert(strcmp(tmp, "ktest_nfds") == 0);
    recorded_ktest_nfds = atoi(strtok(NULL, " ")); // socket for TLS traffic
    assert(ktest_nfds == recorded_ktest_nfds);

    tmp = strtok(NULL, " ");
    assert(strcmp(tmp, "nfds") == 0);
    recorded_nfds = atoi(strtok(NULL, " "));


    // Copy recorded data to the final output fd_sets.
    FD_ZERO(readfds);
    if(writefds != NULL){ FD_ZERO(writefds);}

    tmp = strtok(NULL, " ");
    assert(strcmp(tmp, "outR") == 0);
    item = strtok(NULL, " ");
    assert(strlen(item) == (recorded_ktest_nfds + 3));

    //set out_readfds
    for (i = 0; i < 3; i++) { //0, 1, 2 set out_readfds
      if (item[i] == '1') {
	    FD_SET(i, readfds);
        active_fd_count++;
      }
    }
    for (i = 0; i < recorded_ktest_nfds; i++) {
      if (item[i + 3] == '1') {  //ktest_sockfds set out_readfds
	    FD_SET(ktest_sockfds[i], readfds);
        active_fd_count++;
      }
    }


    if(writefds != NULL) {
        tmp = strtok(NULL, " ");
        assert(strcmp(tmp, "outW") == 0);
        item = strtok(NULL, " ");
        assert(strlen(item) == (recorded_ktest_nfds + 3));
        //set out_writefds
        for (i = 0; i < 3; i++) { //0, 1, 2 set out_writefds
            if (item[i] == '1') {
	            FD_SET(i, writefds);
                active_fd_count++;
            }
        }
        for (i = 0; i < recorded_ktest_nfds; i++) {
            if (item[i +3] == '1') { //ktest_sockfds set out_writefds
	            FD_SET(ktest_sockfds[i], writefds);
                active_fd_count++;
            }
        }
    }


    tmp = strtok(NULL, " ");
    assert(strcmp(tmp, "active_fd_count") == 0);
    ret = atoi(strtok(NULL, " "));

    if (KTEST_DEBUG) {
      printf("SELECT playback (recorded_nfds = %d, actual_nfds = %d):\n",
	     (recorded_ktest_nfds + 3), nfds);
      printf("  outR:");
      print_fd_set((recorded_ktest_nfds+3), readfds);
      if(writefds != NULL) printf("  outW:");
      if(writefds != NULL) print_fd_set((recorded_ktest_nfds+3), writefds);
      printf("  ret = %d active_fd_count = %d\n", ret, active_fd_count);
    }

    if(ret != active_fd_count) printf("select ret = %d active_fd_count = %d\n", ret, active_fd_count);
    assert(active_fd_count == ret); // Did we miss anything?
    free(recorded_select);

    return ret;
  }
  else {
      perror("ktest_select error - should never get here");
      exit(4);
  }
}


int bssl_stdin_ktest_select(int nfds, fd_set *readfds, fd_set *writefds,
		  fd_set *exceptfds, struct timeval *timeout)
{
  assert(readfds != NULL);
  assert(exceptfds == NULL);
  assert(writefds == NULL);
  return ktest_select(nfds, readfds, writefds, exceptfds, timeout);
}


//Added for sshd support.  The monitor creates pseudoterminal and passes it
//to the second (authenticated worker).
ssize_t ktest_recvmsg_fd(int sockfd, struct msghdr *msg, int flags)
{
  assert(flags == 0);
  int expected_return = 1; //openssh expects this to be the return value
  if (ktest_mode == KTEST_NONE) { // passthrough
    return recvmsg(sockfd, msg, flags);
  }
  else if (ktest_mode == KTEST_RECORD) {
    ssize_t num_bytes = recvmsg(sockfd, msg, flags);
    if (num_bytes == expected_return) {
      struct cmsghdr *cmsg;
      cmsg = CMSG_FIRSTHDR(msg);
      int fd = (*(int *)CMSG_DATA(cmsg));
      assert(fd >=0);
      insert_ktest_sockfd(fd); //add the socket being returned to the list
      //we're tracking
    } else if (num_bytes < 0) {
      fprintf(stderr, "ktest_readsocket error returning %d bytes\n", num_bytes);
      exit(1);
    } else {
      fprintf(stderr, "ERROR: expected %d returned from recvmsg got %d\n",
          expected_return, num_bytes);
      exit(1);
    }
    return num_bytes;
  }
  else if (ktest_mode == KTEST_PLAYBACK) {
    //sockfd is really a dummy fd, so we don't care if it is created with
    //open or socket, since we have recorded all interactions it will engage
    //in in playback.  This assumption will not hold if ktest_mode is changed.
    int sockfd = ktest_socket(AF_INET, SOCK_STREAM, 0);
    assert(sockfd >= 0); //Ensure fd creation was successful.

    //The following is highly specific to what is checked in mm_recieve_fd in
    //ssh codebase.
    struct cmsghdr *cmsg;
    cmsg = CMSG_FIRSTHDR(msg);
    cmsg->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(cmsg), &sockfd, sizeof(sockfd));

    return expected_return;
  }
  else {
    perror("ktest_readsocket coding error - should never get here");
    exit(4);
  }
}


ssize_t ktest_writesocket(int fd, const void *buf, size_t count)
{
  if (ktest_mode == KTEST_NONE) { // passthrough
    return writesocket(fd, buf, count);
  }
  else if (ktest_mode == KTEST_RECORD) {
    ssize_t num_bytes;
    if(verification_socket == fd){
      num_bytes = count;
      KTOV_append(&ktov, ktest_object_names[VERIFY_SENDSOCKET], num_bytes, buf);
    }else{
      num_bytes = writesocket(fd, buf, count);
      if (num_bytes > 0) {
        KTOV_append(&ktov, ktest_object_names[WRITESOCKET], num_bytes, buf);
      } else if (num_bytes < 0) {
        perror("ktest_writesocket error");
        exit(1);
      }
    }
    if (KTEST_DEBUG) {
      unsigned int i;
      printf("writesocket redording [%d]", num_bytes);
      for (i = 0; i < num_bytes; i++) {
	printf(" %2.2x", ((unsigned char*)buf)[i]);
      }
      printf("\n");
    }
    return num_bytes;
  }
  else if (ktest_mode == KTEST_PLAYBACK) {
    KTestObject *o;
    if(verification_socket == fd)
      o = KTOV_next_object(&ktov,
				      ktest_object_names[VERIFY_SENDSOCKET]);
    else
      o = KTOV_next_object(&ktov,
				      ktest_object_names[WRITESOCKET]);
 
    if (o->numBytes > count) {
      fprintf(stderr,
	      "ktest_writesocket playback error: %zu bytes of input, "
	      "%d bytes recorded\n", count, o->numBytes);
      int i = 0;
      printf(" Recorded Sending:   \n");
      KTO_print(stdout, o);
      printf("\n");
      o->numBytes = count;
      o->bytes = buf;
      fprintf(stderr, " Attempting to send: \n");
      KTO_print(stdout, o);
      printf("\n");
      exit(2);
    }

    if (KTEST_DEBUG) {
      unsigned int i;
      printf("writesocket playback [%d]", o->numBytes);
      for (i = 0; i < o->numBytes; i++) {
        printf(" %2.2x", ((unsigned char*)o->bytes)[i]);
      }
      printf("\n");
    }

    // Since this is a write, compare for equality.
    if (o->numBytes > 0 && memcmp(buf, o->bytes, o->numBytes) != 0) {
      fprintf(stderr, "WARNING: ktest_writesocket playback - data mismatch\n");
      //trying to send:
      unsigned int i;
      printf("writesocket trying to write [%d]", count);
      for (i = 0; i < count; i++) {
        printf(" %2.2x", ((unsigned char*)buf)[i]);
      }
      printf("\n");
      //and fail
      assert(0);
    }
    return o->numBytes;
  }
  else {
    perror("ktest_writesocket coding error - should never get here");
    exit(4);
  }
}


ssize_t ktest_readsocket_or_error(int fd, void *buf, size_t count)
{
  char* error_str = "is_error ";
  char* not_error_str = "not_error ";
  if (ktest_mode == KTEST_NONE) { // passthrough
    return readsocket(fd, buf, count);
  }
  else if (ktest_mode == KTEST_RECORD) {
    ssize_t num_bytes = readsocket(fd, buf, count);
    int my_errno = errno;
    if (num_bytes >= 0) {
      int size = strlen(not_error_str) + num_bytes;
      int pos = 0;
      char* record = malloc(size);
      pos += snprintf(&record[pos], size-pos, not_error_str);
      assert(pos == strlen(not_error_str));
      memcpy(record+pos, buf, num_bytes);
      KTOV_append(&ktov, ktest_object_names[READSOCKET_OR_ERROR], size, record);
    } else if (num_bytes < 0) {
      int size = strlen(error_str) + sizeof(my_errno);
      int pos = 0;
      char* record = malloc(size);
      pos += snprintf(&record[pos], size-pos, "%s%d", error_str, my_errno);
      assert(my_errno != EINTR && my_errno != EAGAIN);
      KTOV_append(&ktov, ktest_object_names[READSOCKET_OR_ERROR], size, record);
      fprintf(stderr, "ktest_readsocket error returning %d bytes\n", num_bytes);
      assert(my_errno != EINTR && my_errno != EAGAIN);
    }
    if (KTEST_DEBUG && num_bytes>=0) {
      unsigned int i;
      printf("readsocket recording [%d]", num_bytes);
      for (i = 0; i < num_bytes; i++) {
	printf(" %2.2x", ((unsigned char*)buf)[i]);
      }
      printf("\n");
    }
    errno = my_errno;
    return num_bytes;
  }
  else if (ktest_mode == KTEST_PLAYBACK) {
    KTestObject *o = KTOV_next_object(&ktov,
				      ktest_object_names[READSOCKET_OR_ERROR]);
    if(strncmp(o->bytes, error_str, strlen(error_str)) == 0){
      errno = (int)o->bytes[strlen(error_str)];
      fprintf(stderr, "ktest_readsocket error returning bytes: %d errno: %d\n", -1, errno);
      return -1;
    }
    assert(strncmp(o->bytes, not_error_str, strlen(not_error_str)) == 0);
    int   read_len = o->numBytes - strlen(not_error_str);
    char* read_buf = o->bytes    + strlen(not_error_str);
    if (read_len > count) {
      fprintf(stderr,
	      "ktest_readsocket playback error: %zu byte destination buffer, "
	      "%d bytes recorded", count, read_len);
      exit(2);
    }
    // Read recorded data into buffer
    memcpy(buf, read_buf, read_len);
    if (KTEST_DEBUG) {
      unsigned int i;
      printf("readsocket playback [read_len %d size %d]", read_len, o->numBytes);
      for (i = 0; i < read_len; i++) {
	      printf(" %2.2x", ((unsigned char*)buf)[i]);
      }
      printf("\n");
    }
    return read_len;
  }
  else {
    perror("ktest_readsocket coding error - should never get here");
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
    assert(num_bytes >= 0);

    if(verification_socket == fd)
      KTOV_append(&ktov, ktest_object_names[VERIFY_READSOCKET], num_bytes, buf);
    else
      KTOV_append(&ktov, ktest_object_names[READSOCKET], num_bytes, buf);
    if (KTEST_DEBUG) {
      unsigned int i;
      printf("readsocket redording [%d]", num_bytes);
      for (i = 0; i < num_bytes; i++) {
	printf(" %2.2x", ((unsigned char*)buf)[i]);
      }
      printf("\n");
    }
    return num_bytes;
  }
  else if (ktest_mode == KTEST_PLAYBACK) {
    KTestObject *o; 
    if(verification_socket == fd)
      o = KTOV_next_object(&ktov,
			  	      ktest_object_names[VERIFY_READSOCKET]);
    else
      o = KTOV_next_object(&ktov,
			  	      ktest_object_names[READSOCKET]);
 
    if (o->numBytes > count) {
      fprintf(stderr,
	      "ktest_readsocket playback error: %zu byte destination buffer, "
	      "%d bytes recorded", count, o->numBytes);
      exit(2);
    }
    // Read recorded data into buffer
    memcpy(buf, o->bytes, o->numBytes);
    if (KTEST_DEBUG) {
      unsigned int i;
      printf("readsocket playback [%d]", o->numBytes);
      for (i = 0; i < o->numBytes; i++) {
	printf(" %2.2x", ((unsigned char*)buf)[i]);
      }
      printf("\n");
    }
    return o->numBytes;
  }
  else {
    perror("ktest_readsocket coding error - should never get here");
    exit(4);
  }
}

int ktest_record_readbuf(int fd, char* buf, int num_bytes){
  assert(fd == verification_socket);
  assert(ktest_mode == KTEST_RECORD);
  assert(num_bytes >= 0);

  if(verification_socket == fd)
    KTOV_append(&ktov, ktest_object_names[VERIFY_READSOCKET], num_bytes, buf);
  if (KTEST_DEBUG) {
    unsigned int i;
    printf("readsocket redording [%d]", num_bytes);
    for (i = 0; i < num_bytes; i++) {
      printf(" %2.2x", ((unsigned char*)buf)[i]);
    }
    printf("\n");
  }
  return num_bytes;
}

int ktest_raw_read_stdin(void *buf,int siz)
{
  if (ktest_mode == KTEST_NONE) {
      return read(fileno(stdin), buf, siz);
  }
  else if (ktest_mode == KTEST_RECORD) {
      int ret;
      ret = read(fileno(stdin), buf, siz); // might return 0 (EOF)
      KTOV_append(&ktov, ktest_object_names[STDIN], ret, buf);
      return ret;
  }
  else if (ktest_mode == KTEST_PLAYBACK) {
    KTestObject *o = KTOV_next_object(&ktov, ktest_object_names[STDIN]);
    if (o->numBytes > (unsigned int) siz) {
      fprintf(stderr,
	      "ktest_raw_read_stdin playback error: "
	      "%d byte destination buffer, %d bytes recorded",
	      siz, o->numBytes);
      exit(2);
    }
    // Read recorded data into buffer
    memcpy(buf, o->bytes, o->numBytes);
    if (KTEST_DEBUG) {
      unsigned int i;
      printf("raw_read_stdin playback [%du]", o->numBytes);
      for (i = 0; i < o->numBytes; i++) {
	printf(" %2.2x", ((unsigned char*)buf)[i]);
      }
      printf("\n");
    }

    return o->numBytes;
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

int ktest_RAND_status()
{
  if (ktest_mode == KTEST_NONE) {
    return RAND_status();
  }
  else if (ktest_mode == KTEST_RECORD) {
    int ret = RAND_status();
    assert(ret == 1);
    return ret;
  }
  else if (ktest_mode == KTEST_PLAYBACK) {
    return 1; // success
  }
  else {
    perror("ktest_RAND_status coding error - should never get here");
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
    if (KTEST_DEBUG) {
      printf("RAND_bytes returned %d\n", ret);
    }
    KTOV_append(&ktov, ktest_object_names[RNG], num, buf);
    return ret;
  }
  else if (ktest_mode == KTEST_PLAYBACK) {
    KTestObject *o = KTOV_next_object(&ktov, ktest_object_names[RNG]);
    if (o->numBytes != (unsigned int) num) {
      fprintf(stderr,
	      "ktest_RAND_bytes playback error: %d bytes requested, "
	      "%d bytes recorded", num, o->numBytes);
      exit(2);
    }
    memcpy(buf, o->bytes, num);
    if (KTEST_DEBUG) {
      int i;
      printf("RAND_bytes playback [%d]", num);
      for (i = 0; i < num; i++) {
	printf(" %2.2x", buf[i]);
      }
      printf("\n");
    }
    return 1; // success
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
    if (KTEST_DEBUG) {
      printf("RAND_pseudo_bytes returned %d\n", ret);
    }
    return ret;
  }
  else if (ktest_mode == KTEST_PLAYBACK) {
    KTestObject *o = KTOV_next_object(&ktov, ktest_object_names[PRNG]);
    if (o->numBytes != (unsigned int) num) {
      fprintf(stderr,
	      "ktest_RAND_pseudo_bytes playback error: %d bytes requested, "
	      "%d bytes recorded", num, o->numBytes);
      exit(2);
    }
    memcpy(buf, o->bytes, num);
    if (KTEST_DEBUG) {
      int i;
      printf("RAND_pseudo_bytes playback [%d]", num);
      for (i = 0; i < num; i++) {
	printf(" %2.2x", buf[i]);
      }
      printf("\n");
    }
    return 1; // 1 = success. WARNING: might return 0 if not crypto-strong
  }
  else {
    perror("ktest_RAND_pseudo_bytes coding error - should never get here");
    exit(4);
  }
}

void ktest_master_secret(unsigned char *ms, int len) {
  if (ktest_mode == KTEST_NONE) {
    return;
  }
  else if (ktest_mode == KTEST_RECORD) {
    KTOV_append(&ktov, ktest_object_names[MASTER_SECRET], len, ms);
    if (KTEST_DEBUG) {
      int i;
      printf("master_secret recorded [%d]", len);
      for (i = 0; i < len; i++) {
	printf(" %2.2x", ms[i]);
      }
      printf("\n");
    }
    return;
  }
  else if (ktest_mode == KTEST_PLAYBACK) {
    KTestObject *o = KTOV_next_object(&ktov, ktest_object_names[MASTER_SECRET]);
    if (o->numBytes != (unsigned int) len) {
      fprintf(stderr,
	      "ktest_master_secret playback error: %d bytes requested, "
	      "%d bytes recorded", len, o->numBytes);
      exit(2);
    }
    if (o->numBytes > 0 && memcmp(ms, o->bytes, len) != 0) {
      fprintf(stderr, "WARNING: ktest_master_secret playback data mismatch\n");
    }
    memcpy(ms, o->bytes, len);
    if (KTEST_DEBUG) {
      int i;
      printf("master_secret playback [%d]", len);
      for (i = 0; i < len; i++) {
	printf(" %2.2x", ms[i]);
      }
      printf("\n");
    }
    return;
  }
  else {
    perror("ktest_master_secret coding error - should never get here");
    exit(4);
  }
}

void ktest_start(const char *filename, enum kTestMode mode){
  arg_ktest_filename = filename;
  arg_ktest_mode = mode;
  my_pid = getpid();
  //Initialize socketfds with -1
  int i;
  for(i = 0; i < MAX_FDS; i++){
    ktest_sockfds[i] = -1;
  }
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
    assert(my_pid == getpid());
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

    // Sort network events to the front and write as separate file.
    int i, filtered_i;
    for (i = 0, filtered_i = 0; (unsigned int) i < ktest.numObjects; i++) {
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
    assert(my_pid == getpid());
    // TODO: nothing except maybe cleanup?
  }
}

int ktest_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints, struct addrinfo **res){
     if(ktest_mode == KTEST_PLAYBACK){
        int ret = getaddrinfo("localhost", service, hints, res);
        (*res)->ai_next = NULL;
        return ret;
     }else{
        int ret = getaddrinfo(node, service, hints, res);
        (*res)->ai_next = NULL;
        return ret;
     }
}

void ktest_freeaddrinfo(struct addrinfo *res){
    freeaddrinfo(res);
}

int ktest_getpeername(int sockfd, struct sockaddr *addr, socklen_t
       *addrlen){
  if(ktest_mode == KTEST_NONE){
    return getpeername(sockfd, addr, addrlen);
  }else if(ktest_mode == KTEST_RECORD){
    int ret = getpeername(sockfd, addr, addrlen);
    assert(ret == 0);
    KTOV_append(&ktov, ktest_object_names[KTEST_GET_PEER_NAME], *addrlen, addr);

    return ret;
  }else if(ktest_mode == KTEST_PLAYBACK){
    KTestObject *o = KTOV_next_object(&ktov,
                       ktest_object_names[KTEST_GET_PEER_NAME]);
    if (o->numBytes > *addrlen) {
      fprintf(stderr,
        "ktest_getpeername playback error: %zu bytes of input, "
        "%d bytes recorded", *addrlen, o->numBytes);
      exit(2);
    }

    *addrlen = o->numBytes;
    memcpy(addr, o->bytes, o->numBytes);

    if (KTEST_DEBUG) {
      unsigned int i;
      printf("getpeername playback [%d]", o->numBytes);
      for (i = 0; i < o->numBytes; i++) {
        printf(" %2.2x", ((unsigned char*)addr)[i]);
      }
      printf("\n");
    }

    return 0; //assume success
  }else{
    perror("ktest_getpeername error - should never get here");
    exit(4);
  }

}

//Always takes 3 arguements, workaround for klee socket abstraction.  In klee
//klee model will be executed instead.
int ktest_fcntl(int socket, int flags, int not_sure){
    return fcntl(socket, flags, not_sure);
}

int bssl_EC_POINT_mul( const EC_GROUP *group, EC_POINT *r,
                                const BIGNUM *n, const EC_POINT *q,
                                const BIGNUM *m, BN_CTX *ctx){
    return EC_POINT_mul( group, r, n, q, m, ctx);
}


