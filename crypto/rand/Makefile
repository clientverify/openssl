#
# OpenSSL/crypto/rand/Makefile
#

DIR=	rand
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST= randtest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=md_rand.c randfile.c rand_lib.c rand_err.c rand_egd.c \
	rand_win.c rand_unix.c rand_os2.c rand_nw.c
LIBOBJ=md_rand.o randfile.o rand_lib.o rand_err.o rand_egd.o \
	rand_win.o rand_unix.o rand_os2.o rand_nw.o

SRC= $(LIBSRC)

EXHEADER= rand.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

include $(TASE_MKFILE)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.ll *.bc *.tase
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

md_rand.o: ../../e_os.h ../../include/openssl/KTest.h
md_rand.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
md_rand.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
md_rand.o: ../../include/openssl/err.h ../../include/openssl/evp.h
md_rand.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
md_rand.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
md_rand.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
md_rand.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
md_rand.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
md_rand.o: ../../include/openssl/symhacks.h md_rand.c rand_lcl.h
md_rand.bc: ../../e_os.h ../../include/openssl/KTest.h
md_rand.bc: ../../include/openssl/asn1.h ../../include/openssl/bio.h
md_rand.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
md_rand.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
md_rand.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
md_rand.bc: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
md_rand.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
md_rand.bc: ../../include/openssl/rand.h ../../include/openssl/safestack.h
md_rand.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
md_rand.bc: ../../include/openssl/symhacks.h md_rand.c rand_lcl.h
rand_egd.o: ../../include/openssl/KTest.h ../../include/openssl/buffer.h
rand_egd.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
rand_egd.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
rand_egd.o: rand_egd.c
rand_egd.bc: ../../include/openssl/KTest.h ../../include/openssl/buffer.h
rand_egd.bc: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
rand_egd.bc: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
rand_egd.bc: rand_egd.c
rand_err.o: ../../include/openssl/KTest.h ../../include/openssl/bio.h
rand_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
rand_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
rand_err.o: ../../include/openssl/opensslconf.h
rand_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
rand_err.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
rand_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
rand_err.o: rand_err.c
rand_err.bc: ../../include/openssl/KTest.h ../../include/openssl/bio.h
rand_err.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
rand_err.bc: ../../include/openssl/err.h ../../include/openssl/lhash.h
rand_err.bc: ../../include/openssl/opensslconf.h
rand_err.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
rand_err.bc: ../../include/openssl/rand.h ../../include/openssl/safestack.h
rand_err.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
rand_err.bc: rand_err.c
rand_lib.o: ../../e_os.h ../../include/openssl/KTest.h
rand_lib.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
rand_lib.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
rand_lib.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
rand_lib.o: ../../include/openssl/opensslconf.h
rand_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
rand_lib.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
rand_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
rand_lib.o: ../cryptlib.h rand_lib.c
rand_lib.bc: ../../e_os.h ../../include/openssl/KTest.h
rand_lib.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
rand_lib.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
rand_lib.bc: ../../include/openssl/err.h ../../include/openssl/lhash.h
rand_lib.bc: ../../include/openssl/opensslconf.h
rand_lib.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
rand_lib.bc: ../../include/openssl/rand.h ../../include/openssl/safestack.h
rand_lib.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
rand_lib.bc: ../cryptlib.h rand_lib.c
rand_nw.o: ../../e_os.h ../../include/openssl/KTest.h
rand_nw.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
rand_nw.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
rand_nw.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
rand_nw.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
rand_nw.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
rand_nw.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
rand_nw.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
rand_nw.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
rand_nw.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
rand_nw.o: ../cryptlib.h rand_lcl.h rand_nw.c
rand_nw.bc: ../../e_os.h ../../include/openssl/KTest.h
rand_nw.bc: ../../include/openssl/asn1.h ../../include/openssl/bio.h
rand_nw.bc: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
rand_nw.bc: ../../include/openssl/e_os2.h ../../include/openssl/err.h
rand_nw.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
rand_nw.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
rand_nw.bc: ../../include/openssl/opensslconf.h
rand_nw.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
rand_nw.bc: ../../include/openssl/rand.h ../../include/openssl/safestack.h
rand_nw.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
rand_nw.bc: ../../include/openssl/symhacks.h ../cryptlib.h rand_lcl.h rand_nw.c
rand_os2.o: ../../e_os.h ../../include/openssl/KTest.h
rand_os2.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
rand_os2.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
rand_os2.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
rand_os2.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
rand_os2.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
rand_os2.o: ../../include/openssl/opensslconf.h
rand_os2.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
rand_os2.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
rand_os2.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
rand_os2.o: ../../include/openssl/symhacks.h ../cryptlib.h rand_lcl.h
rand_os2.o: rand_os2.c
rand_os2.bc: ../../e_os.h ../../include/openssl/KTest.h
rand_os2.bc: ../../include/openssl/asn1.h ../../include/openssl/bio.h
rand_os2.bc: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
rand_os2.bc: ../../include/openssl/e_os2.h ../../include/openssl/err.h
rand_os2.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
rand_os2.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
rand_os2.bc: ../../include/openssl/opensslconf.h
rand_os2.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
rand_os2.bc: ../../include/openssl/rand.h ../../include/openssl/safestack.h
rand_os2.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
rand_os2.bc: ../../include/openssl/symhacks.h ../cryptlib.h rand_lcl.h
rand_os2.bc: rand_os2.c
rand_unix.o: ../../e_os.h ../../include/openssl/KTest.h
rand_unix.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
rand_unix.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
rand_unix.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
rand_unix.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
rand_unix.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
rand_unix.o: ../../include/openssl/opensslconf.h
rand_unix.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
rand_unix.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
rand_unix.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
rand_unix.o: ../../include/openssl/symhacks.h ../cryptlib.h rand_lcl.h
rand_unix.o: rand_unix.c
rand_unix.bc: ../../e_os.h ../../include/openssl/KTest.h
rand_unix.bc: ../../include/openssl/asn1.h ../../include/openssl/bio.h
rand_unix.bc: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
rand_unix.bc: ../../include/openssl/e_os2.h ../../include/openssl/err.h
rand_unix.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
rand_unix.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
rand_unix.bc: ../../include/openssl/opensslconf.h
rand_unix.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
rand_unix.bc: ../../include/openssl/rand.h ../../include/openssl/safestack.h
rand_unix.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
rand_unix.bc: ../../include/openssl/symhacks.h ../cryptlib.h rand_lcl.h
rand_unix.bc: rand_unix.c
rand_win.o: ../../e_os.h ../../include/openssl/KTest.h
rand_win.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
rand_win.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
rand_win.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
rand_win.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
rand_win.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
rand_win.o: ../../include/openssl/opensslconf.h
rand_win.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
rand_win.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
rand_win.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
rand_win.o: ../../include/openssl/symhacks.h ../cryptlib.h rand_lcl.h
rand_win.o: rand_win.c
rand_win.bc: ../../e_os.h ../../include/openssl/KTest.h
rand_win.bc: ../../include/openssl/asn1.h ../../include/openssl/bio.h
rand_win.bc: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
rand_win.bc: ../../include/openssl/e_os2.h ../../include/openssl/err.h
rand_win.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
rand_win.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
rand_win.bc: ../../include/openssl/opensslconf.h
rand_win.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
rand_win.bc: ../../include/openssl/rand.h ../../include/openssl/safestack.h
rand_win.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
rand_win.bc: ../../include/openssl/symhacks.h ../cryptlib.h rand_lcl.h
rand_win.bc: rand_win.c
randfile.o: ../../e_os.h ../../include/openssl/KTest.h
randfile.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
randfile.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
randfile.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
randfile.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
randfile.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
randfile.o: randfile.c
randfile.bc: ../../e_os.h ../../include/openssl/KTest.h
randfile.bc: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
randfile.bc: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
randfile.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
randfile.bc: ../../include/openssl/rand.h ../../include/openssl/safestack.h
randfile.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
randfile.bc: randfile.c
