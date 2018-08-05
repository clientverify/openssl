#
# crypto/aes/Makefile
#

DIR=	aes
TOP=	../..
CC=	cc
CPP=	$(CC) -E
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

AES_ENC=aes_core.o aes_cbc.o

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
#TEST=aestest.c
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=aes_core.c aes_misc.c aes_ecb.c aes_cbc.c aes_cfb.c aes_ofb.c \
       aes_ctr.c aes_ige.c aes_wrap.c
LIBOBJ=aes_misc.o aes_ecb.o aes_cfb.o aes_ofb.o aes_ctr.o aes_ige.o aes_wrap.o \
       $(AES_ENC)

SRC= $(LIBSRC)

EXHEADER= aes.h
HEADER= aes_locl.h $(EXHEADER)

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
	rm -f *.s *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

aes_cbc.o: ../../include/openssl/aes.h ../../include/openssl/modes.h
aes_cbc.o: ../../include/openssl/opensslconf.h aes_cbc.c
aes_cbc.bc: ../../include/openssl/aes.h ../../include/openssl/modes.h
aes_cbc.bc: ../../include/openssl/opensslconf.h aes_cbc.c
aes_cfb.o: ../../include/openssl/aes.h ../../include/openssl/modes.h
aes_cfb.o: ../../include/openssl/opensslconf.h aes_cfb.c
aes_cfb.bc: ../../include/openssl/aes.h ../../include/openssl/modes.h
aes_cfb.bc: ../../include/openssl/opensslconf.h aes_cfb.c
aes_core.o: ../../include/openssl/aes.h ../../include/openssl/e_os2.h
aes_core.o: ../../include/openssl/opensslconf.h aes_core.c aes_locl.h
aes_core.bc: ../../include/openssl/aes.h ../../include/openssl/e_os2.h
aes_core.bc: ../../include/openssl/opensslconf.h aes_core.c aes_locl.h
aes_ctr.o: ../../include/openssl/aes.h ../../include/openssl/modes.h
aes_ctr.o: ../../include/openssl/opensslconf.h aes_ctr.c
aes_ctr.bc: ../../include/openssl/aes.h ../../include/openssl/modes.h
aes_ctr.bc: ../../include/openssl/opensslconf.h aes_ctr.c
aes_ecb.o: ../../include/openssl/aes.h ../../include/openssl/e_os2.h
aes_ecb.o: ../../include/openssl/opensslconf.h aes_ecb.c aes_locl.h
aes_ecb.bc: ../../include/openssl/aes.h ../../include/openssl/e_os2.h
aes_ecb.bc: ../../include/openssl/opensslconf.h aes_ecb.c aes_locl.h
aes_ige.o: ../../e_os.h ../../include/openssl/aes.h ../../include/openssl/bio.h
aes_ige.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
aes_ige.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
aes_ige.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
aes_ige.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
aes_ige.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
aes_ige.o: ../../include/openssl/symhacks.h ../cryptlib.h aes_ige.c aes_locl.h
aes_ige.bc: ../../e_os.h ../../include/openssl/aes.h
aes_ige.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
aes_ige.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
aes_ige.bc: ../../include/openssl/err.h ../../include/openssl/lhash.h
aes_ige.bc: ../../include/openssl/opensslconf.h
aes_ige.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
aes_ige.bc: ../../include/openssl/safestack.h ../../include/openssl/stack.h
aes_ige.bc: ../../include/openssl/symhacks.h ../cryptlib.h aes_ige.c aes_locl.h
aes_misc.o: ../../include/openssl/aes.h ../../include/openssl/crypto.h
aes_misc.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
aes_misc.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
aes_misc.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
aes_misc.o: ../../include/openssl/symhacks.h aes_locl.h aes_misc.c
aes_misc.bc: ../../include/openssl/aes.h ../../include/openssl/crypto.h
aes_misc.bc: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
aes_misc.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
aes_misc.bc: ../../include/openssl/safestack.h ../../include/openssl/stack.h
aes_misc.bc: ../../include/openssl/symhacks.h aes_locl.h aes_misc.c
aes_ofb.o: ../../include/openssl/aes.h ../../include/openssl/modes.h
aes_ofb.o: ../../include/openssl/opensslconf.h aes_ofb.c
aes_ofb.bc: ../../include/openssl/aes.h ../../include/openssl/modes.h
aes_ofb.bc: ../../include/openssl/opensslconf.h aes_ofb.c
aes_wrap.o: ../../e_os.h ../../include/openssl/aes.h
aes_wrap.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
aes_wrap.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
aes_wrap.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
aes_wrap.o: ../../include/openssl/opensslconf.h
aes_wrap.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
aes_wrap.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
aes_wrap.o: ../../include/openssl/symhacks.h ../cryptlib.h aes_wrap.c
aes_wrap.bc: ../../e_os.h ../../include/openssl/aes.h
aes_wrap.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
aes_wrap.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
aes_wrap.bc: ../../include/openssl/err.h ../../include/openssl/lhash.h
aes_wrap.bc: ../../include/openssl/opensslconf.h
aes_wrap.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
aes_wrap.bc: ../../include/openssl/safestack.h ../../include/openssl/stack.h
aes_wrap.bc: ../../include/openssl/symhacks.h ../cryptlib.h aes_wrap.c
