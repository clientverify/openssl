#
# OpenSSL/crypto/cms/Makefile
#

DIR=	cms
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= cms_lib.c cms_asn1.c cms_att.c cms_io.c cms_smime.c cms_err.c \
	cms_sd.c cms_dd.c cms_cd.c cms_env.c cms_enc.c cms_ess.c \
	cms_pwri.c
LIBOBJ= cms_lib.o cms_asn1.o cms_att.o cms_io.o cms_smime.o cms_err.o \
	cms_sd.o cms_dd.o cms_cd.o cms_env.o cms_enc.o cms_ess.o \
	cms_pwri.o

SRC= $(LIBSRC)

EXHEADER=  cms.h
HEADER=	cms_lcl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

include $(TASE_MKFILE)

test:

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

cms_asn1.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_asn1.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cms_asn1.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_asn1.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_asn1.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_asn1.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cms_asn1.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_asn1.o: ../../include/openssl/opensslconf.h
cms_asn1.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_asn1.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_asn1.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cms_asn1.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_asn1.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_asn1.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_asn1.o: cms.h cms_asn1.c cms_lcl.h
cms_asn1.bc: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_asn1.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cms_asn1.bc: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_asn1.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_asn1.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_asn1.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cms_asn1.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_asn1.bc: ../../include/openssl/opensslconf.h
cms_asn1.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_asn1.bc: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_asn1.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cms_asn1.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_asn1.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_asn1.bc: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_asn1.bc: cms.h cms_asn1.c cms_lcl.h
cms_att.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_att.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cms_att.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_att.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_att.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_att.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_att.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_att.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_att.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_att.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_att.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cms_att.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_att.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_att.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_att.o: cms.h cms_att.c cms_lcl.h
cms_att.bc: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_att.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cms_att.bc: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_att.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_att.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_att.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_att.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_att.bc: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_att.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_att.bc: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_att.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cms_att.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_att.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_att.bc: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_att.bc: cms.h cms_att.c cms_lcl.h
cms_cd.o: ../../e_os.h ../../include/openssl/asn1.h
cms_cd.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_cd.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_cd.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_cd.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_cd.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_cd.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_cd.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_cd.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_cd.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_cd.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_cd.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cms_cd.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_cd.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_cd.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_cd.o: ../cryptlib.h cms_cd.c cms_lcl.h
cms_cd.bc: ../../e_os.h ../../include/openssl/asn1.h
cms_cd.bc: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_cd.bc: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_cd.bc: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_cd.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_cd.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_cd.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_cd.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_cd.bc: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_cd.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_cd.bc: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_cd.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cms_cd.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_cd.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_cd.bc: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_cd.bc: ../cryptlib.h cms_cd.c cms_lcl.h
cms_dd.o: ../../e_os.h ../../include/openssl/asn1.h
cms_dd.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_dd.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_dd.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_dd.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_dd.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_dd.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_dd.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_dd.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_dd.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_dd.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_dd.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cms_dd.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_dd.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_dd.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_dd.o: ../cryptlib.h cms_dd.c cms_lcl.h
cms_dd.bc: ../../e_os.h ../../include/openssl/asn1.h
cms_dd.bc: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_dd.bc: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_dd.bc: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_dd.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_dd.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_dd.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_dd.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_dd.bc: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_dd.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_dd.bc: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_dd.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cms_dd.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_dd.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_dd.bc: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_dd.bc: ../cryptlib.h cms_dd.c cms_lcl.h
cms_enc.o: ../../e_os.h ../../include/openssl/KTest.h
cms_enc.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_enc.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cms_enc.o: ../../include/openssl/cms.h ../../include/openssl/conf.h
cms_enc.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cms_enc.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cms_enc.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
cms_enc.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cms_enc.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_enc.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cms_enc.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
cms_enc.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
cms_enc.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
cms_enc.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_enc.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_enc.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_enc.o: ../cryptlib.h cms_enc.c cms_lcl.h
cms_enc.bc: ../../e_os.h ../../include/openssl/KTest.h
cms_enc.bc: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_enc.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cms_enc.bc: ../../include/openssl/cms.h ../../include/openssl/conf.h
cms_enc.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cms_enc.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cms_enc.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
cms_enc.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cms_enc.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_enc.bc: ../../include/openssl/opensslconf.h
cms_enc.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_enc.bc: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_enc.bc: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
cms_enc.bc: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_enc.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_enc.bc: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_enc.bc: ../../include/openssl/x509v3.h ../cryptlib.h cms_enc.c cms_lcl.h
cms_env.o: ../../e_os.h ../../include/openssl/KTest.h
cms_env.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
cms_env.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_env.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_env.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_env.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_env.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_env.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_env.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_env.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_env.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_env.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_env.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
cms_env.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_env.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_env.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_env.o: ../../include/openssl/x509v3.h ../asn1/asn1_locl.h ../cryptlib.h
cms_env.o: cms_env.c cms_lcl.h
cms_env.bc: ../../e_os.h ../../include/openssl/KTest.h
cms_env.bc: ../../include/openssl/aes.h ../../include/openssl/asn1.h
cms_env.bc: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_env.bc: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_env.bc: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_env.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_env.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_env.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_env.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_env.bc: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_env.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_env.bc: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_env.bc: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
cms_env.bc: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_env.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_env.bc: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_env.bc: ../../include/openssl/x509v3.h ../asn1/asn1_locl.h ../cryptlib.h
cms_env.bc: cms_env.c cms_lcl.h
cms_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
cms_err.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cms_err.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cms_err.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
cms_err.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cms_err.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_err.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cms_err.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
cms_err.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_err.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_err.o: cms_err.c
cms_err.bc: ../../include/openssl/asn1.h ../../include/openssl/bio.h
cms_err.bc: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_err.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cms_err.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cms_err.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
cms_err.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cms_err.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_err.bc: ../../include/openssl/opensslconf.h
cms_err.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_err.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cms_err.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_err.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_err.bc: ../../include/openssl/x509_vfy.h cms_err.c
cms_ess.o: ../../e_os.h ../../include/openssl/KTest.h
cms_ess.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_ess.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cms_ess.o: ../../include/openssl/cms.h ../../include/openssl/conf.h
cms_ess.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cms_ess.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cms_ess.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
cms_ess.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cms_ess.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_ess.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cms_ess.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
cms_ess.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
cms_ess.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
cms_ess.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_ess.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_ess.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_ess.o: ../cryptlib.h cms_ess.c cms_lcl.h
cms_ess.bc: ../../e_os.h ../../include/openssl/KTest.h
cms_ess.bc: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_ess.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cms_ess.bc: ../../include/openssl/cms.h ../../include/openssl/conf.h
cms_ess.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cms_ess.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cms_ess.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
cms_ess.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cms_ess.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_ess.bc: ../../include/openssl/opensslconf.h
cms_ess.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_ess.bc: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_ess.bc: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
cms_ess.bc: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_ess.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_ess.bc: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_ess.bc: ../../include/openssl/x509v3.h ../cryptlib.h cms_ess.c cms_lcl.h
cms_io.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_io.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cms_io.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cms_io.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cms_io.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
cms_io.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cms_io.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_io.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cms_io.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
cms_io.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
cms_io.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_io.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_io.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h cms.h
cms_io.o: cms_io.c cms_lcl.h
cms_io.bc: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_io.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cms_io.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cms_io.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cms_io.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
cms_io.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cms_io.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_io.bc: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cms_io.bc: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
cms_io.bc: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
cms_io.bc: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_io.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_io.bc: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h cms.h
cms_io.bc: cms_io.c cms_lcl.h
cms_lib.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_lib.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cms_lib.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cms_lib.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cms_lib.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
cms_lib.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cms_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_lib.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cms_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
cms_lib.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
cms_lib.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h cms.h
cms_lib.o: cms_lcl.h cms_lib.c
cms_lib.bc: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_lib.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cms_lib.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cms_lib.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cms_lib.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
cms_lib.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cms_lib.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_lib.bc: ../../include/openssl/opensslconf.h
cms_lib.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_lib.bc: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_lib.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cms_lib.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_lib.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_lib.bc: ../../include/openssl/x509_vfy.h cms.h cms_lcl.h cms_lib.c
cms_pwri.o: ../../e_os.h ../../include/openssl/KTest.h
cms_pwri.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
cms_pwri.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_pwri.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_pwri.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_pwri.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_pwri.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_pwri.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_pwri.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_pwri.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_pwri.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_pwri.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_pwri.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
cms_pwri.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_pwri.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_pwri.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_pwri.o: ../../include/openssl/x509v3.h ../asn1/asn1_locl.h ../cryptlib.h
cms_pwri.o: cms_lcl.h cms_pwri.c
cms_pwri.bc: ../../e_os.h ../../include/openssl/KTest.h
cms_pwri.bc: ../../include/openssl/aes.h ../../include/openssl/asn1.h
cms_pwri.bc: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_pwri.bc: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_pwri.bc: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_pwri.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_pwri.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_pwri.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_pwri.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_pwri.bc: ../../include/openssl/objects.h
cms_pwri.bc: ../../include/openssl/opensslconf.h
cms_pwri.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_pwri.bc: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_pwri.bc: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
cms_pwri.bc: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_pwri.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_pwri.bc: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_pwri.bc: ../../include/openssl/x509v3.h ../asn1/asn1_locl.h ../cryptlib.h
cms_pwri.bc: cms_lcl.h cms_pwri.c
cms_sd.o: ../../e_os.h ../../include/openssl/asn1.h
cms_sd.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_sd.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_sd.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_sd.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_sd.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_sd.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_sd.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_sd.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_sd.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_sd.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_sd.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cms_sd.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_sd.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_sd.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_sd.o: ../asn1/asn1_locl.h ../cryptlib.h cms_lcl.h cms_sd.c
cms_sd.bc: ../../e_os.h ../../include/openssl/asn1.h
cms_sd.bc: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_sd.bc: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_sd.bc: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_sd.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_sd.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_sd.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_sd.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_sd.bc: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_sd.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_sd.bc: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_sd.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cms_sd.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_sd.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_sd.bc: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_sd.bc: ../asn1/asn1_locl.h ../cryptlib.h cms_lcl.h cms_sd.c
cms_smime.o: ../../e_os.h ../../include/openssl/asn1.h
cms_smime.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_smime.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_smime.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_smime.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_smime.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_smime.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_smime.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_smime.o: ../../include/openssl/objects.h
cms_smime.o: ../../include/openssl/opensslconf.h
cms_smime.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_smime.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cms_smime.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_smime.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_smime.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_smime.o: ../cryptlib.h cms_lcl.h cms_smime.c
cms_smime.bc: ../../e_os.h ../../include/openssl/asn1.h
cms_smime.bc: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_smime.bc: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_smime.bc: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_smime.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_smime.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_smime.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_smime.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_smime.bc: ../../include/openssl/objects.h
cms_smime.bc: ../../include/openssl/opensslconf.h
cms_smime.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_smime.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cms_smime.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
cms_smime.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_smime.bc: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_smime.bc: ../cryptlib.h cms_lcl.h cms_smime.c
