#
# OpenSSL/crypto/pkcs12/Makefile
#

DIR=	pkcs12
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
LIBSRC= p12_add.c p12_asn.c p12_attr.c p12_crpt.c p12_crt.c p12_decr.c \
	p12_init.c p12_key.c p12_kiss.c p12_mutl.c\
	p12_utl.c p12_npas.c pk12err.c p12_p8d.c p12_p8e.c
LIBOBJ= p12_add.o p12_asn.o p12_attr.o p12_crpt.o p12_crt.o p12_decr.o \
	p12_init.o p12_key.o p12_kiss.o p12_mutl.o\
	p12_utl.o p12_npas.o pk12err.o p12_p8d.o p12_p8e.o

SRC= $(LIBSRC)

EXHEADER=  pkcs12.h
HEADER=	$(EXHEADER)

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

p12_add.o: ../../e_os.h ../../include/openssl/asn1.h
p12_add.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
p12_add.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
p12_add.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
p12_add.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
p12_add.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p12_add.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_add.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
p12_add.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs12.h
p12_add.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
p12_add.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
p12_add.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
p12_add.o: ../../include/openssl/x509_vfy.h ../cryptlib.h p12_add.c
p12_add.bc: ../../e_os.h ../../include/openssl/asn1.h
p12_add.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
p12_add.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
p12_add.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
p12_add.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
p12_add.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p12_add.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_add.bc: ../../include/openssl/opensslconf.h
p12_add.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_add.bc: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_add.bc: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_add.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_add.bc: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_add.bc: ../cryptlib.h p12_add.c
p12_asn.o: ../../e_os.h ../../include/openssl/asn1.h
p12_asn.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
p12_asn.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
p12_asn.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
p12_asn.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
p12_asn.o: ../../include/openssl/err.h ../../include/openssl/evp.h
p12_asn.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
p12_asn.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
p12_asn.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_asn.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_asn.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_asn.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_asn.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_asn.o: ../cryptlib.h p12_asn.c
p12_asn.bc: ../../e_os.h ../../include/openssl/asn1.h
p12_asn.bc: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
p12_asn.bc: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
p12_asn.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
p12_asn.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
p12_asn.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
p12_asn.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
p12_asn.bc: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
p12_asn.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_asn.bc: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_asn.bc: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_asn.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_asn.bc: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_asn.bc: ../cryptlib.h p12_asn.c
p12_attr.o: ../../e_os.h ../../include/openssl/asn1.h
p12_attr.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
p12_attr.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
p12_attr.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
p12_attr.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
p12_attr.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p12_attr.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_attr.o: ../../include/openssl/opensslconf.h
p12_attr.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_attr.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_attr.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_attr.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_attr.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_attr.o: ../cryptlib.h p12_attr.c
p12_attr.bc: ../../e_os.h ../../include/openssl/asn1.h
p12_attr.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
p12_attr.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
p12_attr.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
p12_attr.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
p12_attr.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p12_attr.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_attr.bc: ../../include/openssl/opensslconf.h
p12_attr.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_attr.bc: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_attr.bc: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_attr.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_attr.bc: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_attr.bc: ../cryptlib.h p12_attr.c
p12_crpt.o: ../../e_os.h ../../include/openssl/asn1.h
p12_crpt.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
p12_crpt.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
p12_crpt.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
p12_crpt.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
p12_crpt.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p12_crpt.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_crpt.o: ../../include/openssl/opensslconf.h
p12_crpt.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_crpt.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_crpt.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_crpt.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_crpt.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_crpt.o: ../cryptlib.h p12_crpt.c
p12_crpt.bc: ../../e_os.h ../../include/openssl/asn1.h
p12_crpt.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
p12_crpt.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
p12_crpt.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
p12_crpt.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
p12_crpt.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p12_crpt.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_crpt.bc: ../../include/openssl/opensslconf.h
p12_crpt.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_crpt.bc: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_crpt.bc: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_crpt.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_crpt.bc: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_crpt.bc: ../cryptlib.h p12_crpt.c
p12_crt.o: ../../e_os.h ../../include/openssl/asn1.h
p12_crt.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
p12_crt.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
p12_crt.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
p12_crt.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
p12_crt.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p12_crt.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_crt.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
p12_crt.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs12.h
p12_crt.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
p12_crt.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
p12_crt.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
p12_crt.o: ../../include/openssl/x509_vfy.h ../cryptlib.h p12_crt.c
p12_crt.bc: ../../e_os.h ../../include/openssl/asn1.h
p12_crt.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
p12_crt.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
p12_crt.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
p12_crt.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
p12_crt.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p12_crt.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_crt.bc: ../../include/openssl/opensslconf.h
p12_crt.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_crt.bc: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_crt.bc: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_crt.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_crt.bc: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_crt.bc: ../cryptlib.h p12_crt.c
p12_decr.o: ../../e_os.h ../../include/openssl/asn1.h
p12_decr.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
p12_decr.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
p12_decr.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
p12_decr.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
p12_decr.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p12_decr.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_decr.o: ../../include/openssl/opensslconf.h
p12_decr.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_decr.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_decr.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_decr.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_decr.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_decr.o: ../cryptlib.h p12_decr.c
p12_decr.bc: ../../e_os.h ../../include/openssl/asn1.h
p12_decr.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
p12_decr.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
p12_decr.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
p12_decr.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
p12_decr.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p12_decr.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_decr.bc: ../../include/openssl/opensslconf.h
p12_decr.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_decr.bc: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_decr.bc: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_decr.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_decr.bc: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_decr.bc: ../cryptlib.h p12_decr.c
p12_init.o: ../../e_os.h ../../include/openssl/asn1.h
p12_init.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
p12_init.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
p12_init.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
p12_init.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
p12_init.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p12_init.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_init.o: ../../include/openssl/opensslconf.h
p12_init.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_init.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_init.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_init.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_init.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_init.o: ../cryptlib.h p12_init.c
p12_init.bc: ../../e_os.h ../../include/openssl/asn1.h
p12_init.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
p12_init.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
p12_init.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
p12_init.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
p12_init.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p12_init.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_init.bc: ../../include/openssl/opensslconf.h
p12_init.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_init.bc: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_init.bc: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_init.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_init.bc: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_init.bc: ../cryptlib.h p12_init.c
p12_key.o: ../../e_os.h ../../include/openssl/asn1.h
p12_key.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
p12_key.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
p12_key.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
p12_key.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
p12_key.o: ../../include/openssl/err.h ../../include/openssl/evp.h
p12_key.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
p12_key.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
p12_key.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_key.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_key.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_key.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_key.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_key.o: ../cryptlib.h p12_key.c
p12_key.bc: ../../e_os.h ../../include/openssl/asn1.h
p12_key.bc: ../../include/openssl/bio.h ../../include/openssl/bn.h
p12_key.bc: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
p12_key.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
p12_key.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
p12_key.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
p12_key.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
p12_key.bc: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
p12_key.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_key.bc: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_key.bc: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_key.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_key.bc: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_key.bc: ../cryptlib.h p12_key.c
p12_kiss.o: ../../e_os.h ../../include/openssl/asn1.h
p12_kiss.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
p12_kiss.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
p12_kiss.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
p12_kiss.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
p12_kiss.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p12_kiss.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_kiss.o: ../../include/openssl/opensslconf.h
p12_kiss.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_kiss.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_kiss.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_kiss.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_kiss.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_kiss.o: ../cryptlib.h p12_kiss.c
p12_kiss.bc: ../../e_os.h ../../include/openssl/asn1.h
p12_kiss.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
p12_kiss.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
p12_kiss.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
p12_kiss.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
p12_kiss.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p12_kiss.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_kiss.bc: ../../include/openssl/opensslconf.h
p12_kiss.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_kiss.bc: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_kiss.bc: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_kiss.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_kiss.bc: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_kiss.bc: ../cryptlib.h p12_kiss.c
p12_mutl.o: ../../e_os.h ../../include/openssl/KTest.h
p12_mutl.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
p12_mutl.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
p12_mutl.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
p12_mutl.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
p12_mutl.o: ../../include/openssl/err.h ../../include/openssl/evp.h
p12_mutl.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
p12_mutl.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_mutl.o: ../../include/openssl/opensslconf.h
p12_mutl.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_mutl.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_mutl.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
p12_mutl.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
p12_mutl.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
p12_mutl.o: ../../include/openssl/x509_vfy.h ../cryptlib.h p12_mutl.c
p12_mutl.bc: ../../e_os.h ../../include/openssl/KTest.h
p12_mutl.bc: ../../include/openssl/asn1.h ../../include/openssl/bio.h
p12_mutl.bc: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
p12_mutl.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
p12_mutl.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
p12_mutl.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
p12_mutl.bc: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
p12_mutl.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_mutl.bc: ../../include/openssl/opensslconf.h
p12_mutl.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_mutl.bc: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_mutl.bc: ../../include/openssl/rand.h ../../include/openssl/safestack.h
p12_mutl.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
p12_mutl.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
p12_mutl.bc: ../../include/openssl/x509_vfy.h ../cryptlib.h p12_mutl.c
p12_npas.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
p12_npas.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
p12_npas.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
p12_npas.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
p12_npas.o: ../../include/openssl/err.h ../../include/openssl/evp.h
p12_npas.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
p12_npas.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
p12_npas.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_npas.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
p12_npas.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_npas.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_npas.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_npas.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_npas.o: p12_npas.c
p12_npas.bc: ../../include/openssl/asn1.h ../../include/openssl/bio.h
p12_npas.bc: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
p12_npas.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
p12_npas.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
p12_npas.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
p12_npas.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
p12_npas.bc: ../../include/openssl/objects.h
p12_npas.bc: ../../include/openssl/opensslconf.h
p12_npas.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_npas.bc: ../../include/openssl/pem.h ../../include/openssl/pem2.h
p12_npas.bc: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_npas.bc: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_npas.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_npas.bc: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_npas.bc: p12_npas.c
p12_p8d.o: ../../e_os.h ../../include/openssl/asn1.h
p12_p8d.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
p12_p8d.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
p12_p8d.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
p12_p8d.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
p12_p8d.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p12_p8d.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_p8d.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
p12_p8d.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs12.h
p12_p8d.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
p12_p8d.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
p12_p8d.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
p12_p8d.o: ../../include/openssl/x509_vfy.h ../cryptlib.h p12_p8d.c
p12_p8d.bc: ../../e_os.h ../../include/openssl/asn1.h
p12_p8d.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
p12_p8d.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
p12_p8d.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
p12_p8d.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
p12_p8d.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p12_p8d.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_p8d.bc: ../../include/openssl/opensslconf.h
p12_p8d.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_p8d.bc: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_p8d.bc: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_p8d.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_p8d.bc: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_p8d.bc: ../cryptlib.h p12_p8d.c
p12_p8e.o: ../../e_os.h ../../include/openssl/asn1.h
p12_p8e.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
p12_p8e.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
p12_p8e.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
p12_p8e.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
p12_p8e.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p12_p8e.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_p8e.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
p12_p8e.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs12.h
p12_p8e.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
p12_p8e.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
p12_p8e.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
p12_p8e.o: ../../include/openssl/x509_vfy.h ../cryptlib.h p12_p8e.c
p12_p8e.bc: ../../e_os.h ../../include/openssl/asn1.h
p12_p8e.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
p12_p8e.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
p12_p8e.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
p12_p8e.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
p12_p8e.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p12_p8e.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_p8e.bc: ../../include/openssl/opensslconf.h
p12_p8e.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_p8e.bc: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_p8e.bc: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_p8e.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_p8e.bc: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_p8e.bc: ../cryptlib.h p12_p8e.c
p12_utl.o: ../../e_os.h ../../include/openssl/asn1.h
p12_utl.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
p12_utl.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
p12_utl.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
p12_utl.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
p12_utl.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p12_utl.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_utl.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
p12_utl.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs12.h
p12_utl.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
p12_utl.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
p12_utl.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
p12_utl.o: ../../include/openssl/x509_vfy.h ../cryptlib.h p12_utl.c
p12_utl.bc: ../../e_os.h ../../include/openssl/asn1.h
p12_utl.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
p12_utl.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
p12_utl.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
p12_utl.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
p12_utl.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
p12_utl.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
p12_utl.bc: ../../include/openssl/opensslconf.h
p12_utl.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
p12_utl.bc: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
p12_utl.bc: ../../include/openssl/safestack.h ../../include/openssl/sha.h
p12_utl.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
p12_utl.bc: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
p12_utl.bc: ../cryptlib.h p12_utl.c
pk12err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
pk12err.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
pk12err.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
pk12err.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
pk12err.o: ../../include/openssl/err.h ../../include/openssl/evp.h
pk12err.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
pk12err.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
pk12err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
pk12err.o: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
pk12err.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
pk12err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
pk12err.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
pk12err.o: pk12err.c
pk12err.bc: ../../include/openssl/asn1.h ../../include/openssl/bio.h
pk12err.bc: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
pk12err.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
pk12err.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
pk12err.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
pk12err.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
pk12err.bc: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
pk12err.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
pk12err.bc: ../../include/openssl/pkcs12.h ../../include/openssl/pkcs7.h
pk12err.bc: ../../include/openssl/safestack.h ../../include/openssl/sha.h
pk12err.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
pk12err.bc: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
pk12err.bc: pk12err.c
