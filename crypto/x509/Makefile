#
# OpenSSL/crypto/x509/Makefile
#

DIR=	x509
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile README
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	x509_def.c x509_d2.c x509_r2x.c x509_cmp.c \
	x509_obj.c x509_req.c x509spki.c x509_vfy.c \
	x509_set.c x509cset.c x509rset.c x509_err.c \
	x509name.c x509_v3.c x509_ext.c x509_att.c \
	x509type.c x509_lu.c x_all.c x509_txt.c \
	x509_trs.c by_file.c by_dir.c x509_vpm.c
LIBOBJ= x509_def.o x509_d2.o x509_r2x.o x509_cmp.o \
	x509_obj.o x509_req.o x509spki.o x509_vfy.o \
	x509_set.o x509cset.o x509rset.o x509_err.o \
	x509name.o x509_v3.o x509_ext.o x509_att.o \
	x509type.o x509_lu.o x_all.o x509_txt.o \
	x509_trs.o by_file.o by_dir.o x509_vpm.o

SRC= $(LIBSRC)

EXHEADER= x509.h x509_vfy.h
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

by_dir.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
by_dir.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
by_dir.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
by_dir.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
by_dir.o: ../../include/openssl/err.h ../../include/openssl/evp.h
by_dir.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
by_dir.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
by_dir.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
by_dir.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
by_dir.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
by_dir.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
by_dir.o: ../../include/openssl/x509_vfy.h ../cryptlib.h by_dir.c
by_dir.bc: ../../e_os.h ../../include/openssl/asn1.h
by_dir.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
by_dir.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
by_dir.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
by_dir.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
by_dir.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
by_dir.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
by_dir.bc: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
by_dir.bc: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
by_dir.bc: ../../include/openssl/safestack.h ../../include/openssl/sha.h
by_dir.bc: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
by_dir.bc: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
by_dir.bc: ../cryptlib.h by_dir.c
by_file.o: ../../e_os.h ../../include/openssl/asn1.h
by_file.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
by_file.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
by_file.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
by_file.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
by_file.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
by_file.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
by_file.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
by_file.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
by_file.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
by_file.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
by_file.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
by_file.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
by_file.o: ../cryptlib.h by_file.c
by_file.bc: ../../e_os.h ../../include/openssl/asn1.h
by_file.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
by_file.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
by_file.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
by_file.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
by_file.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
by_file.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
by_file.bc: ../../include/openssl/opensslconf.h
by_file.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
by_file.bc: ../../include/openssl/pem.h ../../include/openssl/pem2.h
by_file.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
by_file.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
by_file.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
by_file.bc: ../../include/openssl/x509_vfy.h ../cryptlib.h by_file.c
x509_att.o: ../../e_os.h ../../include/openssl/asn1.h
x509_att.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_att.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_att.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_att.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_att.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_att.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_att.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_att.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_att.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_att.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_att.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_att.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_att.o: ../cryptlib.h x509_att.c
x509_att.bc: ../../e_os.h ../../include/openssl/asn1.h
x509_att.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_att.bc: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_att.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_att.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_att.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_att.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_att.bc: ../../include/openssl/objects.h
x509_att.bc: ../../include/openssl/opensslconf.h
x509_att.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_att.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_att.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_att.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_att.bc: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_att.bc: ../cryptlib.h x509_att.c
x509_cmp.o: ../../e_os.h ../../include/openssl/asn1.h
x509_cmp.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_cmp.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_cmp.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_cmp.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_cmp.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_cmp.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_cmp.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_cmp.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_cmp.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_cmp.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_cmp.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_cmp.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_cmp.o: ../cryptlib.h x509_cmp.c
x509_cmp.bc: ../../e_os.h ../../include/openssl/asn1.h
x509_cmp.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_cmp.bc: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_cmp.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_cmp.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_cmp.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_cmp.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_cmp.bc: ../../include/openssl/objects.h
x509_cmp.bc: ../../include/openssl/opensslconf.h
x509_cmp.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_cmp.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_cmp.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_cmp.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_cmp.bc: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_cmp.bc: ../cryptlib.h x509_cmp.c
x509_d2.o: ../../e_os.h ../../include/openssl/asn1.h
x509_d2.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_d2.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_d2.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_d2.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_d2.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_d2.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_d2.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
x509_d2.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
x509_d2.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509_d2.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509_d2.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509_d2.o: ../cryptlib.h x509_d2.c
x509_d2.bc: ../../e_os.h ../../include/openssl/asn1.h
x509_d2.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_d2.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_d2.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_d2.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_d2.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_d2.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_d2.bc: ../../include/openssl/opensslconf.h
x509_d2.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_d2.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_d2.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_d2.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_d2.bc: ../../include/openssl/x509_vfy.h ../cryptlib.h x509_d2.c
x509_def.o: ../../e_os.h ../../include/openssl/asn1.h
x509_def.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_def.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_def.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_def.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_def.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_def.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_def.o: ../../include/openssl/opensslconf.h
x509_def.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_def.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_def.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_def.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_def.o: ../../include/openssl/x509_vfy.h ../cryptlib.h x509_def.c
x509_def.bc: ../../e_os.h ../../include/openssl/asn1.h
x509_def.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_def.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_def.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_def.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_def.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_def.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_def.bc: ../../include/openssl/opensslconf.h
x509_def.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_def.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_def.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_def.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_def.bc: ../../include/openssl/x509_vfy.h ../cryptlib.h x509_def.c
x509_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509_err.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
x509_err.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_err.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_err.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_err.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_err.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_err.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_err.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_err.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_err.o: ../../include/openssl/x509_vfy.h x509_err.c
x509_err.bc: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509_err.bc: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
x509_err.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_err.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_err.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_err.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_err.bc: ../../include/openssl/objects.h
x509_err.bc: ../../include/openssl/opensslconf.h
x509_err.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_err.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_err.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_err.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_err.bc: ../../include/openssl/x509_vfy.h x509_err.c
x509_ext.o: ../../e_os.h ../../include/openssl/asn1.h
x509_ext.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_ext.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_ext.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_ext.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_ext.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_ext.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_ext.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_ext.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_ext.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_ext.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_ext.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_ext.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_ext.o: ../cryptlib.h x509_ext.c
x509_ext.bc: ../../e_os.h ../../include/openssl/asn1.h
x509_ext.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_ext.bc: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_ext.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_ext.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_ext.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_ext.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_ext.bc: ../../include/openssl/objects.h
x509_ext.bc: ../../include/openssl/opensslconf.h
x509_ext.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_ext.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_ext.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_ext.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_ext.bc: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_ext.bc: ../cryptlib.h x509_ext.c
x509_lu.o: ../../e_os.h ../../include/openssl/asn1.h
x509_lu.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_lu.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_lu.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_lu.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_lu.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_lu.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_lu.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_lu.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_lu.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_lu.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_lu.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_lu.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_lu.o: ../cryptlib.h x509_lu.c
x509_lu.bc: ../../e_os.h ../../include/openssl/asn1.h
x509_lu.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_lu.bc: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_lu.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_lu.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_lu.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_lu.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_lu.bc: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_lu.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_lu.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_lu.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_lu.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_lu.bc: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_lu.bc: ../cryptlib.h x509_lu.c
x509_obj.o: ../../e_os.h ../../include/openssl/asn1.h
x509_obj.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_obj.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_obj.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_obj.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_obj.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_obj.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_obj.o: ../../include/openssl/opensslconf.h
x509_obj.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_obj.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_obj.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_obj.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_obj.o: ../../include/openssl/x509_vfy.h ../cryptlib.h x509_obj.c
x509_obj.bc: ../../e_os.h ../../include/openssl/asn1.h
x509_obj.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_obj.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_obj.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_obj.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_obj.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_obj.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_obj.bc: ../../include/openssl/opensslconf.h
x509_obj.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_obj.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_obj.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_obj.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_obj.bc: ../../include/openssl/x509_vfy.h ../cryptlib.h x509_obj.c
x509_r2x.o: ../../e_os.h ../../include/openssl/asn1.h
x509_r2x.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
x509_r2x.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
x509_r2x.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_r2x.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_r2x.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_r2x.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_r2x.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_r2x.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_r2x.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_r2x.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_r2x.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_r2x.o: ../../include/openssl/x509_vfy.h ../cryptlib.h x509_r2x.c
x509_r2x.bc: ../../e_os.h ../../include/openssl/asn1.h
x509_r2x.bc: ../../include/openssl/bio.h ../../include/openssl/bn.h
x509_r2x.bc: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
x509_r2x.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_r2x.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_r2x.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_r2x.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_r2x.bc: ../../include/openssl/objects.h
x509_r2x.bc: ../../include/openssl/opensslconf.h
x509_r2x.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_r2x.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_r2x.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_r2x.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_r2x.bc: ../../include/openssl/x509_vfy.h ../cryptlib.h x509_r2x.c
x509_req.o: ../../e_os.h ../../include/openssl/asn1.h
x509_req.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x509_req.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
x509_req.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_req.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_req.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_req.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_req.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_req.o: ../../include/openssl/opensslconf.h
x509_req.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_req.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
x509_req.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_req.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_req.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_req.o: ../../include/openssl/x509_vfy.h ../cryptlib.h x509_req.c
x509_req.bc: ../../e_os.h ../../include/openssl/asn1.h
x509_req.bc: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x509_req.bc: ../../include/openssl/bn.h ../../include/openssl/buffer.h
x509_req.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_req.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_req.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_req.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_req.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_req.bc: ../../include/openssl/opensslconf.h
x509_req.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_req.bc: ../../include/openssl/pem.h ../../include/openssl/pem2.h
x509_req.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_req.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_req.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_req.bc: ../../include/openssl/x509_vfy.h ../cryptlib.h x509_req.c
x509_set.o: ../../e_os.h ../../include/openssl/asn1.h
x509_set.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_set.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_set.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_set.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_set.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_set.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_set.o: ../../include/openssl/opensslconf.h
x509_set.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_set.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_set.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_set.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_set.o: ../../include/openssl/x509_vfy.h ../cryptlib.h x509_set.c
x509_set.bc: ../../e_os.h ../../include/openssl/asn1.h
x509_set.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_set.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_set.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_set.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_set.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_set.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_set.bc: ../../include/openssl/opensslconf.h
x509_set.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_set.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_set.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_set.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_set.bc: ../../include/openssl/x509_vfy.h ../cryptlib.h x509_set.c
x509_trs.o: ../../e_os.h ../../include/openssl/asn1.h
x509_trs.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_trs.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_trs.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_trs.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_trs.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_trs.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_trs.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_trs.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_trs.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_trs.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_trs.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_trs.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_trs.o: ../cryptlib.h x509_trs.c
x509_trs.bc: ../../e_os.h ../../include/openssl/asn1.h
x509_trs.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_trs.bc: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_trs.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_trs.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_trs.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_trs.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_trs.bc: ../../include/openssl/objects.h
x509_trs.bc: ../../include/openssl/opensslconf.h
x509_trs.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_trs.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_trs.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_trs.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_trs.bc: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_trs.bc: ../cryptlib.h x509_trs.c
x509_txt.o: ../../e_os.h ../../include/openssl/asn1.h
x509_txt.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_txt.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_txt.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_txt.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_txt.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_txt.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_txt.o: ../../include/openssl/opensslconf.h
x509_txt.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_txt.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_txt.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_txt.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_txt.o: ../../include/openssl/x509_vfy.h ../cryptlib.h x509_txt.c
x509_txt.bc: ../../e_os.h ../../include/openssl/asn1.h
x509_txt.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_txt.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_txt.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_txt.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_txt.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_txt.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_txt.bc: ../../include/openssl/opensslconf.h
x509_txt.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_txt.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_txt.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_txt.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_txt.bc: ../../include/openssl/x509_vfy.h ../cryptlib.h x509_txt.c
x509_v3.o: ../../e_os.h ../../include/openssl/asn1.h
x509_v3.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_v3.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_v3.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_v3.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_v3.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_v3.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_v3.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_v3.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_v3.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_v3.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_v3.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_v3.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_v3.o: ../cryptlib.h x509_v3.c
x509_v3.bc: ../../e_os.h ../../include/openssl/asn1.h
x509_v3.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_v3.bc: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_v3.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_v3.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_v3.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_v3.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_v3.bc: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_v3.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_v3.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_v3.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_v3.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_v3.bc: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_v3.bc: ../cryptlib.h x509_v3.c
x509_vfy.o: ../../e_os.h ../../include/openssl/asn1.h
x509_vfy.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_vfy.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_vfy.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_vfy.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_vfy.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_vfy.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_vfy.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_vfy.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_vfy.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_vfy.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_vfy.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_vfy.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_vfy.o: ../cryptlib.h x509_vfy.c
x509_vfy.bc: ../../e_os.h ../../include/openssl/asn1.h
x509_vfy.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_vfy.bc: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_vfy.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_vfy.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_vfy.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_vfy.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_vfy.bc: ../../include/openssl/objects.h
x509_vfy.bc: ../../include/openssl/opensslconf.h
x509_vfy.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_vfy.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_vfy.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_vfy.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_vfy.bc: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_vfy.bc: ../cryptlib.h x509_vfy.c
x509_vpm.o: ../../e_os.h ../../include/openssl/asn1.h
x509_vpm.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_vpm.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_vpm.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_vpm.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_vpm.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_vpm.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_vpm.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_vpm.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_vpm.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_vpm.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_vpm.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_vpm.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_vpm.o: ../cryptlib.h x509_vpm.c
x509_vpm.bc: ../../e_os.h ../../include/openssl/asn1.h
x509_vpm.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_vpm.bc: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_vpm.bc: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_vpm.bc: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_vpm.bc: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_vpm.bc: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_vpm.bc: ../../include/openssl/objects.h
x509_vpm.bc: ../../include/openssl/opensslconf.h
x509_vpm.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_vpm.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_vpm.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_vpm.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_vpm.bc: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_vpm.bc: ../cryptlib.h x509_vpm.c
x509cset.o: ../../e_os.h ../../include/openssl/asn1.h
x509cset.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509cset.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509cset.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509cset.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509cset.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509cset.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509cset.o: ../../include/openssl/opensslconf.h
x509cset.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509cset.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509cset.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509cset.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509cset.o: ../../include/openssl/x509_vfy.h ../cryptlib.h x509cset.c
x509cset.bc: ../../e_os.h ../../include/openssl/asn1.h
x509cset.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509cset.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509cset.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509cset.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509cset.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509cset.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509cset.bc: ../../include/openssl/opensslconf.h
x509cset.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509cset.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509cset.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509cset.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509cset.bc: ../../include/openssl/x509_vfy.h ../cryptlib.h x509cset.c
x509name.o: ../../e_os.h ../../include/openssl/asn1.h
x509name.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509name.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509name.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509name.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509name.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509name.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509name.o: ../../include/openssl/opensslconf.h
x509name.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509name.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509name.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509name.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509name.o: ../../include/openssl/x509_vfy.h ../cryptlib.h x509name.c
x509name.bc: ../../e_os.h ../../include/openssl/asn1.h
x509name.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509name.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509name.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509name.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509name.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509name.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509name.bc: ../../include/openssl/opensslconf.h
x509name.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509name.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509name.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509name.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509name.bc: ../../include/openssl/x509_vfy.h ../cryptlib.h x509name.c
x509rset.o: ../../e_os.h ../../include/openssl/asn1.h
x509rset.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509rset.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509rset.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509rset.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509rset.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509rset.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509rset.o: ../../include/openssl/opensslconf.h
x509rset.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509rset.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509rset.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509rset.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509rset.o: ../../include/openssl/x509_vfy.h ../cryptlib.h x509rset.c
x509rset.bc: ../../e_os.h ../../include/openssl/asn1.h
x509rset.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509rset.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509rset.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509rset.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509rset.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509rset.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509rset.bc: ../../include/openssl/opensslconf.h
x509rset.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509rset.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509rset.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509rset.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509rset.bc: ../../include/openssl/x509_vfy.h ../cryptlib.h x509rset.c
x509spki.o: ../../e_os.h ../../include/openssl/asn1.h
x509spki.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509spki.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509spki.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509spki.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509spki.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509spki.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509spki.o: ../../include/openssl/opensslconf.h
x509spki.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509spki.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509spki.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509spki.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509spki.o: ../../include/openssl/x509_vfy.h ../cryptlib.h x509spki.c
x509spki.bc: ../../e_os.h ../../include/openssl/asn1.h
x509spki.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509spki.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509spki.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509spki.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509spki.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509spki.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509spki.bc: ../../include/openssl/opensslconf.h
x509spki.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509spki.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509spki.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509spki.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509spki.bc: ../../include/openssl/x509_vfy.h ../cryptlib.h x509spki.c
x509type.o: ../../e_os.h ../../include/openssl/asn1.h
x509type.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509type.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509type.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509type.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509type.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509type.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509type.o: ../../include/openssl/opensslconf.h
x509type.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509type.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509type.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509type.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509type.o: ../../include/openssl/x509_vfy.h ../cryptlib.h x509type.c
x509type.bc: ../../e_os.h ../../include/openssl/asn1.h
x509type.bc: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509type.bc: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509type.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509type.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509type.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509type.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509type.bc: ../../include/openssl/opensslconf.h
x509type.bc: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509type.bc: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509type.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509type.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509type.bc: ../../include/openssl/x509_vfy.h ../cryptlib.h x509type.c
x_all.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
x_all.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
x_all.o: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
x_all.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x_all.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x_all.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x_all.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_all.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
x_all.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
x_all.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
x_all.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x_all.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x_all.o: ../../include/openssl/x509_vfy.h ../cryptlib.h x_all.c
x_all.bc: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
x_all.bc: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
x_all.bc: ../../include/openssl/dsa.h ../../include/openssl/e_os2.h
x_all.bc: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x_all.bc: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x_all.bc: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x_all.bc: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x_all.bc: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
x_all.bc: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
x_all.bc: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
x_all.bc: ../../include/openssl/sha.h ../../include/openssl/stack.h
x_all.bc: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x_all.bc: ../../include/openssl/x509_vfy.h ../cryptlib.h x_all.c
