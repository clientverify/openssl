#
#  apps/Makefile
#

DIR=		apps
TOP=		..
CC=		cc
INCLUDES=	-I$(TOP) -I../include $(KRB5_INCLUDES)
CFLAG=		-g -static
MAKEFILE=	Makefile
PERL=		perl
RM=		rm -f
# KRB5 stuff
KRB5_INCLUDES=
LIBKRB5=

PEX_LIBS=
EX_LIBS= 
EXE_EXT= 

SHLIB_TARGET=

CFLAGS= -DMONOLITH $(INCLUDES) $(CFLAG)

GENERAL=Makefile makeapps.com install.com

DLIBCRYPTO=../libcrypto.a
DLIBSSL=../libssl.a
LIBCRYPTO=-L.. -lcrypto
LIBSSL=-L.. -lssl


PROGRAM= s_client

SCRIPTS=CA.sh CA.pl tsget

EXE= $(PROGRAM)$(EXE_EXT)


E_EXE= s_client
#verify asn1pars req dgst dh dhparam enc passwd gendh errstr \
ca crl rsa rsautl dsa dsaparam ec ecparam \
x509 genrsa gendsa genpkey s_server s_client speed \
s_time version pkcs7 cms crl2pkcs7 sess_id ciphers nseq pkcs12 \
pkcs8 pkey pkeyparam pkeyutl spkac smime rand engine ocsp prime ts srp

PROGS= $(PROGRAM).c

A_OBJ=apps.o
A_SRC=apps.c
S_OBJ=	s_cb.o s_socket.o
S_SRC=	s_cb.c s_socket.c
RAND_OBJ=app_rand.o
RAND_SRC=app_rand.c

E_OBJ= s_client.o $(A_OBJ) $(S_OBJ) $(RAND_OBJ) 
#verify.o asn1pars.o req.o dgst.o dh.o dhparam.o enc.o passwd.o gendh.o errstr.o \
ca.o pkcs7.o crl2p7.o crl.o \
rsa.o rsautl.o dsa.o dsaparam.o ec.o ecparam.o \
x509.o genrsa.o gendsa.o genpkey.o s_server.o s_client.o speed.o \
s_time.o $(A_OBJ) $(S_OBJ) $(RAND_OBJ) version.o sess_id.o \
ciphers.o nseq.o pkcs12.o pkcs8.o pkey.o pkeyparam.o pkeyutl.o \
spkac.o smime.o cms.o rand.o engine.o ocsp.o prime.o ts.o srp.o

E_SRC= s_client.c  $(A_SRC) $(S_SRC) $(RAND_SRC) 
#verify.c asn1pars.c req.c dgst.c dh.c enc.c passwd.c gendh.c errstr.c ca.c \
pkcs7.c crl2p7.c crl.c \
rsa.c rsautl.c dsa.c dsaparam.c ec.c ecparam.c \
x509.c genrsa.c gendsa.c genpkey.c s_server.c s_client.c speed.c \
s_time.c $(A_SRC) $(S_SRC) $(RAND_SRC) version.c sess_id.c \
ciphers.c nseq.c pkcs12.c pkcs8.c pkey.c pkeyparam.c pkeyutl.c \
spkac.c smime.c cms.c rand.c engine.c ocsp.c prime.c ts.c srp.c

SRC=$(E_SRC)

EXHEADER=
HEADER=	apps.h progs.h s_apps.h \
	testdsa.h testrsa.h \
	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	@(cd ..; $(MAKE) DIRS=$(DIR) all)

include $(TASE_MKFILE)

all:	exe

exe:	$(EXE)

req: sreq.o $(A_OBJ) $(DLIBCRYPTO)
	shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	$(MAKE) -f $(TOP)/Makefile.shared -e \
		APPNAME=req OBJECTS="sreq.o $(A_OBJ) $(RAND_OBJ)" \
		LIBDEPS="$(PEX_LIBS) $(LIBCRYPTO) $(EX_LIBS)" \
		link_app.$${shlib_target}

#sreq.o: req.c 
#	$(CC) -c $(INCLUDES) $(CFLAG) -o sreq.o req.c

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@set -e; for i in $(EXE); \
	do  \
	(echo installing $$i; \
	 cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new; \
	 chmod 755 $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new; \
	 mv -f $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i.new $(INSTALL_PREFIX)$(INSTALLTOP)/bin/$$i ); \
	 done;
	@set -e; for i in $(SCRIPTS); \
	do  \
	(echo installing $$i; \
	 cp $$i $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i.new; \
	 chmod 755 $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i.new; \
	 mv -f $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i.new $(INSTALL_PREFIX)$(OPENSSLDIR)/misc/$$i ); \
	 done
	@cp openssl.cnf $(INSTALL_PREFIX)$(OPENSSLDIR)/openssl.cnf.new; \
	chmod 644 $(INSTALL_PREFIX)$(OPENSSLDIR)/openssl.cnf.new; \
	mv -f  $(INSTALL_PREFIX)$(OPENSSLDIR)/openssl.cnf.new $(INSTALL_PREFIX)$(OPENSSLDIR)/openssl.cnf

tags:
	ctags $(SRC)

tests:

links:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@if [ -z "$(THIS)" ]; then \
	    $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; \
	else \
	    $(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(SRC); \
	fi

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)
	rm -f CA.pl

clean:
	rm -f *.ll *.bc *.tase
	rm -f *.o *.obj *.dll lib tags core .pure .nfs* *.old *.bak fluff $(EXE)
	rm -f req

$(DLIBSSL):
	(cd ..; $(MAKE) DIRS=ssl all)

$(DLIBCRYPTO):
	(cd ..; $(MAKE) DIRS=crypto all)

$(EXE): progs.h $(E_OBJ) $(PROGRAM).o $(DLIBCRYPTO) $(DLIBSSL)
	$(RM) $(EXE)
	shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	elif [ -n "$(FIPSCANLIB)" ]; then \
	  FIPSLD_CC="$(CC)"; CC=$(FIPSDIR)/bin/fipsld; export CC FIPSLD_CC; \
	fi; \
	LIBRARIES="$(LIBSSL) $(LIBKRB5) $(LIBCRYPTO)" ; \
	$(MAKE) -f $(TOP)/Makefile.shared -e \
		APPNAME=$(EXE) OBJECTS="$(PROGRAM).o $(E_OBJ)" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}
	@(cd ..; $(MAKE) rehash)

progs.h: progs.pl
	$(PERL) progs.pl $(E_EXE) >progs.h
	$(RM) $(PROGRAM).o

# DO NOT DELETE THIS LINE -- make depend depends on it.

app_rand.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
app_rand.o: ../include/openssl/bio.h ../include/openssl/buffer.h
app_rand.o: ../include/openssl/conf.h ../include/openssl/crypto.h
app_rand.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
app_rand.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
app_rand.o: ../include/openssl/evp.h ../include/openssl/lhash.h
app_rand.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
app_rand.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
app_rand.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
app_rand.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
app_rand.o: ../include/openssl/safestack.h ../include/openssl/sha.h
app_rand.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
app_rand.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
app_rand.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h
app_rand.o: app_rand.c apps.h
app_rand.bc: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
app_rand.bc: ../include/openssl/bio.h ../include/openssl/buffer.h
app_rand.bc: ../include/openssl/conf.h ../include/openssl/crypto.h
app_rand.bc: ../include/openssl/e_os2.h ../include/openssl/ec.h
app_rand.bc: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
app_rand.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
app_rand.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
app_rand.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
app_rand.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
app_rand.bc: ../include/openssl/pkcs7.h ../include/openssl/rand.h
app_rand.bc: ../include/openssl/safestack.h ../include/openssl/sha.h
app_rand.bc: ../include/openssl/stack.h ../include/openssl/symhacks.h
app_rand.bc: ../include/openssl/txt_db.h ../include/openssl/x509.h
app_rand.bc: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h
app_rand.bc: app_rand.c apps.h
apps.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
apps.o: ../include/openssl/bn.h ../include/openssl/buffer.h
apps.o: ../include/openssl/conf.h ../include/openssl/crypto.h
apps.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
apps.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
apps.o: ../include/openssl/err.h ../include/openssl/evp.h
apps.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
apps.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
apps.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
apps.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
apps.o: ../include/openssl/pem2.h ../include/openssl/pkcs12.h
apps.o: ../include/openssl/pkcs7.h ../include/openssl/rsa.h
apps.o: ../include/openssl/safestack.h ../include/openssl/sha.h
apps.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
apps.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
apps.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
apps.o: ../include/openssl/x509v3.h apps.c apps.h
apps.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
apps.bc: ../include/openssl/bn.h ../include/openssl/buffer.h
apps.bc: ../include/openssl/conf.h ../include/openssl/crypto.h
apps.bc: ../include/openssl/e_os2.h ../include/openssl/ec.h
apps.bc: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
apps.bc: ../include/openssl/err.h ../include/openssl/evp.h
apps.bc: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
apps.bc: ../include/openssl/objects.h ../include/openssl/ocsp.h
apps.bc: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
apps.bc: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
apps.bc: ../include/openssl/pem2.h ../include/openssl/pkcs12.h
apps.bc: ../include/openssl/pkcs7.h ../include/openssl/rsa.h
apps.bc: ../include/openssl/safestack.h ../include/openssl/sha.h
apps.bc: ../include/openssl/stack.h ../include/openssl/symhacks.h
apps.bc: ../include/openssl/txt_db.h ../include/openssl/ui.h
apps.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
apps.bc: ../include/openssl/x509v3.h apps.c apps.h
asn1pars.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
asn1pars.o: ../include/openssl/buffer.h ../include/openssl/conf.h
asn1pars.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
asn1pars.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
asn1pars.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
asn1pars.o: ../include/openssl/evp.h ../include/openssl/lhash.h
asn1pars.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
asn1pars.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
asn1pars.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
asn1pars.o: ../include/openssl/pem.h ../include/openssl/pem2.h
asn1pars.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
asn1pars.o: ../include/openssl/sha.h ../include/openssl/stack.h
asn1pars.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
asn1pars.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
asn1pars.o: ../include/openssl/x509v3.h apps.h asn1pars.c
asn1pars.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
asn1pars.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
asn1pars.bc: ../include/openssl/crypto.h ../include/openssl/e_os2.h
asn1pars.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
asn1pars.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
asn1pars.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
asn1pars.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
asn1pars.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
asn1pars.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
asn1pars.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
asn1pars.bc: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
asn1pars.bc: ../include/openssl/sha.h ../include/openssl/stack.h
asn1pars.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
asn1pars.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
asn1pars.bc: ../include/openssl/x509v3.h apps.h asn1pars.c
ca.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ca.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ca.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ca.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ca.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ca.o: ../include/openssl/err.h ../include/openssl/evp.h
ca.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ca.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
ca.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ca.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ca.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ca.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ca.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ca.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
ca.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h ca.c
ca.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ca.bc: ../include/openssl/bn.h ../include/openssl/buffer.h
ca.bc: ../include/openssl/conf.h ../include/openssl/crypto.h
ca.bc: ../include/openssl/e_os2.h ../include/openssl/ec.h
ca.bc: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ca.bc: ../include/openssl/err.h ../include/openssl/evp.h
ca.bc: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ca.bc: ../include/openssl/objects.h ../include/openssl/ocsp.h
ca.bc: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ca.bc: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ca.bc: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ca.bc: ../include/openssl/safestack.h ../include/openssl/sha.h
ca.bc: ../include/openssl/stack.h ../include/openssl/symhacks.h
ca.bc: ../include/openssl/txt_db.h ../include/openssl/x509.h
ca.bc: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h ca.c
ciphers.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ciphers.o: ../include/openssl/buffer.h ../include/openssl/conf.h
ciphers.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
ciphers.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ciphers.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ciphers.o: ../include/openssl/err.h ../include/openssl/evp.h
ciphers.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
ciphers.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ciphers.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
ciphers.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ciphers.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ciphers.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ciphers.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
ciphers.o: ../include/openssl/sha.h ../include/openssl/srtp.h
ciphers.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ciphers.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
ciphers.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ciphers.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
ciphers.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ciphers.o: ../include/openssl/x509v3.h apps.h ciphers.c
ciphers.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ciphers.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
ciphers.bc: ../include/openssl/crypto.h ../include/openssl/dtls1.h
ciphers.bc: ../include/openssl/e_os2.h ../include/openssl/ec.h
ciphers.bc: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ciphers.bc: ../include/openssl/err.h ../include/openssl/evp.h
ciphers.bc: ../include/openssl/hmac.h ../include/openssl/kssl.h
ciphers.bc: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ciphers.bc: ../include/openssl/objects.h ../include/openssl/ocsp.h
ciphers.bc: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ciphers.bc: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ciphers.bc: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ciphers.bc: ../include/openssl/pqueue.h ../include/openssl/safestack.h
ciphers.bc: ../include/openssl/sha.h ../include/openssl/srtp.h
ciphers.bc: ../include/openssl/ssl.h ../include/openssl/ssl2.h
ciphers.bc: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
ciphers.bc: ../include/openssl/stack.h ../include/openssl/symhacks.h
ciphers.bc: ../include/openssl/tls1.h ../include/openssl/txt_db.h
ciphers.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ciphers.bc: ../include/openssl/x509v3.h apps.h ciphers.c
cms.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
cms.o: ../include/openssl/buffer.h ../include/openssl/cms.h
cms.o: ../include/openssl/conf.h ../include/openssl/crypto.h
cms.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
cms.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
cms.o: ../include/openssl/err.h ../include/openssl/evp.h
cms.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
cms.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
cms.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
cms.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
cms.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
cms.o: ../include/openssl/safestack.h ../include/openssl/sha.h
cms.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
cms.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
cms.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h cms.c
cms.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
cms.bc: ../include/openssl/buffer.h ../include/openssl/cms.h
cms.bc: ../include/openssl/conf.h ../include/openssl/crypto.h
cms.bc: ../include/openssl/e_os2.h ../include/openssl/ec.h
cms.bc: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
cms.bc: ../include/openssl/err.h ../include/openssl/evp.h
cms.bc: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
cms.bc: ../include/openssl/objects.h ../include/openssl/ocsp.h
cms.bc: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
cms.bc: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
cms.bc: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
cms.bc: ../include/openssl/safestack.h ../include/openssl/sha.h
cms.bc: ../include/openssl/stack.h ../include/openssl/symhacks.h
cms.bc: ../include/openssl/txt_db.h ../include/openssl/x509.h
cms.bc: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h cms.c
crl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
crl.o: ../include/openssl/buffer.h ../include/openssl/conf.h
crl.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
crl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
crl.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
crl.o: ../include/openssl/evp.h ../include/openssl/lhash.h
crl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
crl.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
crl.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
crl.o: ../include/openssl/pem.h ../include/openssl/pem2.h
crl.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
crl.o: ../include/openssl/sha.h ../include/openssl/stack.h
crl.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
crl.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
crl.o: ../include/openssl/x509v3.h apps.h crl.c
crl.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
crl.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
crl.bc: ../include/openssl/crypto.h ../include/openssl/e_os2.h
crl.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
crl.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
crl.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
crl.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
crl.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
crl.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
crl.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
crl.bc: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
crl.bc: ../include/openssl/sha.h ../include/openssl/stack.h
crl.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
crl.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
crl.bc: ../include/openssl/x509v3.h apps.h crl.c
crl2p7.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
crl2p7.o: ../include/openssl/buffer.h ../include/openssl/conf.h
crl2p7.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
crl2p7.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
crl2p7.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
crl2p7.o: ../include/openssl/evp.h ../include/openssl/lhash.h
crl2p7.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
crl2p7.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
crl2p7.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
crl2p7.o: ../include/openssl/pem.h ../include/openssl/pem2.h
crl2p7.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
crl2p7.o: ../include/openssl/sha.h ../include/openssl/stack.h
crl2p7.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
crl2p7.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
crl2p7.o: ../include/openssl/x509v3.h apps.h crl2p7.c
crl2p7.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
crl2p7.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
crl2p7.bc: ../include/openssl/crypto.h ../include/openssl/e_os2.h
crl2p7.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
crl2p7.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
crl2p7.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
crl2p7.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
crl2p7.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
crl2p7.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
crl2p7.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
crl2p7.bc: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
crl2p7.bc: ../include/openssl/sha.h ../include/openssl/stack.h
crl2p7.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
crl2p7.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
crl2p7.bc: ../include/openssl/x509v3.h apps.h crl2p7.c
dgst.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dgst.o: ../include/openssl/buffer.h ../include/openssl/conf.h
dgst.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
dgst.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
dgst.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
dgst.o: ../include/openssl/evp.h ../include/openssl/hmac.h
dgst.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
dgst.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
dgst.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
dgst.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
dgst.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
dgst.o: ../include/openssl/safestack.h ../include/openssl/sha.h
dgst.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
dgst.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
dgst.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h dgst.c
dgst.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dgst.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
dgst.bc: ../include/openssl/crypto.h ../include/openssl/e_os2.h
dgst.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
dgst.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
dgst.bc: ../include/openssl/evp.h ../include/openssl/hmac.h
dgst.bc: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
dgst.bc: ../include/openssl/objects.h ../include/openssl/ocsp.h
dgst.bc: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
dgst.bc: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
dgst.bc: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
dgst.bc: ../include/openssl/safestack.h ../include/openssl/sha.h
dgst.bc: ../include/openssl/stack.h ../include/openssl/symhacks.h
dgst.bc: ../include/openssl/txt_db.h ../include/openssl/x509.h
dgst.bc: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
dgst.bc: dgst.c
dh.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dh.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dh.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dh.o: ../include/openssl/dh.h ../include/openssl/e_os2.h
dh.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
dh.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
dh.o: ../include/openssl/evp.h ../include/openssl/lhash.h
dh.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
dh.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
dh.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dh.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dh.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
dh.o: ../include/openssl/sha.h ../include/openssl/stack.h
dh.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dh.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
dh.o: ../include/openssl/x509v3.h apps.h dh.c
dh.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dh.bc: ../include/openssl/bn.h ../include/openssl/buffer.h
dh.bc: ../include/openssl/conf.h ../include/openssl/crypto.h
dh.bc: ../include/openssl/dh.h ../include/openssl/e_os2.h
dh.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
dh.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
dh.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
dh.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
dh.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
dh.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dh.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
dh.bc: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
dh.bc: ../include/openssl/sha.h ../include/openssl/stack.h
dh.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dh.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
dh.bc: ../include/openssl/x509v3.h apps.h dh.c
dsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dsa.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
dsa.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
dsa.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
dsa.o: ../include/openssl/evp.h ../include/openssl/lhash.h
dsa.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
dsa.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
dsa.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dsa.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dsa.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
dsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
dsa.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dsa.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
dsa.o: ../include/openssl/x509v3.h apps.h dsa.c
dsa.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dsa.bc: ../include/openssl/bn.h ../include/openssl/buffer.h
dsa.bc: ../include/openssl/conf.h ../include/openssl/crypto.h
dsa.bc: ../include/openssl/dsa.h ../include/openssl/e_os2.h
dsa.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
dsa.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
dsa.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
dsa.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
dsa.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
dsa.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dsa.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
dsa.bc: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
dsa.bc: ../include/openssl/sha.h ../include/openssl/stack.h
dsa.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dsa.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
dsa.bc: ../include/openssl/x509v3.h apps.h dsa.c
dsaparam.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dsaparam.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dsaparam.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dsaparam.o: ../include/openssl/dh.h ../include/openssl/dsa.h
dsaparam.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
dsaparam.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
dsaparam.o: ../include/openssl/err.h ../include/openssl/evp.h
dsaparam.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
dsaparam.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
dsaparam.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
dsaparam.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
dsaparam.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
dsaparam.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
dsaparam.o: ../include/openssl/sha.h ../include/openssl/stack.h
dsaparam.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dsaparam.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
dsaparam.o: ../include/openssl/x509v3.h apps.h dsaparam.c
dsaparam.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dsaparam.bc: ../include/openssl/bn.h ../include/openssl/buffer.h
dsaparam.bc: ../include/openssl/conf.h ../include/openssl/crypto.h
dsaparam.bc: ../include/openssl/dh.h ../include/openssl/dsa.h
dsaparam.bc: ../include/openssl/e_os2.h ../include/openssl/ec.h
dsaparam.bc: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
dsaparam.bc: ../include/openssl/err.h ../include/openssl/evp.h
dsaparam.bc: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
dsaparam.bc: ../include/openssl/objects.h ../include/openssl/ocsp.h
dsaparam.bc: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
dsaparam.bc: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
dsaparam.bc: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
dsaparam.bc: ../include/openssl/rsa.h ../include/openssl/safestack.h
dsaparam.bc: ../include/openssl/sha.h ../include/openssl/stack.h
dsaparam.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
dsaparam.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
dsaparam.bc: ../include/openssl/x509v3.h apps.h dsaparam.c
ec.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ec.o: ../include/openssl/buffer.h ../include/openssl/conf.h
ec.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
ec.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ec.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
ec.o: ../include/openssl/evp.h ../include/openssl/lhash.h
ec.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ec.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ec.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ec.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ec.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
ec.o: ../include/openssl/sha.h ../include/openssl/stack.h
ec.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
ec.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ec.o: ../include/openssl/x509v3.h apps.h ec.c
ec.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ec.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
ec.bc: ../include/openssl/crypto.h ../include/openssl/e_os2.h
ec.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
ec.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
ec.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
ec.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ec.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ec.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ec.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
ec.bc: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
ec.bc: ../include/openssl/sha.h ../include/openssl/stack.h
ec.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
ec.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
ec.bc: ../include/openssl/x509v3.h apps.h ec.c
ecparam.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ecparam.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ecparam.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ecparam.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ecparam.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ecparam.o: ../include/openssl/err.h ../include/openssl/evp.h
ecparam.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ecparam.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
ecparam.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ecparam.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ecparam.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ecparam.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ecparam.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ecparam.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
ecparam.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
ecparam.o: ecparam.c
ecparam.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ecparam.bc: ../include/openssl/bn.h ../include/openssl/buffer.h
ecparam.bc: ../include/openssl/conf.h ../include/openssl/crypto.h
ecparam.bc: ../include/openssl/e_os2.h ../include/openssl/ec.h
ecparam.bc: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ecparam.bc: ../include/openssl/err.h ../include/openssl/evp.h
ecparam.bc: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ecparam.bc: ../include/openssl/objects.h ../include/openssl/ocsp.h
ecparam.bc: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ecparam.bc: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ecparam.bc: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ecparam.bc: ../include/openssl/safestack.h ../include/openssl/sha.h
ecparam.bc: ../include/openssl/stack.h ../include/openssl/symhacks.h
ecparam.bc: ../include/openssl/txt_db.h ../include/openssl/x509.h
ecparam.bc: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
ecparam.bc: ecparam.c
enc.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
enc.o: ../include/openssl/bio.h ../include/openssl/buffer.h
enc.o: ../include/openssl/conf.h ../include/openssl/crypto.h
enc.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
enc.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
enc.o: ../include/openssl/err.h ../include/openssl/evp.h
enc.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
enc.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
enc.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
enc.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
enc.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
enc.o: ../include/openssl/rand.h ../include/openssl/safestack.h
enc.o: ../include/openssl/sha.h ../include/openssl/stack.h
enc.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
enc.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
enc.o: ../include/openssl/x509v3.h apps.h enc.c
enc.bc: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
enc.bc: ../include/openssl/bio.h ../include/openssl/buffer.h
enc.bc: ../include/openssl/conf.h ../include/openssl/crypto.h
enc.bc: ../include/openssl/e_os2.h ../include/openssl/ec.h
enc.bc: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
enc.bc: ../include/openssl/err.h ../include/openssl/evp.h
enc.bc: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
enc.bc: ../include/openssl/objects.h ../include/openssl/ocsp.h
enc.bc: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
enc.bc: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
enc.bc: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
enc.bc: ../include/openssl/rand.h ../include/openssl/safestack.h
enc.bc: ../include/openssl/sha.h ../include/openssl/stack.h
enc.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
enc.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
enc.bc: ../include/openssl/x509v3.h apps.h enc.c
engine.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
engine.o: ../include/openssl/buffer.h ../include/openssl/conf.h
engine.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
engine.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
engine.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
engine.o: ../include/openssl/evp.h ../include/openssl/lhash.h
engine.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
engine.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
engine.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
engine.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
engine.o: ../include/openssl/sha.h ../include/openssl/stack.h
engine.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
engine.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
engine.o: ../include/openssl/x509v3.h apps.h engine.c
engine.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
engine.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
engine.bc: ../include/openssl/crypto.h ../include/openssl/e_os2.h
engine.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
engine.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
engine.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
engine.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
engine.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
engine.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
engine.bc: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
engine.bc: ../include/openssl/sha.h ../include/openssl/stack.h
engine.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
engine.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
engine.bc: ../include/openssl/x509v3.h apps.h engine.c
errstr.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
errstr.o: ../include/openssl/buffer.h ../include/openssl/conf.h
errstr.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
errstr.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
errstr.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
errstr.o: ../include/openssl/err.h ../include/openssl/evp.h
errstr.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
errstr.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
errstr.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
errstr.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
errstr.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
errstr.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
errstr.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
errstr.o: ../include/openssl/sha.h ../include/openssl/srtp.h
errstr.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
errstr.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
errstr.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
errstr.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
errstr.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
errstr.o: ../include/openssl/x509v3.h apps.h errstr.c
errstr.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
errstr.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
errstr.bc: ../include/openssl/crypto.h ../include/openssl/dtls1.h
errstr.bc: ../include/openssl/e_os2.h ../include/openssl/ec.h
errstr.bc: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
errstr.bc: ../include/openssl/err.h ../include/openssl/evp.h
errstr.bc: ../include/openssl/hmac.h ../include/openssl/kssl.h
errstr.bc: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
errstr.bc: ../include/openssl/objects.h ../include/openssl/ocsp.h
errstr.bc: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
errstr.bc: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
errstr.bc: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
errstr.bc: ../include/openssl/pqueue.h ../include/openssl/safestack.h
errstr.bc: ../include/openssl/sha.h ../include/openssl/srtp.h
errstr.bc: ../include/openssl/ssl.h ../include/openssl/ssl2.h
errstr.bc: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
errstr.bc: ../include/openssl/stack.h ../include/openssl/symhacks.h
errstr.bc: ../include/openssl/tls1.h ../include/openssl/txt_db.h
errstr.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
errstr.bc: ../include/openssl/x509v3.h apps.h errstr.c
gendh.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
gendh.o: ../include/openssl/bio.h ../include/openssl/bn.h
gendh.o: ../include/openssl/buffer.h ../include/openssl/conf.h
gendh.o: ../include/openssl/crypto.h ../include/openssl/dh.h
gendh.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
gendh.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
gendh.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
gendh.o: ../include/openssl/evp.h ../include/openssl/lhash.h
gendh.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
gendh.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
gendh.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
gendh.o: ../include/openssl/pem.h ../include/openssl/pem2.h
gendh.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
gendh.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
gendh.o: ../include/openssl/sha.h ../include/openssl/stack.h
gendh.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
gendh.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
gendh.o: ../include/openssl/x509v3.h apps.h gendh.c
gendh.bc: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
gendh.bc: ../include/openssl/bio.h ../include/openssl/bn.h
gendh.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
gendh.bc: ../include/openssl/crypto.h ../include/openssl/dh.h
gendh.bc: ../include/openssl/dsa.h ../include/openssl/e_os2.h
gendh.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
gendh.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
gendh.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
gendh.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
gendh.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
gendh.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
gendh.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
gendh.bc: ../include/openssl/pkcs7.h ../include/openssl/rand.h
gendh.bc: ../include/openssl/rsa.h ../include/openssl/safestack.h
gendh.bc: ../include/openssl/sha.h ../include/openssl/stack.h
gendh.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
gendh.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
gendh.bc: ../include/openssl/x509v3.h apps.h gendh.c
gendsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
gendsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
gendsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
gendsa.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
gendsa.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
gendsa.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
gendsa.o: ../include/openssl/evp.h ../include/openssl/lhash.h
gendsa.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
gendsa.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
gendsa.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
gendsa.o: ../include/openssl/pem.h ../include/openssl/pem2.h
gendsa.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
gendsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
gendsa.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
gendsa.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
gendsa.o: ../include/openssl/x509v3.h apps.h gendsa.c
gendsa.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
gendsa.bc: ../include/openssl/bn.h ../include/openssl/buffer.h
gendsa.bc: ../include/openssl/conf.h ../include/openssl/crypto.h
gendsa.bc: ../include/openssl/dsa.h ../include/openssl/e_os2.h
gendsa.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
gendsa.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
gendsa.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
gendsa.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
gendsa.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
gendsa.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
gendsa.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
gendsa.bc: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
gendsa.bc: ../include/openssl/sha.h ../include/openssl/stack.h
gendsa.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
gendsa.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
gendsa.bc: ../include/openssl/x509v3.h apps.h gendsa.c
genpkey.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
genpkey.o: ../include/openssl/buffer.h ../include/openssl/conf.h
genpkey.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
genpkey.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
genpkey.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
genpkey.o: ../include/openssl/evp.h ../include/openssl/lhash.h
genpkey.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
genpkey.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
genpkey.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
genpkey.o: ../include/openssl/pem.h ../include/openssl/pem2.h
genpkey.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
genpkey.o: ../include/openssl/sha.h ../include/openssl/stack.h
genpkey.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
genpkey.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
genpkey.o: ../include/openssl/x509v3.h apps.h genpkey.c
genpkey.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
genpkey.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
genpkey.bc: ../include/openssl/crypto.h ../include/openssl/e_os2.h
genpkey.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
genpkey.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
genpkey.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
genpkey.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
genpkey.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
genpkey.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
genpkey.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
genpkey.bc: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
genpkey.bc: ../include/openssl/sha.h ../include/openssl/stack.h
genpkey.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
genpkey.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
genpkey.bc: ../include/openssl/x509v3.h apps.h genpkey.c
genrsa.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
genrsa.o: ../include/openssl/bio.h ../include/openssl/bn.h
genrsa.o: ../include/openssl/buffer.h ../include/openssl/conf.h
genrsa.o: ../include/openssl/crypto.h ../include/openssl/dh.h
genrsa.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
genrsa.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
genrsa.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
genrsa.o: ../include/openssl/evp.h ../include/openssl/lhash.h
genrsa.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
genrsa.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
genrsa.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
genrsa.o: ../include/openssl/pem.h ../include/openssl/pem2.h
genrsa.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
genrsa.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
genrsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
genrsa.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
genrsa.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
genrsa.o: ../include/openssl/x509v3.h apps.h genrsa.c
genrsa.bc: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
genrsa.bc: ../include/openssl/bio.h ../include/openssl/bn.h
genrsa.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
genrsa.bc: ../include/openssl/crypto.h ../include/openssl/dh.h
genrsa.bc: ../include/openssl/dsa.h ../include/openssl/e_os2.h
genrsa.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
genrsa.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
genrsa.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
genrsa.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
genrsa.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
genrsa.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
genrsa.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
genrsa.bc: ../include/openssl/pkcs7.h ../include/openssl/rand.h
genrsa.bc: ../include/openssl/rsa.h ../include/openssl/safestack.h
genrsa.bc: ../include/openssl/sha.h ../include/openssl/stack.h
genrsa.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
genrsa.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
genrsa.bc: ../include/openssl/x509v3.h apps.h genrsa.c
nseq.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
nseq.o: ../include/openssl/buffer.h ../include/openssl/conf.h
nseq.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
nseq.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
nseq.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
nseq.o: ../include/openssl/evp.h ../include/openssl/lhash.h
nseq.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
nseq.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
nseq.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
nseq.o: ../include/openssl/pem.h ../include/openssl/pem2.h
nseq.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
nseq.o: ../include/openssl/sha.h ../include/openssl/stack.h
nseq.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
nseq.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
nseq.o: ../include/openssl/x509v3.h apps.h nseq.c
nseq.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
nseq.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
nseq.bc: ../include/openssl/crypto.h ../include/openssl/e_os2.h
nseq.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
nseq.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
nseq.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
nseq.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
nseq.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
nseq.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
nseq.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
nseq.bc: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
nseq.bc: ../include/openssl/sha.h ../include/openssl/stack.h
nseq.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
nseq.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
nseq.bc: ../include/openssl/x509v3.h apps.h nseq.c
ocsp.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ocsp.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ocsp.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ocsp.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ocsp.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ocsp.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
ocsp.o: ../include/openssl/evp.h ../include/openssl/hmac.h
ocsp.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
ocsp.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ocsp.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ocsp.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ocsp.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ocsp.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
ocsp.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ocsp.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ocsp.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ocsp.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ocsp.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ocsp.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
ocsp.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h ocsp.c
ocsp.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ocsp.bc: ../include/openssl/bn.h ../include/openssl/buffer.h
ocsp.bc: ../include/openssl/conf.h ../include/openssl/crypto.h
ocsp.bc: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
ocsp.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
ocsp.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
ocsp.bc: ../include/openssl/evp.h ../include/openssl/hmac.h
ocsp.bc: ../include/openssl/kssl.h ../include/openssl/lhash.h
ocsp.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ocsp.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ocsp.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ocsp.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
ocsp.bc: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
ocsp.bc: ../include/openssl/safestack.h ../include/openssl/sha.h
ocsp.bc: ../include/openssl/srtp.h ../include/openssl/ssl.h
ocsp.bc: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ocsp.bc: ../include/openssl/ssl3.h ../include/openssl/stack.h
ocsp.bc: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ocsp.bc: ../include/openssl/txt_db.h ../include/openssl/x509.h
ocsp.bc: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
ocsp.bc: ocsp.c
openssl.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
openssl.o: ../include/openssl/bio.h ../include/openssl/buffer.h
openssl.o: ../include/openssl/conf.h ../include/openssl/crypto.h
openssl.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
openssl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
openssl.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
openssl.o: ../include/openssl/evp.h ../include/openssl/hmac.h
openssl.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
openssl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
openssl.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
openssl.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
openssl.o: ../include/openssl/pem.h ../include/openssl/pem2.h
openssl.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
openssl.o: ../include/openssl/rand.h ../include/openssl/safestack.h
openssl.o: ../include/openssl/sha.h ../include/openssl/srtp.h
openssl.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
openssl.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
openssl.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
openssl.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
openssl.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
openssl.o: ../include/openssl/x509v3.h apps.h openssl.c progs.h s_apps.h
openssl.bc: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
openssl.bc: ../include/openssl/bio.h ../include/openssl/buffer.h
openssl.bc: ../include/openssl/conf.h ../include/openssl/crypto.h
openssl.bc: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
openssl.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
openssl.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
openssl.bc: ../include/openssl/evp.h ../include/openssl/hmac.h
openssl.bc: ../include/openssl/kssl.h ../include/openssl/lhash.h
openssl.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
openssl.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
openssl.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
openssl.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
openssl.bc: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
openssl.bc: ../include/openssl/rand.h ../include/openssl/safestack.h
openssl.bc: ../include/openssl/sha.h ../include/openssl/srtp.h
openssl.bc: ../include/openssl/ssl.h ../include/openssl/ssl2.h
openssl.bc: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
openssl.bc: ../include/openssl/stack.h ../include/openssl/symhacks.h
openssl.bc: ../include/openssl/tls1.h ../include/openssl/txt_db.h
openssl.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
openssl.bc: ../include/openssl/x509v3.h apps.h openssl.c progs.h s_apps.h
passwd.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
passwd.o: ../include/openssl/bio.h ../include/openssl/buffer.h
passwd.o: ../include/openssl/conf.h ../include/openssl/crypto.h
passwd.o: ../include/openssl/des.h ../include/openssl/des_old.h
passwd.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
passwd.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
passwd.o: ../include/openssl/err.h ../include/openssl/evp.h
passwd.o: ../include/openssl/lhash.h ../include/openssl/md5.h
passwd.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
passwd.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
passwd.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
passwd.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
passwd.o: ../include/openssl/safestack.h ../include/openssl/sha.h
passwd.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
passwd.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
passwd.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
passwd.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
passwd.o: passwd.c
passwd.bc: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
passwd.bc: ../include/openssl/bio.h ../include/openssl/buffer.h
passwd.bc: ../include/openssl/conf.h ../include/openssl/crypto.h
passwd.bc: ../include/openssl/des.h ../include/openssl/des_old.h
passwd.bc: ../include/openssl/e_os2.h ../include/openssl/ec.h
passwd.bc: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
passwd.bc: ../include/openssl/err.h ../include/openssl/evp.h
passwd.bc: ../include/openssl/lhash.h ../include/openssl/md5.h
passwd.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
passwd.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
passwd.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
passwd.bc: ../include/openssl/pkcs7.h ../include/openssl/rand.h
passwd.bc: ../include/openssl/safestack.h ../include/openssl/sha.h
passwd.bc: ../include/openssl/stack.h ../include/openssl/symhacks.h
passwd.bc: ../include/openssl/txt_db.h ../include/openssl/ui.h
passwd.bc: ../include/openssl/ui_compat.h ../include/openssl/x509.h
passwd.bc: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
passwd.bc: passwd.c
pkcs12.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs12.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkcs12.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkcs12.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs12.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkcs12.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkcs12.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkcs12.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkcs12.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkcs12.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkcs12.o: ../include/openssl/pkcs12.h ../include/openssl/pkcs7.h
pkcs12.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkcs12.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkcs12.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
pkcs12.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
pkcs12.o: pkcs12.c
pkcs12.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs12.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
pkcs12.bc: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkcs12.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs12.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkcs12.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
pkcs12.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkcs12.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkcs12.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkcs12.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
pkcs12.bc: ../include/openssl/pkcs12.h ../include/openssl/pkcs7.h
pkcs12.bc: ../include/openssl/safestack.h ../include/openssl/sha.h
pkcs12.bc: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkcs12.bc: ../include/openssl/txt_db.h ../include/openssl/x509.h
pkcs12.bc: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
pkcs12.bc: pkcs12.c
pkcs7.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs7.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkcs7.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkcs7.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs7.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkcs7.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkcs7.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkcs7.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkcs7.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkcs7.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkcs7.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkcs7.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkcs7.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkcs7.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
pkcs7.o: ../include/openssl/x509v3.h apps.h pkcs7.c
pkcs7.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs7.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
pkcs7.bc: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkcs7.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs7.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkcs7.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
pkcs7.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkcs7.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkcs7.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkcs7.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
pkcs7.bc: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkcs7.bc: ../include/openssl/sha.h ../include/openssl/stack.h
pkcs7.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkcs7.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
pkcs7.bc: ../include/openssl/x509v3.h apps.h pkcs7.c
pkcs8.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs8.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkcs8.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkcs8.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs8.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkcs8.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkcs8.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkcs8.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkcs8.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkcs8.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkcs8.o: ../include/openssl/pkcs12.h ../include/openssl/pkcs7.h
pkcs8.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkcs8.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkcs8.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
pkcs8.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
pkcs8.o: pkcs8.c
pkcs8.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs8.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
pkcs8.bc: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkcs8.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs8.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkcs8.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
pkcs8.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkcs8.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkcs8.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkcs8.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
pkcs8.bc: ../include/openssl/pkcs12.h ../include/openssl/pkcs7.h
pkcs8.bc: ../include/openssl/safestack.h ../include/openssl/sha.h
pkcs8.bc: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkcs8.bc: ../include/openssl/txt_db.h ../include/openssl/x509.h
pkcs8.bc: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
pkcs8.bc: pkcs8.c
pkey.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkey.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkey.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkey.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkey.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkey.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkey.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkey.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkey.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkey.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkey.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkey.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkey.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkey.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
pkey.o: ../include/openssl/x509v3.h apps.h pkey.c
pkey.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkey.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
pkey.bc: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkey.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkey.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkey.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
pkey.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkey.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkey.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkey.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
pkey.bc: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkey.bc: ../include/openssl/sha.h ../include/openssl/stack.h
pkey.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkey.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
pkey.bc: ../include/openssl/x509v3.h apps.h pkey.c
pkeyparam.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkeyparam.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkeyparam.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkeyparam.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkeyparam.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkeyparam.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkeyparam.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkeyparam.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkeyparam.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkeyparam.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkeyparam.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkeyparam.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkeyparam.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkeyparam.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
pkeyparam.o: ../include/openssl/x509v3.h apps.h pkeyparam.c
pkeyparam.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkeyparam.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
pkeyparam.bc: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkeyparam.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkeyparam.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkeyparam.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
pkeyparam.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkeyparam.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkeyparam.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkeyparam.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
pkeyparam.bc: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkeyparam.bc: ../include/openssl/sha.h ../include/openssl/stack.h
pkeyparam.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkeyparam.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
pkeyparam.bc: ../include/openssl/x509v3.h apps.h pkeyparam.c
pkeyutl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkeyutl.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkeyutl.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkeyutl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkeyutl.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkeyutl.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkeyutl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkeyutl.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkeyutl.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkeyutl.o: ../include/openssl/pem.h ../include/openssl/pem2.h
pkeyutl.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkeyutl.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkeyutl.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkeyutl.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
pkeyutl.o: ../include/openssl/x509v3.h apps.h pkeyutl.c
pkeyutl.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkeyutl.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
pkeyutl.bc: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkeyutl.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkeyutl.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkeyutl.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
pkeyutl.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkeyutl.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
pkeyutl.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
pkeyutl.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
pkeyutl.bc: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkeyutl.bc: ../include/openssl/sha.h ../include/openssl/stack.h
pkeyutl.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
pkeyutl.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
pkeyutl.bc: ../include/openssl/x509v3.h apps.h pkeyutl.c
prime.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
prime.o: ../include/openssl/bn.h ../include/openssl/buffer.h
prime.o: ../include/openssl/conf.h ../include/openssl/crypto.h
prime.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
prime.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
prime.o: ../include/openssl/evp.h ../include/openssl/lhash.h
prime.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
prime.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
prime.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
prime.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
prime.o: ../include/openssl/sha.h ../include/openssl/stack.h
prime.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
prime.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
prime.o: ../include/openssl/x509v3.h apps.h prime.c
prime.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
prime.bc: ../include/openssl/bn.h ../include/openssl/buffer.h
prime.bc: ../include/openssl/conf.h ../include/openssl/crypto.h
prime.bc: ../include/openssl/e_os2.h ../include/openssl/ec.h
prime.bc: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
prime.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
prime.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
prime.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
prime.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
prime.bc: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
prime.bc: ../include/openssl/sha.h ../include/openssl/stack.h
prime.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
prime.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
prime.bc: ../include/openssl/x509v3.h apps.h prime.c
rand.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
rand.o: ../include/openssl/bio.h ../include/openssl/buffer.h
rand.o: ../include/openssl/conf.h ../include/openssl/crypto.h
rand.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
rand.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
rand.o: ../include/openssl/err.h ../include/openssl/evp.h
rand.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
rand.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
rand.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
rand.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
rand.o: ../include/openssl/rand.h ../include/openssl/safestack.h
rand.o: ../include/openssl/sha.h ../include/openssl/stack.h
rand.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
rand.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
rand.o: ../include/openssl/x509v3.h apps.h rand.c
rand.bc: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
rand.bc: ../include/openssl/bio.h ../include/openssl/buffer.h
rand.bc: ../include/openssl/conf.h ../include/openssl/crypto.h
rand.bc: ../include/openssl/e_os2.h ../include/openssl/ec.h
rand.bc: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
rand.bc: ../include/openssl/err.h ../include/openssl/evp.h
rand.bc: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
rand.bc: ../include/openssl/objects.h ../include/openssl/ocsp.h
rand.bc: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
rand.bc: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
rand.bc: ../include/openssl/rand.h ../include/openssl/safestack.h
rand.bc: ../include/openssl/sha.h ../include/openssl/stack.h
rand.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
rand.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
rand.bc: ../include/openssl/x509v3.h apps.h rand.c
req.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
req.o: ../include/openssl/bn.h ../include/openssl/buffer.h
req.o: ../include/openssl/conf.h ../include/openssl/crypto.h
req.o: ../include/openssl/dh.h ../include/openssl/dsa.h
req.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
req.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
req.o: ../include/openssl/err.h ../include/openssl/evp.h
req.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
req.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
req.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
req.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
req.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
req.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
req.o: ../include/openssl/sha.h ../include/openssl/stack.h
req.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
req.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
req.o: ../include/openssl/x509v3.h apps.h req.c
req.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
req.bc: ../include/openssl/bn.h ../include/openssl/buffer.h
req.bc: ../include/openssl/conf.h ../include/openssl/crypto.h
req.bc: ../include/openssl/dh.h ../include/openssl/dsa.h
req.bc: ../include/openssl/e_os2.h ../include/openssl/ec.h
req.bc: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
req.bc: ../include/openssl/err.h ../include/openssl/evp.h
req.bc: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
req.bc: ../include/openssl/objects.h ../include/openssl/ocsp.h
req.bc: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
req.bc: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
req.bc: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
req.bc: ../include/openssl/rsa.h ../include/openssl/safestack.h
req.bc: ../include/openssl/sha.h ../include/openssl/stack.h
req.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
req.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
req.bc: ../include/openssl/x509v3.h apps.h req.c
rsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
rsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
rsa.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
rsa.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
rsa.o: ../include/openssl/err.h ../include/openssl/evp.h
rsa.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
rsa.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
rsa.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
rsa.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
rsa.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
rsa.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
rsa.o: ../include/openssl/sha.h ../include/openssl/stack.h
rsa.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
rsa.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
rsa.o: ../include/openssl/x509v3.h apps.h rsa.c
rsa.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rsa.bc: ../include/openssl/bn.h ../include/openssl/buffer.h
rsa.bc: ../include/openssl/conf.h ../include/openssl/crypto.h
rsa.bc: ../include/openssl/e_os2.h ../include/openssl/ec.h
rsa.bc: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
rsa.bc: ../include/openssl/err.h ../include/openssl/evp.h
rsa.bc: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
rsa.bc: ../include/openssl/objects.h ../include/openssl/ocsp.h
rsa.bc: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
rsa.bc: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
rsa.bc: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
rsa.bc: ../include/openssl/rsa.h ../include/openssl/safestack.h
rsa.bc: ../include/openssl/sha.h ../include/openssl/stack.h
rsa.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
rsa.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
rsa.bc: ../include/openssl/x509v3.h apps.h rsa.c
rsautl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rsautl.o: ../include/openssl/buffer.h ../include/openssl/conf.h
rsautl.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
rsautl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
rsautl.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
rsautl.o: ../include/openssl/evp.h ../include/openssl/lhash.h
rsautl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
rsautl.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
rsautl.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
rsautl.o: ../include/openssl/pem.h ../include/openssl/pem2.h
rsautl.o: ../include/openssl/pkcs7.h ../include/openssl/rsa.h
rsautl.o: ../include/openssl/safestack.h ../include/openssl/sha.h
rsautl.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
rsautl.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
rsautl.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
rsautl.o: rsautl.c
rsautl.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rsautl.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
rsautl.bc: ../include/openssl/crypto.h ../include/openssl/e_os2.h
rsautl.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
rsautl.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
rsautl.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
rsautl.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
rsautl.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
rsautl.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
rsautl.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
rsautl.bc: ../include/openssl/pkcs7.h ../include/openssl/rsa.h
rsautl.bc: ../include/openssl/safestack.h ../include/openssl/sha.h
rsautl.bc: ../include/openssl/stack.h ../include/openssl/symhacks.h
rsautl.bc: ../include/openssl/txt_db.h ../include/openssl/x509.h
rsautl.bc: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
rsautl.bc: rsautl.c
s_cb.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
s_cb.o: ../include/openssl/bio.h ../include/openssl/buffer.h
s_cb.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_cb.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s_cb.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s_cb.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
s_cb.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s_cb.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s_cb.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_cb.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
s_cb.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_cb.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_cb.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
s_cb.o: ../include/openssl/rand.h ../include/openssl/safestack.h
s_cb.o: ../include/openssl/sha.h ../include/openssl/srtp.h
s_cb.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_cb.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s_cb.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_cb.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_cb.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s_cb.o: ../include/openssl/x509v3.h apps.h s_apps.h s_cb.c
s_cb.bc: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
s_cb.bc: ../include/openssl/bio.h ../include/openssl/buffer.h
s_cb.bc: ../include/openssl/conf.h ../include/openssl/crypto.h
s_cb.bc: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s_cb.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
s_cb.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
s_cb.bc: ../include/openssl/evp.h ../include/openssl/hmac.h
s_cb.bc: ../include/openssl/kssl.h ../include/openssl/lhash.h
s_cb.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_cb.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
s_cb.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_cb.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
s_cb.bc: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
s_cb.bc: ../include/openssl/rand.h ../include/openssl/safestack.h
s_cb.bc: ../include/openssl/sha.h ../include/openssl/srtp.h
s_cb.bc: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_cb.bc: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s_cb.bc: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_cb.bc: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_cb.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s_cb.bc: ../include/openssl/x509v3.h apps.h s_apps.h s_cb.c
s_client.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
s_client.o: ../include/openssl/bio.h ../include/openssl/bn.h
s_client.o: ../include/openssl/buffer.h ../include/openssl/conf.h
s_client.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
s_client.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_client.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_client.o: ../include/openssl/err.h ../include/openssl/evp.h
s_client.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
s_client.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s_client.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
s_client.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_client.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_client.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_client.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
s_client.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_client.o: ../include/openssl/srp.h ../include/openssl/srtp.h
s_client.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_client.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s_client.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_client.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_client.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s_client.o: ../include/openssl/x509v3.h apps.h s_apps.h s_client.c timeouts.h
s_client.bc: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
s_client.bc: ../include/openssl/bio.h ../include/openssl/bn.h
s_client.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
s_client.bc: ../include/openssl/crypto.h ../include/openssl/dtls1.h
s_client.bc: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_client.bc: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_client.bc: ../include/openssl/err.h ../include/openssl/evp.h
s_client.bc: ../include/openssl/hmac.h ../include/openssl/kssl.h
s_client.bc: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s_client.bc: ../include/openssl/objects.h ../include/openssl/ocsp.h
s_client.bc: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_client.bc: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_client.bc: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_client.bc: ../include/openssl/pqueue.h ../include/openssl/rand.h
s_client.bc: ../include/openssl/safestack.h ../include/openssl/sha.h
s_client.bc: ../include/openssl/srp.h ../include/openssl/srtp.h
s_client.bc: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_client.bc: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s_client.bc: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_client.bc: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_client.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s_client.bc: ../include/openssl/x509v3.h apps.h s_apps.h s_client.c timeouts.h
s_server.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
s_server.o: ../include/openssl/bio.h ../include/openssl/bn.h
s_server.o: ../include/openssl/buffer.h ../include/openssl/conf.h
s_server.o: ../include/openssl/crypto.h ../include/openssl/dh.h
s_server.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
s_server.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_server.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_server.o: ../include/openssl/err.h ../include/openssl/evp.h
s_server.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
s_server.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s_server.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
s_server.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_server.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_server.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_server.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
s_server.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
s_server.o: ../include/openssl/sha.h ../include/openssl/srp.h
s_server.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s_server.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s_server.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_server.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_server.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
s_server.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
s_server.o: s_apps.h s_server.c timeouts.h
s_server.bc: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
s_server.bc: ../include/openssl/bio.h ../include/openssl/bn.h
s_server.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
s_server.bc: ../include/openssl/crypto.h ../include/openssl/dh.h
s_server.bc: ../include/openssl/dsa.h ../include/openssl/dtls1.h
s_server.bc: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_server.bc: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_server.bc: ../include/openssl/err.h ../include/openssl/evp.h
s_server.bc: ../include/openssl/hmac.h ../include/openssl/kssl.h
s_server.bc: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s_server.bc: ../include/openssl/objects.h ../include/openssl/ocsp.h
s_server.bc: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_server.bc: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_server.bc: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_server.bc: ../include/openssl/pqueue.h ../include/openssl/rand.h
s_server.bc: ../include/openssl/rsa.h ../include/openssl/safestack.h
s_server.bc: ../include/openssl/sha.h ../include/openssl/srp.h
s_server.bc: ../include/openssl/srtp.h ../include/openssl/ssl.h
s_server.bc: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s_server.bc: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_server.bc: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_server.bc: ../include/openssl/txt_db.h ../include/openssl/x509.h
s_server.bc: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
s_server.bc: s_apps.h s_server.c timeouts.h
s_socket.o: ../e_os.h ../e_os2.h ../include/openssl/KTest.h
s_socket.o: ../include/openssl/asn1.h ../include/openssl/bio.h
s_socket.o: ../include/openssl/buffer.h ../include/openssl/conf.h
s_socket.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
s_socket.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_socket.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_socket.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s_socket.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s_socket.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_socket.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
s_socket.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_socket.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_socket.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
s_socket.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_socket.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s_socket.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s_socket.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_socket.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_socket.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
s_socket.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
s_socket.o: s_apps.h s_socket.c
s_socket.bc: ../e_os.h ../e_os2.h ../include/openssl/KTest.h
s_socket.bc: ../include/openssl/asn1.h ../include/openssl/bio.h
s_socket.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
s_socket.bc: ../include/openssl/crypto.h ../include/openssl/dtls1.h
s_socket.bc: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_socket.bc: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_socket.bc: ../include/openssl/evp.h ../include/openssl/hmac.h
s_socket.bc: ../include/openssl/kssl.h ../include/openssl/lhash.h
s_socket.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_socket.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
s_socket.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_socket.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
s_socket.bc: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
s_socket.bc: ../include/openssl/safestack.h ../include/openssl/sha.h
s_socket.bc: ../include/openssl/srtp.h ../include/openssl/ssl.h
s_socket.bc: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s_socket.bc: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_socket.bc: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_socket.bc: ../include/openssl/txt_db.h ../include/openssl/x509.h
s_socket.bc: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
s_socket.bc: s_apps.h s_socket.c
s_time.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s_time.o: ../include/openssl/buffer.h ../include/openssl/conf.h
s_time.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
s_time.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_time.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_time.o: ../include/openssl/err.h ../include/openssl/evp.h
s_time.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
s_time.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s_time.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
s_time.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_time.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_time.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_time.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
s_time.o: ../include/openssl/sha.h ../include/openssl/srtp.h
s_time.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_time.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s_time.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_time.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_time.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s_time.o: ../include/openssl/x509v3.h apps.h s_apps.h s_time.c
s_time.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s_time.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
s_time.bc: ../include/openssl/crypto.h ../include/openssl/dtls1.h
s_time.bc: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_time.bc: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_time.bc: ../include/openssl/err.h ../include/openssl/evp.h
s_time.bc: ../include/openssl/hmac.h ../include/openssl/kssl.h
s_time.bc: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s_time.bc: ../include/openssl/objects.h ../include/openssl/ocsp.h
s_time.bc: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_time.bc: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_time.bc: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_time.bc: ../include/openssl/pqueue.h ../include/openssl/safestack.h
s_time.bc: ../include/openssl/sha.h ../include/openssl/srtp.h
s_time.bc: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_time.bc: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s_time.bc: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_time.bc: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_time.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
s_time.bc: ../include/openssl/x509v3.h apps.h s_apps.h s_time.c
sess_id.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
sess_id.o: ../include/openssl/buffer.h ../include/openssl/conf.h
sess_id.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
sess_id.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
sess_id.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
sess_id.o: ../include/openssl/err.h ../include/openssl/evp.h
sess_id.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
sess_id.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
sess_id.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
sess_id.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
sess_id.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
sess_id.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
sess_id.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
sess_id.o: ../include/openssl/sha.h ../include/openssl/srtp.h
sess_id.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
sess_id.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
sess_id.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
sess_id.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
sess_id.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
sess_id.o: ../include/openssl/x509v3.h apps.h sess_id.c
sess_id.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
sess_id.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
sess_id.bc: ../include/openssl/crypto.h ../include/openssl/dtls1.h
sess_id.bc: ../include/openssl/e_os2.h ../include/openssl/ec.h
sess_id.bc: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
sess_id.bc: ../include/openssl/err.h ../include/openssl/evp.h
sess_id.bc: ../include/openssl/hmac.h ../include/openssl/kssl.h
sess_id.bc: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
sess_id.bc: ../include/openssl/objects.h ../include/openssl/ocsp.h
sess_id.bc: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
sess_id.bc: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
sess_id.bc: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
sess_id.bc: ../include/openssl/pqueue.h ../include/openssl/safestack.h
sess_id.bc: ../include/openssl/sha.h ../include/openssl/srtp.h
sess_id.bc: ../include/openssl/ssl.h ../include/openssl/ssl2.h
sess_id.bc: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
sess_id.bc: ../include/openssl/stack.h ../include/openssl/symhacks.h
sess_id.bc: ../include/openssl/tls1.h ../include/openssl/txt_db.h
sess_id.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
sess_id.bc: ../include/openssl/x509v3.h apps.h sess_id.c
smime.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
smime.o: ../include/openssl/buffer.h ../include/openssl/conf.h
smime.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
smime.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
smime.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
smime.o: ../include/openssl/evp.h ../include/openssl/lhash.h
smime.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
smime.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
smime.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
smime.o: ../include/openssl/pem.h ../include/openssl/pem2.h
smime.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
smime.o: ../include/openssl/sha.h ../include/openssl/stack.h
smime.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
smime.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
smime.o: ../include/openssl/x509v3.h apps.h smime.c
smime.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
smime.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
smime.bc: ../include/openssl/crypto.h ../include/openssl/e_os2.h
smime.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
smime.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
smime.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
smime.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
smime.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
smime.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
smime.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
smime.bc: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
smime.bc: ../include/openssl/sha.h ../include/openssl/stack.h
smime.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
smime.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
smime.bc: ../include/openssl/x509v3.h apps.h smime.c
speed.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/aes.h
speed.o: ../include/openssl/asn1.h ../include/openssl/bio.h
speed.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
speed.o: ../include/openssl/buffer.h ../include/openssl/camellia.h
speed.o: ../include/openssl/conf.h ../include/openssl/crypto.h
speed.o: ../include/openssl/des.h ../include/openssl/des_old.h
speed.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
speed.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
speed.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
speed.o: ../include/openssl/evp.h ../include/openssl/hmac.h
speed.o: ../include/openssl/idea.h ../include/openssl/lhash.h
speed.o: ../include/openssl/md5.h ../include/openssl/modes.h
speed.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
speed.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
speed.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
speed.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
speed.o: ../include/openssl/rc2.h ../include/openssl/rc4.h
speed.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
speed.o: ../include/openssl/seed.h ../include/openssl/sha.h
speed.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
speed.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
speed.o: ../include/openssl/ui_compat.h ../include/openssl/whrlpool.h
speed.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
speed.o: ../include/openssl/x509v3.h apps.h speed.c testdsa.h testrsa.h
speed.bc: ../e_os.h ../include/openssl/KTest.h ../include/openssl/aes.h
speed.bc: ../include/openssl/asn1.h ../include/openssl/bio.h
speed.bc: ../include/openssl/blowfish.h ../include/openssl/bn.h
speed.bc: ../include/openssl/buffer.h ../include/openssl/camellia.h
speed.bc: ../include/openssl/conf.h ../include/openssl/crypto.h
speed.bc: ../include/openssl/des.h ../include/openssl/des_old.h
speed.bc: ../include/openssl/dsa.h ../include/openssl/e_os2.h
speed.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
speed.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
speed.bc: ../include/openssl/evp.h ../include/openssl/hmac.h
speed.bc: ../include/openssl/idea.h ../include/openssl/lhash.h
speed.bc: ../include/openssl/md5.h ../include/openssl/modes.h
speed.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
speed.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
speed.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
speed.bc: ../include/openssl/pkcs7.h ../include/openssl/rand.h
speed.bc: ../include/openssl/rc2.h ../include/openssl/rc4.h
speed.bc: ../include/openssl/rsa.h ../include/openssl/safestack.h
speed.bc: ../include/openssl/seed.h ../include/openssl/sha.h
speed.bc: ../include/openssl/stack.h ../include/openssl/symhacks.h
speed.bc: ../include/openssl/txt_db.h ../include/openssl/ui.h
speed.bc: ../include/openssl/ui_compat.h ../include/openssl/whrlpool.h
speed.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
speed.bc: ../include/openssl/x509v3.h apps.h speed.c testdsa.h testrsa.h
spkac.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
spkac.o: ../include/openssl/buffer.h ../include/openssl/conf.h
spkac.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
spkac.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
spkac.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
spkac.o: ../include/openssl/evp.h ../include/openssl/lhash.h
spkac.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
spkac.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
spkac.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
spkac.o: ../include/openssl/pem.h ../include/openssl/pem2.h
spkac.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
spkac.o: ../include/openssl/sha.h ../include/openssl/stack.h
spkac.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
spkac.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
spkac.o: ../include/openssl/x509v3.h apps.h spkac.c
spkac.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
spkac.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
spkac.bc: ../include/openssl/crypto.h ../include/openssl/e_os2.h
spkac.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
spkac.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
spkac.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
spkac.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
spkac.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
spkac.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
spkac.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
spkac.bc: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
spkac.bc: ../include/openssl/sha.h ../include/openssl/stack.h
spkac.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
spkac.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
spkac.bc: ../include/openssl/x509v3.h apps.h spkac.c
srp.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
srp.o: ../include/openssl/bn.h ../include/openssl/buffer.h
srp.o: ../include/openssl/conf.h ../include/openssl/crypto.h
srp.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
srp.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
srp.o: ../include/openssl/err.h ../include/openssl/evp.h
srp.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
srp.o: ../include/openssl/objects.h ../include/openssl/ocsp.h
srp.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
srp.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
srp.o: ../include/openssl/safestack.h ../include/openssl/sha.h
srp.o: ../include/openssl/srp.h ../include/openssl/stack.h
srp.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
srp.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
srp.o: ../include/openssl/x509v3.h apps.h srp.c
srp.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
srp.bc: ../include/openssl/bn.h ../include/openssl/buffer.h
srp.bc: ../include/openssl/conf.h ../include/openssl/crypto.h
srp.bc: ../include/openssl/e_os2.h ../include/openssl/ec.h
srp.bc: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
srp.bc: ../include/openssl/err.h ../include/openssl/evp.h
srp.bc: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
srp.bc: ../include/openssl/objects.h ../include/openssl/ocsp.h
srp.bc: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
srp.bc: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
srp.bc: ../include/openssl/safestack.h ../include/openssl/sha.h
srp.bc: ../include/openssl/srp.h ../include/openssl/stack.h
srp.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
srp.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
srp.bc: ../include/openssl/x509v3.h apps.h srp.c
ts.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
ts.o: ../include/openssl/bio.h ../include/openssl/bn.h
ts.o: ../include/openssl/buffer.h ../include/openssl/conf.h
ts.o: ../include/openssl/crypto.h ../include/openssl/dh.h
ts.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
ts.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ts.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
ts.o: ../include/openssl/evp.h ../include/openssl/lhash.h
ts.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ts.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ts.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ts.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ts.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
ts.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
ts.o: ../include/openssl/sha.h ../include/openssl/stack.h
ts.o: ../include/openssl/symhacks.h ../include/openssl/ts.h
ts.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
ts.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h ts.c
ts.bc: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
ts.bc: ../include/openssl/bio.h ../include/openssl/bn.h
ts.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
ts.bc: ../include/openssl/crypto.h ../include/openssl/dh.h
ts.bc: ../include/openssl/dsa.h ../include/openssl/e_os2.h
ts.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
ts.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
ts.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
ts.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ts.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
ts.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ts.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
ts.bc: ../include/openssl/pkcs7.h ../include/openssl/rand.h
ts.bc: ../include/openssl/rsa.h ../include/openssl/safestack.h
ts.bc: ../include/openssl/sha.h ../include/openssl/stack.h
ts.bc: ../include/openssl/symhacks.h ../include/openssl/ts.h
ts.bc: ../include/openssl/txt_db.h ../include/openssl/x509.h
ts.bc: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h ts.c
verify.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
verify.o: ../include/openssl/buffer.h ../include/openssl/conf.h
verify.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
verify.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
verify.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
verify.o: ../include/openssl/evp.h ../include/openssl/lhash.h
verify.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
verify.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
verify.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
verify.o: ../include/openssl/pem.h ../include/openssl/pem2.h
verify.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
verify.o: ../include/openssl/sha.h ../include/openssl/stack.h
verify.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
verify.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
verify.o: ../include/openssl/x509v3.h apps.h verify.c
verify.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
verify.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
verify.bc: ../include/openssl/crypto.h ../include/openssl/e_os2.h
verify.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
verify.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
verify.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
verify.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
verify.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
verify.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
verify.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
verify.bc: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
verify.bc: ../include/openssl/sha.h ../include/openssl/stack.h
verify.bc: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
verify.bc: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
verify.bc: ../include/openssl/x509v3.h apps.h verify.c
version.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
version.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
version.o: ../include/openssl/buffer.h ../include/openssl/conf.h
version.o: ../include/openssl/crypto.h ../include/openssl/des.h
version.o: ../include/openssl/des_old.h ../include/openssl/e_os2.h
version.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
version.o: ../include/openssl/ecdsa.h ../include/openssl/evp.h
version.o: ../include/openssl/idea.h ../include/openssl/lhash.h
version.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
version.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
version.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
version.o: ../include/openssl/pkcs7.h ../include/openssl/rc4.h
version.o: ../include/openssl/safestack.h ../include/openssl/sha.h
version.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
version.o: ../include/openssl/txt_db.h ../include/openssl/ui.h
version.o: ../include/openssl/ui_compat.h ../include/openssl/x509.h
version.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
version.o: version.c
version.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
version.bc: ../include/openssl/blowfish.h ../include/openssl/bn.h
version.bc: ../include/openssl/buffer.h ../include/openssl/conf.h
version.bc: ../include/openssl/crypto.h ../include/openssl/des.h
version.bc: ../include/openssl/des_old.h ../include/openssl/e_os2.h
version.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
version.bc: ../include/openssl/ecdsa.h ../include/openssl/evp.h
version.bc: ../include/openssl/idea.h ../include/openssl/lhash.h
version.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
version.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
version.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
version.bc: ../include/openssl/pkcs7.h ../include/openssl/rc4.h
version.bc: ../include/openssl/safestack.h ../include/openssl/sha.h
version.bc: ../include/openssl/stack.h ../include/openssl/symhacks.h
version.bc: ../include/openssl/txt_db.h ../include/openssl/ui.h
version.bc: ../include/openssl/ui_compat.h ../include/openssl/x509.h
version.bc: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
version.bc: version.c
x509.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
x509.o: ../include/openssl/bn.h ../include/openssl/buffer.h
x509.o: ../include/openssl/conf.h ../include/openssl/crypto.h
x509.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
x509.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
x509.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
x509.o: ../include/openssl/evp.h ../include/openssl/lhash.h
x509.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
x509.o: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
x509.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
x509.o: ../include/openssl/pem.h ../include/openssl/pem2.h
x509.o: ../include/openssl/pkcs7.h ../include/openssl/rsa.h
x509.o: ../include/openssl/safestack.h ../include/openssl/sha.h
x509.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
x509.o: ../include/openssl/txt_db.h ../include/openssl/x509.h
x509.o: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h x509.c
x509.bc: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
x509.bc: ../include/openssl/bn.h ../include/openssl/buffer.h
x509.bc: ../include/openssl/conf.h ../include/openssl/crypto.h
x509.bc: ../include/openssl/dsa.h ../include/openssl/e_os2.h
x509.bc: ../include/openssl/ec.h ../include/openssl/ecdh.h
x509.bc: ../include/openssl/ecdsa.h ../include/openssl/err.h
x509.bc: ../include/openssl/evp.h ../include/openssl/lhash.h
x509.bc: ../include/openssl/obj_mac.h ../include/openssl/objects.h
x509.bc: ../include/openssl/ocsp.h ../include/openssl/opensslconf.h
x509.bc: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
x509.bc: ../include/openssl/pem.h ../include/openssl/pem2.h
x509.bc: ../include/openssl/pkcs7.h ../include/openssl/rsa.h
x509.bc: ../include/openssl/safestack.h ../include/openssl/sha.h
x509.bc: ../include/openssl/stack.h ../include/openssl/symhacks.h
x509.bc: ../include/openssl/txt_db.h ../include/openssl/x509.h
x509.bc: ../include/openssl/x509_vfy.h ../include/openssl/x509v3.h apps.h
x509.bc: x509.c
