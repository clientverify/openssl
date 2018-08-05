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

PROGRAM= openssl

SCRIPTS=CA.sh CA.pl tsget

EXE= $(PROGRAM)$(EXE_EXT)

E_EXE=	verify asn1pars req dgst dh dhparam enc passwd gendh errstr \
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

E_OBJ=	verify.o asn1pars.o req.o dgst.o dh.o dhparam.o enc.o passwd.o gendh.o errstr.o \
	ca.o pkcs7.o crl2p7.o crl.o \
	rsa.o rsautl.o dsa.o dsaparam.o ec.o ecparam.o \
	x509.o genrsa.o gendsa.o genpkey.o s_server.o s_client.o speed.o \
	s_time.o $(A_OBJ) $(S_OBJ) $(RAND_OBJ) version.o sess_id.o \
	ciphers.o nseq.o pkcs12.o pkcs8.o pkey.o pkeyparam.o pkeyutl.o \
	spkac.o smime.o cms.o rand.o engine.o ocsp.o prime.o ts.o srp.o

E_SRC=	verify.c asn1pars.c req.c dgst.c dh.c enc.c passwd.c gendh.c errstr.c ca.c \
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

sreq.o: req.c 
	$(CC) -c $(INCLUDES) $(CFLAG) -o sreq.o req.c

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
app_rand.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
app_rand.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
app_rand.o: ../include/openssl/rand.h ../include/openssl/safestack.h
app_rand.o: ../include/openssl/sha.h ../include/openssl/stack.h
app_rand.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
app_rand.o: app_rand.c apps.h
apps.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
apps.o: ../include/openssl/bn.h ../include/openssl/buffer.h
apps.o: ../include/openssl/conf.h ../include/openssl/crypto.h
apps.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
apps.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
apps.o: ../include/openssl/err.h ../include/openssl/evp.h
apps.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
apps.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
apps.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
apps.o: ../include/openssl/pem.h ../include/openssl/pem2.h
apps.o: ../include/openssl/pkcs12.h ../include/openssl/pkcs7.h
apps.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
apps.o: ../include/openssl/sha.h ../include/openssl/stack.h
apps.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
apps.o: ../include/openssl/ui.h ../include/openssl/x509v3.h apps.c apps.h
asn1pars.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
asn1pars.o: ../include/openssl/buffer.h ../include/openssl/conf.h
asn1pars.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
asn1pars.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
asn1pars.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
asn1pars.o: ../include/openssl/evp.h ../include/openssl/lhash.h
asn1pars.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
asn1pars.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
asn1pars.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
asn1pars.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
asn1pars.o: ../include/openssl/safestack.h ../include/openssl/sha.h
asn1pars.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
asn1pars.o: ../include/openssl/txt_db.h apps.h asn1pars.c
ca.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ca.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ca.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ca.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ca.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ca.o: ../include/openssl/err.h ../include/openssl/evp.h
ca.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ca.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
ca.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ca.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ca.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
ca.o: ../include/openssl/sha.h ../include/openssl/stack.h
ca.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
ca.o: ../include/openssl/x509v3.h apps.h ca.c
ciphers.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ciphers.o: ../include/openssl/buffer.h ../include/openssl/conf.h
ciphers.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
ciphers.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ciphers.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ciphers.o: ../include/openssl/err.h ../include/openssl/evp.h
ciphers.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
ciphers.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ciphers.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
ciphers.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ciphers.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ciphers.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
ciphers.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ciphers.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
ciphers.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
ciphers.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
ciphers.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
ciphers.o: ../include/openssl/txt_db.h apps.h ciphers.c
cms.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
cms.o: ../include/openssl/buffer.h ../include/openssl/cms.h
cms.o: ../include/openssl/conf.h ../include/openssl/crypto.h
cms.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
cms.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
cms.o: ../include/openssl/err.h ../include/openssl/evp.h
cms.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
cms.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
cms.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
cms.o: ../include/openssl/pem.h ../include/openssl/pem2.h
cms.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
cms.o: ../include/openssl/sha.h ../include/openssl/stack.h
cms.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
cms.o: ../include/openssl/x509v3.h apps.h cms.c
crl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
crl.o: ../include/openssl/buffer.h ../include/openssl/conf.h
crl.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
crl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
crl.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
crl.o: ../include/openssl/evp.h ../include/openssl/lhash.h
crl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
crl.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
crl.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
crl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
crl.o: ../include/openssl/safestack.h ../include/openssl/sha.h
crl.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
crl.o: ../include/openssl/txt_db.h ../include/openssl/x509v3.h apps.h crl.c
crl2p7.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
crl2p7.o: ../include/openssl/buffer.h ../include/openssl/conf.h
crl2p7.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
crl2p7.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
crl2p7.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
crl2p7.o: ../include/openssl/evp.h ../include/openssl/lhash.h
crl2p7.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
crl2p7.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
crl2p7.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
crl2p7.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
crl2p7.o: ../include/openssl/safestack.h ../include/openssl/sha.h
crl2p7.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
crl2p7.o: ../include/openssl/txt_db.h apps.h crl2p7.c
dgst.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dgst.o: ../include/openssl/buffer.h ../include/openssl/conf.h
dgst.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
dgst.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
dgst.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
dgst.o: ../include/openssl/evp.h ../include/openssl/hmac.h
dgst.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
dgst.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
dgst.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dgst.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dgst.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
dgst.o: ../include/openssl/sha.h ../include/openssl/stack.h
dgst.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h apps.h dgst.c
dh.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dh.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dh.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dh.o: ../include/openssl/dh.h ../include/openssl/e_os2.h
dh.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
dh.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
dh.o: ../include/openssl/evp.h ../include/openssl/lhash.h
dh.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
dh.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
dh.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
dh.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
dh.o: ../include/openssl/safestack.h ../include/openssl/sha.h
dh.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
dh.o: ../include/openssl/txt_db.h apps.h dh.c
dsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dsa.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
dsa.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
dsa.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
dsa.o: ../include/openssl/evp.h ../include/openssl/lhash.h
dsa.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
dsa.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
dsa.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
dsa.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
dsa.o: ../include/openssl/safestack.h ../include/openssl/sha.h
dsa.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
dsa.o: ../include/openssl/txt_db.h apps.h dsa.c
dsaparam.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
dsaparam.o: ../include/openssl/bn.h ../include/openssl/buffer.h
dsaparam.o: ../include/openssl/conf.h ../include/openssl/crypto.h
dsaparam.o: ../include/openssl/dh.h ../include/openssl/dsa.h
dsaparam.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
dsaparam.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
dsaparam.o: ../include/openssl/err.h ../include/openssl/evp.h
dsaparam.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
dsaparam.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
dsaparam.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
dsaparam.o: ../include/openssl/pem.h ../include/openssl/pem2.h
dsaparam.o: ../include/openssl/pkcs7.h ../include/openssl/rsa.h
dsaparam.o: ../include/openssl/safestack.h ../include/openssl/sha.h
dsaparam.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
dsaparam.o: ../include/openssl/txt_db.h apps.h dsaparam.c
ec.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ec.o: ../include/openssl/buffer.h ../include/openssl/conf.h
ec.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
ec.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ec.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
ec.o: ../include/openssl/evp.h ../include/openssl/lhash.h
ec.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ec.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ec.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ec.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ec.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ec.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ec.o: ../include/openssl/txt_db.h apps.h ec.c
ecparam.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
ecparam.o: ../include/openssl/bn.h ../include/openssl/buffer.h
ecparam.o: ../include/openssl/conf.h ../include/openssl/crypto.h
ecparam.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
ecparam.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
ecparam.o: ../include/openssl/err.h ../include/openssl/evp.h
ecparam.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
ecparam.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
ecparam.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
ecparam.o: ../include/openssl/pem.h ../include/openssl/pem2.h
ecparam.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
ecparam.o: ../include/openssl/sha.h ../include/openssl/stack.h
ecparam.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h apps.h
ecparam.o: ecparam.c
enc.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
enc.o: ../include/openssl/bio.h ../include/openssl/buffer.h
enc.o: ../include/openssl/conf.h ../include/openssl/crypto.h
enc.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
enc.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
enc.o: ../include/openssl/err.h ../include/openssl/evp.h
enc.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
enc.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
enc.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
enc.o: ../include/openssl/pem.h ../include/openssl/pem2.h
enc.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
enc.o: ../include/openssl/safestack.h ../include/openssl/sha.h
enc.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
enc.o: ../include/openssl/txt_db.h apps.h enc.c
engine.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
engine.o: ../include/openssl/buffer.h ../include/openssl/conf.h
engine.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
engine.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
engine.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
engine.o: ../include/openssl/evp.h ../include/openssl/lhash.h
engine.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
engine.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
engine.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
engine.o: ../include/openssl/safestack.h ../include/openssl/sha.h
engine.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
engine.o: ../include/openssl/txt_db.h apps.h engine.c
errstr.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
errstr.o: ../include/openssl/buffer.h ../include/openssl/conf.h
errstr.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
errstr.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
errstr.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
errstr.o: ../include/openssl/err.h ../include/openssl/evp.h
errstr.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
errstr.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
errstr.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
errstr.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
errstr.o: ../include/openssl/pem.h ../include/openssl/pem2.h
errstr.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
errstr.o: ../include/openssl/safestack.h ../include/openssl/sha.h
errstr.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
errstr.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
errstr.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
errstr.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
errstr.o: ../include/openssl/txt_db.h apps.h errstr.c
gendh.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
gendh.o: ../include/openssl/bio.h ../include/openssl/bn.h
gendh.o: ../include/openssl/buffer.h ../include/openssl/conf.h
gendh.o: ../include/openssl/crypto.h ../include/openssl/dh.h
gendh.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
gendh.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
gendh.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
gendh.o: ../include/openssl/evp.h ../include/openssl/lhash.h
gendh.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
gendh.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
gendh.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
gendh.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
gendh.o: ../include/openssl/rand.h ../include/openssl/rsa.h
gendh.o: ../include/openssl/safestack.h ../include/openssl/sha.h
gendh.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
gendh.o: ../include/openssl/txt_db.h apps.h gendh.c
gendsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
gendsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
gendsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
gendsa.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
gendsa.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
gendsa.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
gendsa.o: ../include/openssl/evp.h ../include/openssl/lhash.h
gendsa.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
gendsa.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
gendsa.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
gendsa.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
gendsa.o: ../include/openssl/safestack.h ../include/openssl/sha.h
gendsa.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
gendsa.o: ../include/openssl/txt_db.h apps.h gendsa.c
genpkey.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
genpkey.o: ../include/openssl/buffer.h ../include/openssl/conf.h
genpkey.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
genpkey.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
genpkey.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
genpkey.o: ../include/openssl/evp.h ../include/openssl/lhash.h
genpkey.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
genpkey.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
genpkey.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
genpkey.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
genpkey.o: ../include/openssl/safestack.h ../include/openssl/sha.h
genpkey.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
genpkey.o: ../include/openssl/txt_db.h apps.h genpkey.c
genrsa.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
genrsa.o: ../include/openssl/bio.h ../include/openssl/bn.h
genrsa.o: ../include/openssl/buffer.h ../include/openssl/conf.h
genrsa.o: ../include/openssl/crypto.h ../include/openssl/dh.h
genrsa.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
genrsa.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
genrsa.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
genrsa.o: ../include/openssl/evp.h ../include/openssl/lhash.h
genrsa.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
genrsa.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
genrsa.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
genrsa.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
genrsa.o: ../include/openssl/rand.h ../include/openssl/rsa.h
genrsa.o: ../include/openssl/safestack.h ../include/openssl/sha.h
genrsa.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
genrsa.o: ../include/openssl/txt_db.h apps.h genrsa.c
nseq.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
nseq.o: ../include/openssl/buffer.h ../include/openssl/conf.h
nseq.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
nseq.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
nseq.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
nseq.o: ../include/openssl/evp.h ../include/openssl/lhash.h
nseq.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
nseq.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
nseq.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
nseq.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
nseq.o: ../include/openssl/safestack.h ../include/openssl/sha.h
nseq.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
nseq.o: ../include/openssl/txt_db.h apps.h nseq.c
ocsp.o: ocsp.c
openssl.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
openssl.o: ../include/openssl/bio.h ../include/openssl/buffer.h
openssl.o: ../include/openssl/conf.h ../include/openssl/crypto.h
openssl.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
openssl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
openssl.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
openssl.o: ../include/openssl/evp.h ../include/openssl/hmac.h
openssl.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
openssl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
openssl.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
openssl.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
openssl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
openssl.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
openssl.o: ../include/openssl/safestack.h ../include/openssl/sha.h
openssl.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
openssl.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
openssl.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
openssl.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
openssl.o: ../include/openssl/txt_db.h apps.h openssl.c progs.h s_apps.h
passwd.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
passwd.o: ../include/openssl/bio.h ../include/openssl/buffer.h
passwd.o: ../include/openssl/conf.h ../include/openssl/crypto.h
passwd.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
passwd.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
passwd.o: ../include/openssl/err.h ../include/openssl/evp.h
passwd.o: ../include/openssl/lhash.h ../include/openssl/md5.h
passwd.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
passwd.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
passwd.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
passwd.o: ../include/openssl/rand.h ../include/openssl/safestack.h
passwd.o: ../include/openssl/sha.h ../include/openssl/stack.h
passwd.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h apps.h
passwd.o: passwd.c
pkcs12.o: ../include/openssl/opensslconf.h pkcs12.c
pkcs7.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs7.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkcs7.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkcs7.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs7.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkcs7.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkcs7.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkcs7.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkcs7.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkcs7.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
pkcs7.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkcs7.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkcs7.o: ../include/openssl/txt_db.h apps.h pkcs7.c
pkcs8.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkcs8.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkcs8.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkcs8.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkcs8.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkcs8.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkcs8.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkcs8.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkcs8.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkcs8.o: ../include/openssl/pem2.h ../include/openssl/pkcs12.h
pkcs8.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
pkcs8.o: ../include/openssl/sha.h ../include/openssl/stack.h
pkcs8.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h apps.h
pkcs8.o: pkcs8.c
pkey.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkey.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkey.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkey.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkey.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkey.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkey.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkey.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkey.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkey.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
pkey.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkey.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkey.o: ../include/openssl/txt_db.h apps.h pkey.c
pkeyparam.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkeyparam.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkeyparam.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkeyparam.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkeyparam.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkeyparam.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkeyparam.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkeyparam.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkeyparam.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkeyparam.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
pkeyparam.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkeyparam.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkeyparam.o: ../include/openssl/txt_db.h apps.h pkeyparam.c
pkeyutl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
pkeyutl.o: ../include/openssl/buffer.h ../include/openssl/conf.h
pkeyutl.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
pkeyutl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
pkeyutl.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
pkeyutl.o: ../include/openssl/evp.h ../include/openssl/lhash.h
pkeyutl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
pkeyutl.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
pkeyutl.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
pkeyutl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
pkeyutl.o: ../include/openssl/safestack.h ../include/openssl/sha.h
pkeyutl.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
pkeyutl.o: ../include/openssl/txt_db.h apps.h pkeyutl.c
prime.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
prime.o: ../include/openssl/bn.h ../include/openssl/buffer.h
prime.o: ../include/openssl/conf.h ../include/openssl/crypto.h
prime.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
prime.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
prime.o: ../include/openssl/evp.h ../include/openssl/lhash.h
prime.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
prime.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
prime.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
prime.o: ../include/openssl/safestack.h ../include/openssl/sha.h
prime.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
prime.o: ../include/openssl/txt_db.h apps.h prime.c
rand.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
rand.o: ../include/openssl/bio.h ../include/openssl/buffer.h
rand.o: ../include/openssl/conf.h ../include/openssl/crypto.h
rand.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
rand.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
rand.o: ../include/openssl/err.h ../include/openssl/evp.h
rand.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
rand.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
rand.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
rand.o: ../include/openssl/pkcs7.h ../include/openssl/rand.h
rand.o: ../include/openssl/safestack.h ../include/openssl/sha.h
rand.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
rand.o: ../include/openssl/txt_db.h apps.h rand.c
req.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
req.o: ../include/openssl/bn.h ../include/openssl/buffer.h
req.o: ../include/openssl/conf.h ../include/openssl/crypto.h
req.o: ../include/openssl/dh.h ../include/openssl/dsa.h
req.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
req.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
req.o: ../include/openssl/err.h ../include/openssl/evp.h
req.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
req.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
req.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
req.o: ../include/openssl/pem.h ../include/openssl/pem2.h
req.o: ../include/openssl/pkcs7.h ../include/openssl/rsa.h
req.o: ../include/openssl/safestack.h ../include/openssl/sha.h
req.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
req.o: ../include/openssl/txt_db.h ../include/openssl/x509v3.h apps.h req.c
rsa.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rsa.o: ../include/openssl/bn.h ../include/openssl/buffer.h
rsa.o: ../include/openssl/conf.h ../include/openssl/crypto.h
rsa.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
rsa.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
rsa.o: ../include/openssl/err.h ../include/openssl/evp.h
rsa.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
rsa.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
rsa.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
rsa.o: ../include/openssl/pem.h ../include/openssl/pem2.h
rsa.o: ../include/openssl/pkcs7.h ../include/openssl/rsa.h
rsa.o: ../include/openssl/safestack.h ../include/openssl/sha.h
rsa.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
rsa.o: ../include/openssl/txt_db.h apps.h rsa.c
rsautl.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
rsautl.o: ../include/openssl/buffer.h ../include/openssl/conf.h
rsautl.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
rsautl.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
rsautl.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
rsautl.o: ../include/openssl/evp.h ../include/openssl/lhash.h
rsautl.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
rsautl.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
rsautl.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
rsautl.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
rsautl.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
rsautl.o: ../include/openssl/sha.h ../include/openssl/stack.h
rsautl.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h apps.h
rsautl.o: rsautl.c
s_cb.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
s_cb.o: ../include/openssl/bio.h ../include/openssl/buffer.h
s_cb.o: ../include/openssl/conf.h ../include/openssl/crypto.h
s_cb.o: ../include/openssl/dtls1.h ../include/openssl/e_os2.h
s_cb.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
s_cb.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
s_cb.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s_cb.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s_cb.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_cb.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_cb.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_cb.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_cb.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
s_cb.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_cb.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s_cb.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s_cb.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_cb.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_cb.o: ../include/openssl/txt_db.h apps.h s_apps.h s_cb.c
s_client.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
s_client.o: ../include/openssl/bio.h ../include/openssl/bn.h
s_client.o: ../include/openssl/buffer.h ../include/openssl/conf.h
s_client.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
s_client.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_client.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_client.o: ../include/openssl/err.h ../include/openssl/evp.h
s_client.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
s_client.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s_client.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
s_client.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_client.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_client.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
s_client.o: ../include/openssl/rand.h ../include/openssl/safestack.h
s_client.o: ../include/openssl/sha.h ../include/openssl/srtp.h
s_client.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_client.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s_client.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_client.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h
s_client.o: ../include/openssl/x509v3.h apps.h s_apps.h s_client.c timeouts.h
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
s_server.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
s_server.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_server.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_server.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
s_server.o: ../include/openssl/rand.h ../include/openssl/rsa.h
s_server.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_server.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s_server.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s_server.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_server.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_server.o: ../include/openssl/txt_db.h ../include/openssl/x509v3.h apps.h
s_server.o: s_apps.h s_server.c timeouts.h
s_socket.o: ../e_os.h ../e_os2.h ../include/openssl/KTest.h
s_socket.o: ../include/openssl/asn1.h ../include/openssl/bio.h
s_socket.o: ../include/openssl/buffer.h ../include/openssl/conf.h
s_socket.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
s_socket.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_socket.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_socket.o: ../include/openssl/evp.h ../include/openssl/hmac.h
s_socket.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
s_socket.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
s_socket.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
s_socket.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
s_socket.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
s_socket.o: ../include/openssl/pqueue.h ../include/openssl/safestack.h
s_socket.o: ../include/openssl/sha.h ../include/openssl/srtp.h
s_socket.o: ../include/openssl/ssl.h ../include/openssl/ssl2.h
s_socket.o: ../include/openssl/ssl23.h ../include/openssl/ssl3.h
s_socket.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
s_socket.o: ../include/openssl/tls1.h ../include/openssl/txt_db.h apps.h
s_socket.o: s_apps.h s_socket.c
s_time.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
s_time.o: ../include/openssl/buffer.h ../include/openssl/conf.h
s_time.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
s_time.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
s_time.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
s_time.o: ../include/openssl/err.h ../include/openssl/evp.h
s_time.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
s_time.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
s_time.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
s_time.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
s_time.o: ../include/openssl/pem.h ../include/openssl/pem2.h
s_time.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
s_time.o: ../include/openssl/safestack.h ../include/openssl/sha.h
s_time.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
s_time.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
s_time.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
s_time.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
s_time.o: ../include/openssl/txt_db.h apps.h s_apps.h s_time.c
sess_id.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
sess_id.o: ../include/openssl/buffer.h ../include/openssl/conf.h
sess_id.o: ../include/openssl/crypto.h ../include/openssl/dtls1.h
sess_id.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
sess_id.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
sess_id.o: ../include/openssl/err.h ../include/openssl/evp.h
sess_id.o: ../include/openssl/hmac.h ../include/openssl/kssl.h
sess_id.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
sess_id.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
sess_id.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
sess_id.o: ../include/openssl/pem.h ../include/openssl/pem2.h
sess_id.o: ../include/openssl/pkcs7.h ../include/openssl/pqueue.h
sess_id.o: ../include/openssl/safestack.h ../include/openssl/sha.h
sess_id.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
sess_id.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
sess_id.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
sess_id.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
sess_id.o: ../include/openssl/txt_db.h apps.h sess_id.c
smime.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
smime.o: ../include/openssl/buffer.h ../include/openssl/conf.h
smime.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
smime.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
smime.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
smime.o: ../include/openssl/evp.h ../include/openssl/lhash.h
smime.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
smime.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
smime.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
smime.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
smime.o: ../include/openssl/safestack.h ../include/openssl/sha.h
smime.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
smime.o: ../include/openssl/txt_db.h ../include/openssl/x509v3.h apps.h smime.c
speed.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/aes.h
speed.o: ../include/openssl/asn1.h ../include/openssl/bio.h
speed.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
speed.o: ../include/openssl/buffer.h ../include/openssl/conf.h
speed.o: ../include/openssl/crypto.h ../include/openssl/dsa.h
speed.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
speed.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
speed.o: ../include/openssl/err.h ../include/openssl/evp.h
speed.o: ../include/openssl/hmac.h ../include/openssl/lhash.h
speed.o: ../include/openssl/md5.h ../include/openssl/modes.h
speed.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
speed.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
speed.o: ../include/openssl/ossl_typ.h ../include/openssl/pkcs7.h
speed.o: ../include/openssl/rand.h ../include/openssl/rc2.h
speed.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
speed.o: ../include/openssl/seed.h ../include/openssl/sha.h
speed.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
speed.o: ../include/openssl/txt_db.h ../include/openssl/whrlpool.h apps.h
speed.o: speed.c testdsa.h testrsa.h
spkac.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
spkac.o: ../include/openssl/buffer.h ../include/openssl/conf.h
spkac.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
spkac.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
spkac.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
spkac.o: ../include/openssl/evp.h ../include/openssl/lhash.h
spkac.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
spkac.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
spkac.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
spkac.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
spkac.o: ../include/openssl/safestack.h ../include/openssl/sha.h
spkac.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
spkac.o: ../include/openssl/txt_db.h apps.h spkac.c
srp.o: ../include/openssl/opensslconf.h srp.c
ts.o: ../e_os.h ../include/openssl/KTest.h ../include/openssl/asn1.h
ts.o: ../include/openssl/bio.h ../include/openssl/bn.h
ts.o: ../include/openssl/buffer.h ../include/openssl/conf.h
ts.o: ../include/openssl/crypto.h ../include/openssl/dh.h
ts.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
ts.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
ts.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
ts.o: ../include/openssl/evp.h ../include/openssl/lhash.h
ts.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
ts.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ts.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
ts.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
ts.o: ../include/openssl/rand.h ../include/openssl/rsa.h
ts.o: ../include/openssl/safestack.h ../include/openssl/sha.h
ts.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ts.o: ../include/openssl/ts.h ../include/openssl/txt_db.h
ts.o: ../include/openssl/x509v3.h apps.h ts.c
verify.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
verify.o: ../include/openssl/buffer.h ../include/openssl/conf.h
verify.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
verify.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
verify.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
verify.o: ../include/openssl/evp.h ../include/openssl/lhash.h
verify.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
verify.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
verify.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
verify.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
verify.o: ../include/openssl/safestack.h ../include/openssl/sha.h
verify.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
verify.o: ../include/openssl/txt_db.h ../include/openssl/x509v3.h apps.h
verify.o: verify.c
version.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
version.o: ../include/openssl/blowfish.h ../include/openssl/bn.h
version.o: ../include/openssl/buffer.h ../include/openssl/conf.h
version.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
version.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
version.o: ../include/openssl/ecdsa.h ../include/openssl/evp.h
version.o: ../include/openssl/lhash.h ../include/openssl/obj_mac.h
version.o: ../include/openssl/objects.h ../include/openssl/opensslconf.h
version.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
version.o: ../include/openssl/pkcs7.h ../include/openssl/safestack.h
version.o: ../include/openssl/sha.h ../include/openssl/stack.h
version.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h apps.h
version.o: version.c
x509.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
x509.o: ../include/openssl/bn.h ../include/openssl/buffer.h
x509.o: ../include/openssl/conf.h ../include/openssl/crypto.h
x509.o: ../include/openssl/dsa.h ../include/openssl/e_os2.h
x509.o: ../include/openssl/ec.h ../include/openssl/ecdh.h
x509.o: ../include/openssl/ecdsa.h ../include/openssl/err.h
x509.o: ../include/openssl/evp.h ../include/openssl/lhash.h
x509.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
x509.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
x509.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
x509.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
x509.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
x509.o: ../include/openssl/sha.h ../include/openssl/stack.h
x509.o: ../include/openssl/symhacks.h ../include/openssl/txt_db.h
x509.o: ../include/openssl/x509v3.h apps.h x509.c
