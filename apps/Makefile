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
AR= ar r

PEX_LIBS=
EX_LIBS= 
EXE_EXT= 

SHLIB_TARGET=

# Removed -DMONOLITH in order to build only one specific application binary.
CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile makeapps.com install.com

DLIBCRYPTO=../libcrypto.a
DLIBSSL=../libssl.a
DLIBTASESSL=../libtasessl.a
DLIBTASEAPPS=../libtaseapps.a
LIBCRYPTO=-L.. -lcrypto
LIBSSL=-L.. -lssl

PROGRAM= openssl

SCRIPTS=CA.sh CA.pl tsget

EXE= $(PROGRAM)$(EXE_EXT)

E_EXE=s_client
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

E_OBJ=	s_client.o $(A_OBJ) $(S_OBJ) $(RAND_OBJ)
#verify.o asn1pars.o req.o dgst.o dh.o dhparam.o enc.o passwd.o gendh.o errstr.o \
	ca.o pkcs7.o crl2p7.o crl.o \
	rsa.o rsautl.o dsa.o dsaparam.o ec.o ecparam.o \
	x509.o genrsa.o gendsa.o genpkey.o s_server.o s_client.o speed.o \
	s_time.o $(A_OBJ) $(S_OBJ) $(RAND_OBJ) version.o sess_id.o \
	ciphers.o nseq.o pkcs12.o pkcs8.o pkey.o pkeyparam.o pkeyutl.o \
	spkac.o smime.o cms.o rand.o engine.o ocsp.o prime.o ts.o srp.o

E_SRC=	s_client.c $(A_SRC) $(S_SRC) $(RAND_SRC)
# verify.c asn1pars.c req.c dgst.c dh.c enc.c passwd.c gendh.c errstr.c ca.c \
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

all:	exe

libtasessl: $(DLIBTASESSL)

exe:	$(EXE)

req: sreq.o $(A_OBJ) $(DLIBCRYPTO)
	shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	$(MAKE) -f $(TOP)/Makefile.shared -e \
		APPNAME=req OBJECTS="sreq.o $(A_OBJ) $(RAND_OBJ)" \
		LIBDEPS="$(PEX_LIBS) $(LIBCRYPTO) $(EX_LIBS)" \
		link_app.$${shlib_target}

# TODO: If this rule gives you shit, just comment it out.
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
	rm -f *.o *.obj *.dll lib tags core .pure .nfs* *.old *.bak fluff $(EXE)
	rm -f req

$(DLIBSSL):
	(cd ..; $(MAKE) DIRS=ssl all)

$(DLIBCRYPTO):
	(cd ..; $(MAKE) DIRS=crypto all)

$(DLIBTASEAPPS): $(E_OBJ)
	$(AR) $@ $^
	$(RANLIB) $@ || echo Never mind ranlib error.

TASE_TEMP_DIR := $(shell mktemp -d)

#Workaround to drop all tase objects into a temp dir and ar them together
$(DLIBTASESSL): $(DLIBTASEAPPS) $(DLIBCRYPTO) $(DLIBSSL)
	echo Doing the archive lulz in $(TASE_TEMP_DIR)
	cp $^ $(TASE_TEMP_DIR)
	(set -e; \
	cd $(TASE_TEMP_DIR); \
	for f in $^; \
	do \
	ar x $$(basename $$f); \
	done; \
	find . -iname '*.o' | xargs $(AR) temparchive.a)
	cp $(TASE_TEMP_DIR)/temparchive.a $@
	$(RANLIB) $@ || echo Never mind.
	rm -r $(TASE_TEMP_DIR)

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
