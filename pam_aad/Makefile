CC=gcc
CFLAGS=-Wall -Wstrict-prototypes -Werror -fPIC -std=c99 -I.

LD_SONAME=-Wl,-soname,pam_aad.so
LIBRARY=pam_aad.so

PREFIX=$(DESTDIR)/usr
LIBDIR=/lib/x86_64-linux-gnu/security/

BUILD=.libs

default: build
build: pam_aad

pam_aad_build_dir:
	[ -d $(BUILD) ] || mkdir $(BUILD)


pam_aad: pam_aad_build_dir
	$(CC) $(CFLAGS) -c nss_http.c -o $(BUILD)/nss_http.o
	$(CC) $(CFLAGS) -c pam_aad.c -o $(BUILD)/pam_aad.o

	$(CC) -shared -o $(BUILD)/$(LIBRARY) \
				$(BUILD)/pam_aad.o \
				$(BUILD)/nss_http.o \
				-lpam -lcurl -ljansson

clean:
	rm -rf $(BUILD)

pkgclean:
	rm -rf debian/.debhelper debian/debhelper-build-stamp
	rm -rf debian/files debian/pam-aad debian/pam-aad.substvars
	rm -rf ../pam-aad_*.build ../pam-aad_*.buildinfo ../pam-aad_*.changes
	rm -rf ../pam-aad*.deb ../pam-aad_*.dsc ../pam-aad_*.tar.xz

install:
	[ -d $(DESTDIR)/$(LIBDIR) ] || install -d $(DESTDIR)/$(LIBDIR)
	install $(BUILD)/$(LIBRARY) $(DESTDIR)/$(LIBDIR)

.PHONY: clean install pam_aad_build_dir pam_aad
