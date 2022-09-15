CC=gcc
CFLAGS=-Wall -Wstrict-prototypes -Werror -fPIC -std=c99

LD_SONAME=-Wl,-soname,libnss_aad.so.2
LIBRARY=libnss_aad.so.2.0
LINKS=libnss_aad.so.2 libnss_aad.so

PREFIX=$(DESTDIR)/usr
LIBDIR=/lib/x86_64-linux-gnu/

BUILD=.libs

default: build
build: nss_aad

nss_aad_build_dir:
	[ -d $(BUILD) ] || mkdir $(BUILD)

nss_http-passwd:
	$(CC) $(CFLAGS) -c nss_http-passwd.c -o $(BUILD)/nss_http-passwd.o

nss_http-group:
	$(CC) $(CFLAGS) -c nss_http-group.c -o $(BUILD)/nss_http-group.o

nss_http-shadow:
	$(CC) $(CFLAGS) -c nss_http-shadow.c -o $(BUILD)/nss_http-shadow.o

nss_aad_services: nss_http-passwd nss_http-group nss_http-shadow

nss_aad: nss_aad_build_dir nss_aad_services
	$(CC) $(CFLAGS) -c nss_http.c -o $(BUILD)/nss_http.o

	$(CC) -shared $(LD_SONAME) -o $(BUILD)/$(LIBRARY) \
		$(BUILD)/nss_http.o \
		$(BUILD)/nss_http-passwd.o \
		$(BUILD)/nss_http-group.o \
		$(BUILD)/nss_http-shadow.o \
                -lcurl -ljansson

clean:
	rm -rf $(BUILD)

pkgclean:
	rm -rf debian/.debhelper debian/debhelper-build-stamp
	rm -rf debian/files debian/libnss-aad debian/libnss-aad.substvars
	rm -rf ../libnss-aad_*.build ../libnss-aad_*.buildinfo ../libnss-aad_*.changes
	rm -rf ../libnss-aad*.deb ../libnss-aad_*.dsc ../libnss-aad_*.tar.xz

install:
	[ -d $(DESTDIR)/$(LIBDIR) ] || install -d $(DESTDIR)/$(LIBDIR)
	install $(BUILD)/$(LIBRARY) $(DESTDIR)/$(LIBDIR)
	cd $(DESTDIR)/$(LIBDIR); for link in $(LINKS); do ln -sf $(LIBRARY) $$link ; done

.PHONY: clean install nss_http_build_dir nss_http
