SUBDIRS = utils utils12
EXTRA_DIST = utils/policies utils/certificates utils/regtests utils/man utils/reg.sh utils/cakey.pem demo
ACLOCAL_AMFLAGS = -I m4

pkgname = $(PACKAGE_TARNAME)-$(PACKAGE_VERSION)
tarname = $(pkgname).tar.gz

$(tarname):
	git archive --format=tar --prefix=$(pkgname)/ v$(PACKAGE_VERSION) $(FILES) | gzip >$@

tar: $(tarname)
