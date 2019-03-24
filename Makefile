version := $(shell cat VERSION)

ifeq ($(shell git describe --exact-match 2>/dev/null),)
# sanlock-3.7.0-5-g11fb098 -> 5.g11fb098
release := $(shell git describe --tags | awk -F- '{print $$(NF-1) "." $$(NF)}')
else
release := 0
endif

distname := sanlock-$(version)
tarball := $(distname).tar.gz

all:
	$(MAKE) -C wdmd
	$(MAKE) -C src
	$(MAKE) -C python inplace

clean:
	$(MAKE) -C wdmd clean
	$(MAKE) -C src clean
	$(MAKE) -C python clean

dist: spec
	rm -f $(tarball)
	git archive --prefix=$(distname)/ HEAD > $(distname).tar
	tar rf $(distname).tar --transform="s|^|$(distname)/&|" sanlock.spec
	gzip $(distname).tar

srpm: dist
	rpmbuild -ts $(tarball)

rpm: dist
	rpmbuild -ta $(tarball)

spec:
	sed -e 's/@VERSION@/$(version)/g' \
		-e 's/@RELEASE@/$(release)/g' \
		sanlock.spec.in > sanlock.spec
