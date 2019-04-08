version := $(shell cat VERSION)

ifeq ($(shell git describe --exact-match 2>/dev/null),)
# sanlock-3.7.0-5-g11fb098 -> 5.g11fb098
release := $(shell git describe --tags | awk -F- '{print $$(NF-1) "." $$(NF)}')
else
release := 0
endif

distname := sanlock-$(version)
tarball := $(distname).tar.gz

SUBDIRS = wdmd src python reset

.PHONY: all $(SUBDIRS) clean install

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

src: wdmd

python reset: src

clean install:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir $@; \
	done

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
