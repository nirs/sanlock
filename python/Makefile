
INSTALL=$(shell which install)
RPMTOP=$(shell bash -c "pwd -P")/rpmbuild
rpmversion:=0.1
rpmrelease:=1.$(shell date +%Y%m%d)git
TARBALL=python-sync-manger-$(rpmversion)-$(rpmrelease).tar.gz

rpm:
	rm -rf $(RPMTOP)
	mkdir $(RPMTOP)
	mkdir $(RPMTOP)/BUILD  $(RPMTOP)/BUILDROOT  $(RPMTOP)/RPMS  $(RPMTOP)/SOURCES  $(RPMTOP)/SPECS $(RPMTOP)/SRPMS
	tar zcf $(TARBALL) `git ls-files`
	mv $(TARBALL) $(RPMTOP)/SOURCES
	sed 's/^Version:.*/Version: $(rpmversion)/;s/^Release:.*/Release: $(rpmrelease)%{?dist}/;s/^Source0:.*/Source0: $(TARBALL)/' \
		python-sync_manager.spec.in > python-sync_manager.spec
	rpmbuild -v -ba --define="_topdir $(RPMTOP)" \
                        --define="_sourcedir $(RPMTOP)/SOURCES" \
		./python-sync_manager.spec
