Name:           sanlock
Version:        1.0
Release:        2%{?dist}
Summary:        A shared disk lock manager

Group:          System Environment/Base
License:        GPLv2+
URL:            https://fedorahosted.org/sanlock/
Source0:        https://fedorahosted.org/releases/s/a/sanlock/%{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  libblkid-devel

#Requires: <nothing>

%description
sanlock uses disk paxos to manage leases on shared storage.
Hosts connected to a common SAN can use this to synchronize their
access to the shared disks.

%prep
%setup -q

%build
# upstream does not require configure
# upstream does not support _smp_mflags
CFLAGS=$RPM_OPT_FLAGS make -C src

%install
rm -rf $RPM_BUILD_ROOT
make -C src \
        install LIB_LIBDIR=%{_libdir} \
        DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%doc COPYING
%{_sbindir}/sanlock
%{_libdir}/libsanlock.so.*

%package        devel
Summary:        Development files for %{name}
Group:          Development/Libraries
Requires:       %{name} = %{version}-%{release}

%description    devel
The %{name}-devel package contains libraries and header files for
developing applications that use %{name}.

%files          devel
%defattr(-,root,root,-)
%doc COPYING
%{_libdir}/libsanlock.so
%{_includedir}/sanlock.h
%{_includedir}/sanlock_resource.h

%changelog
* Tue Feb 8 2011 Angus Salkeld <asalkeld@redhat.com> - 1.0-2
* - SPEC: Add docs and make more consistent with the fedora template.

* Mon Jan 10 2011 Fabio M. Di Nitto <fdinitto@redhat.com> - 1.0-1
- first cut at rpm packaging
