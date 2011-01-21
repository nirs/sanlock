## global alphatag git0a6184070

Name:		sanlock
Version:	1.0
Release:	1%{?alphatag:.%{alphatag}}%{?dist}
Summary:	A shared disk lock manager
Group:		System Environment/Base
License:	GPLv2+
URL:		https://fedorahosted.org/releases/s/a/sanlock/
Source0:	https://fedorahosted.org/releases/s/a/sanlock/%{name}-%{version}.tar.gz

## Setup/build bits
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:	libblkid-devel

%description
sanlock uses disk paxos to manage leases on shared storage.
Hosts connected to a common SAN can use this to synchronize their
access to the shared disks.

%prep
%setup -q -n %{name}-%{version}

%build
# upstream does not require configure

# upstream does not support _smp_mflags
CFLAGS="$(echo '%{optflags}')" make -C daemon

%install
rm -rf %{buildroot}
make -C daemon \
	install LIB_LIBDIR=%{_libdir} \
	DESTDIR=%{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
/usr/libexec/sanlock
%{_libdir}/libsanlock.so.*

%post -n sanlock -p /sbin/ldconfig

%postun -n sanlock -p /sbin/ldconfig

%package -n sanlock-devel
Group: Development/Libraries
Summary: A shared disk lock manager devel package
Requires: sanlock = %{version}-%{release}

%description -n sanlock-devel
The sanlock library devel package.

%files -n sanlock-devel
%defattr(-,root,root,-)
%{_libdir}/libsanlock.so
%{_includedir}/sanlock.h
%{_includedir}/sanlock_resource.h

%changelog
* Mon Jan 10 2011 Fabio M. Di Nitto <fdinitto@redhat.com> - 1.0-1
- first cut at rpm packaging
