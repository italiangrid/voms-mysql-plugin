Name:		voms-mysql-plugin
Version:	3.1.5.1
Release:	1%{?dist}
Summary:	VOMS server plugin for MySQL

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://glite.web.cern.ch/glite/
Source:		%{name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Provides:	voms-mysql = %{version}-%{release}
Obsoletes:	voms-mysql < %{version}-%{release}
Requires:	voms-server%{?_isa}
BuildRequires:	libtool
BuildRequires:	mysql-devel%{?_isa}
BuildRequires:	openssl%{?_isa}

%description
In grid computing, and whenever the access to resources may be controlled
by parties external to the resource provider, users may be grouped to
Virtual Organizations (VOs). This package provides a VO Membership Service
(VOMS), which informs on that association between users and their VOs:
groups, roles and capabilities.

This package offers the MySQL implementation for the VOMS server.

%prep
%setup -q
./bootstrap

%build
%configure --libdir=%{_libdir}/voms
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

rm $RPM_BUILD_ROOT%{_libdir}/voms/libvomsmysql.a
rm $RPM_BUILD_ROOT%{_libdir}/voms/libvomsmysql.la

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{_datadir}/voms/voms-mysql.data
%{_datadir}/voms/voms-mysql-compat.data
%dir %{_libdir}/voms
%{_libdir}/voms/libvomsmysql.so

%changelog
* Tue May 31 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.1.5.1-1
- Update to version 3.1.5.1

* Wed Mar 23 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.1.3.2-3
- Rebuild for mysql 5.5.10

* Mon Feb 07 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.1.3.2-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Sun Jun  6 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.1.3.2-1
- Update to version 3.1.3.2
- Drop all patches (accepted upstream)

* Thu Dec  3 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.1.3.1-1
- Update to version 3.1.3.1

* Sat Aug 15 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.1.1-1
- Update to version 3.1.1

* Tue Jun 30 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.1.0-1
- First build
