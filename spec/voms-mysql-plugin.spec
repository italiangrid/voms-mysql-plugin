Name:		voms-mysql-plugin
Version:	3.1.7
Release:	1%{?dist}
Summary:	VOMS server plugin for MySQL

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		https://wiki.italiangrid.it/twiki/bin/view/VOMS
Source:		%{name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Provides:	voms-mysql = %{version}-%{release}
Obsoletes:	voms-mysql < %{version}-%{release}
Requires:	voms-server%{?_isa}
BuildRequires:	libtool
BuildRequires:	mysql-devel%{?_isa}
BuildRequires:	openssl%{?_isa}

%description
The Virtual Organization Membership Service (VOMS) is an attribute authority
which serves as central repository for VO user authorization information,
providing support for sorting users into group hierarchies, keeping track of
their roles and other attributes in order to issue trusted attribute
certificates and SAML assertions used in the Grid environment for
authorization purposes.

This package offers the MySQL implementation for the VOMS server.

%prep
%setup -q
./autogen.sh

%build
%configure 
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

rm $RPM_BUILD_ROOT%{_libdir}/libvomsmysql.a
rm $RPM_BUILD_ROOT%{_libdir}/libvomsmysql.la

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{_datadir}/voms/voms-mysql.data
%{_datadir}/voms/voms-mysql-compat.data
%{_libdir}/libvomsmysql.so

%changelog
* Fri Aug 26 2016 Andrea Ceccanti <andrea.ceccanti@cnaf.infn.it> - 3.1.7-0
- Update to version 3.1.7

* Tue May 31 2011 Andrea Ceccanti <andrea.ceccanti@cnaf.infn.it> - 3.1.6-1
- Update to version 3.1.6

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
