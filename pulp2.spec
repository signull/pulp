# sitelib for noarch packages, sitearch for others (remove the unneeded one)
%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}
%{!?python_sitearch: %global python_sitearch %(%{__python} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib(1))")}

%if 0%{?rhel} == 5
%define pulp_selinux 0
%else
%define pulp_selinux 1
%endif

%if %{pulp_selinux}
#SELinux
%define selinux_variants mls strict targeted
%define selinux_policyver %(sed -e 's,.*selinux-policy-\\([^/]*\\)/.*,\\1,' /usr/share/selinux/devel/policyhelp 2> /dev/null)
%define moduletype apps
%endif

# -- headers - pulp server ---------------------------------------------------

Name:           pulp
Version:        0.0.295
Release:        1%{?dist}
Summary:        An application for managing software content

Group:          Development/Languages
License:        GPLv2
URL:            https://fedorahosted.org/pulp/
Source0:        https://fedorahosted.org/releases/p/u/pulp/%{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildArch:      noarch
BuildRequires:  python2-devel
BuildRequires:  python-setuptools
BuildRequires:  python-nose
BuildRequires:  rpm-python

Requires: %{name}-common = %{version}
Requires: pymongo >= 1.9
Requires: python-setuptools
Requires: python-webpy
Requires: python-simplejson >= 2.0.9
Requires: python-oauth2 >= 1.5.170-2.pulp%{?dist}
Requires: python-httplib2
Requires: python-isodate >= 0.4.4-3.pulp%{?dist}
Requires: python-BeautifulSoup
Requires: grinder >= 0.1.3-1
Requires: httpd
Requires: mod_ssl
Requires: openssl
Requires: python-ldap
Requires: python-gofer >= 0.70
Requires: crontabs
Requires: acl
Requires: mod_wsgi >= 3.3-3.pulp%{?dist}
Requires: mongodb
Requires: mongodb-server
Requires: qpid-cpp-server
%if 0%{?rhel} == 5
Requires: m2crypto
%else
Requires: m2crypto >= 0.21.1.pulp-7%{?dist}
%endif

%if %{pulp_selinux}
Requires: %{name}-selinux-server = %{version}-%{release}
%endif

%if 0%{?rhel} == 5
# RHEL-5
Requires: python-uuid
Requires: python-ssl
Requires: python-ctypes
Requires: python-hashlib
Requires: createrepo = 0.9.8-3
%endif
%if 0%{?rhel} == 6
# RHEL-6
Requires: python-ctypes
Requires: python-hashlib
Requires: nss >= 3.12.9
Requires: curl => 7.19.7
%endif

%if 0%{?rhel} == 5
# RHEL-5
Requires: mkisofs
%else
# RHEL-6 & Fedora
Requires: genisoimage
%endif

# Both attempt to serve content at the same apache alias, so don't
# allow them to be installed at the same time.
Conflicts:      pulp-cds

%description
Pulp provides replication, access, and accounting for software repositories.

# -- headers - pulp client lib ---------------------------------------------------

%package client-lib
Summary:        Client side libraries pulp client tools
Group:          Development/Languages
BuildRequires:  rpm-python
Requires:       python-simplejson
Requires:       python-isodate >= 0.4.4
Requires:       m2crypto
Requires:       %{name}-common = %{version}
Requires:       gofer >= 0.70
%if !0%{?fedora}
# RHEL
Requires:       python-hashlib
%endif
Requires:       python-rhsm >= 0.96.4
Obsoletes:      pulp-client <= 0.218

%description client-lib
A collection of libraries used by by the pulp client tools.

# -- headers - pulp client ---------------------------------------------------

%package consumer
Summary:        Client side tool for pulp consumers
Group:          Development/Languages
Requires:       %{name}-client-lib = %{version}
Requires:       python-okaara >= 1.0.12
Obsoletes:      pulp-client <= 0.218

%description consumer
A client tool used on pulp consumers to do things such as consumer
registration, and repository binding.

# -- headers - pulp admin ---------------------------------------------------

%package admin
Summary:        Admin tool to administer the pulp server
Group:          Development/Languages
Requires:       %{name}-client-lib = %{version}
Requires:       python-okaara >= 1.0.12
Obsoletes:      pulp-client <= 0.218

%description admin
A tool used to administer the pulp server, such as repo creation and synching,
and to kick off remote actions on consumers.

# -- headers - pulp common ---------------------------------------------------

%package common
Summary:        Pulp common python packages.
Group:          Development/Languages
BuildRequires:  rpm-python

%description common
A collection of resources that are common between the pulp server and client.

# -- headers - pulp cds ------------------------------------------------------

%package cds
Summary:        Provides the ability to run as a pulp external CDS.
Group:          Development/Languages
BuildRequires:  rpm-python
Requires:       %{name}-common = %{version}
Requires:       gofer >= 0.70
Requires:       grinder >= 0.0.146
Requires:       httpd
Requires:       mod_wsgi >= 3.3-3.pulp%{?dist}
Requires:       mod_ssl
%if 0%{?rhel} == 5
Requires: m2crypto
%else
Requires: m2crypto >= 0.21.1.pulp-7%{?dist}
%endif
%if %{pulp_selinux}
Requires: %{name}-selinux-server = %{version}-%{release}
%endif
BuildRequires:  rpm-python
# Both attempt to serve content at the same apache alias, so don't
# allow them to be installed at the same time.
Conflicts:      pulp

%description cds
Tools necessary to interact synchronize content from a pulp server and serve that content
to clients.

# -- headers - pulp-selinux-server ---------------------------------------------------

%if %{pulp_selinux}
%package        selinux-server
Summary:        Pulp SELinux policy for server components.
Group:          Development/Languages
BuildRequires:  rpm-python
BuildRequires:  make
BuildRequires:  checkpolicy
BuildRequires:  selinux-policy-devel
BuildRequires:  hardlink

%if "%{selinux_policyver}" != ""
Requires: selinux-policy >= %{selinux_policyver}
%endif
Requires(post): policycoreutils-python
Requires(post): selinux-policy-targeted
Requires(post): /usr/sbin/semodule, /sbin/fixfiles, /usr/sbin/semanage
Requires(postun): /usr/sbin/semodule

%description    selinux-server
SELinux policy for Pulp's server components
%endif

# -- build -------------------------------------------------------------------

%prep
%setup -q

%build
pushd src
%{__python} setup.py build
popd
%if %{pulp_selinux}
# SELinux Configuration
cd selinux/server
perl -i -pe 'BEGIN { $VER = join ".", grep /^\d+$/, split /\./, "%{version}.%{release}"; } s!0.0.0!$VER!g;' pulp-server.te
./build.sh
cd -
%endif

%install
rm -rf %{buildroot}
pushd src
%{__python} setup.py install -O1 --skip-build --root %{buildroot}
popd

# Pulp Configuration
mkdir -p %{buildroot}/etc/pulp
cp -R etc/pulp/* %{buildroot}/etc/pulp

# Pulp Log
mkdir -p %{buildroot}/var/log/pulp

# Apache Configuration
mkdir -p %{buildroot}/etc/httpd/conf.d/
cp etc/httpd/conf.d/pulp.conf %{buildroot}/etc/httpd/conf.d/

# Pulp Web Services
cp -R srv %{buildroot}

# Pulp PKI
mkdir -p %{buildroot}/etc/pki/pulp
mkdir -p %{buildroot}/etc/pki/pulp/consumer
cp etc/pki/pulp/* %{buildroot}/etc/pki/pulp

mkdir -p %{buildroot}/etc/pki/pulp/content

# Pulp Runtime
mkdir -p %{buildroot}/var/lib/pulp
mkdir -p %{buildroot}/var/lib/pulp/plugins
mkdir -p %{buildroot}/var/lib/pulp/plugins/distributors
mkdir -p %{buildroot}/var/lib/pulp/plugins/importers
mkdir -p %{buildroot}/var/lib/pulp/plugins/profilers
mkdir -p %{buildroot}/var/lib/pulp/plugins/types
mkdir -p %{buildroot}/var/lib/pulp/published
mkdir -p %{buildroot}/var/lib/pulp/published/http
mkdir -p %{buildroot}/var/lib/pulp/published/https
mkdir -p %{buildroot}/var/lib/pulp/uploads
mkdir -p %{buildroot}/var/www
ln -s /var/lib/pulp/published %{buildroot}/var/www/pub

# Pulp Plugins
cp -R plugins/types/* %{buildroot}/var/lib/pulp/plugins/types
cp -R plugins/importers/* %{buildroot}/var/lib/pulp/plugins/importers
cp -R plugins/distributors/* %{buildroot}/var/lib/pulp/plugins/distributors

# Enable when there's at least one distributor
# cp -R plugins/distributors/* %{buildroot}/var/lib/pulp/plugins/distributors

# Client and CDS Gofer Plugins
mkdir -p %{buildroot}/etc/gofer/plugins
mkdir -p %{buildroot}/%{_libdir}/gofer/plugins
cp etc/gofer/plugins/*.conf %{buildroot}/etc/gofer/plugins
cp -R src/pulp/gc_client/agent/gofer/*.py %{buildroot}/%{_libdir}/gofer/plugins
cp -R src/pulp/client/consumer/goferplugins/*.py %{buildroot}/%{_libdir}/gofer/plugins
cp src/pulp/cds/gofer/cdsplugin.py %{buildroot}/%{_libdir}/gofer/plugins

# profile plugin
mkdir -p %{buildroot}/etc/yum/pluginconf.d/
mkdir -p %{buildroot}/%{_usr}/lib/yum-plugins/
cp etc/yum/pluginconf.d/*.conf %{buildroot}/etc/yum/pluginconf.d/
cp src/pulp/client/consumer/yumplugin/pulp-profile-update.py %{buildroot}/%{_usr}/lib/yum-plugins/

# Pulp and CDS init.d
mkdir -p %{buildroot}/etc/rc.d/init.d
cp etc/rc.d/init.d/* %{buildroot}/etc/rc.d/init.d/
if [ ! -e %{buildroot}/etc/rc.d/init.d/pulp-agent ]
then
    ln -s etc/rc.d/init.d/goferd %{buildroot}/etc/rc.d/init.d/pulp-agent
fi

# Remove egg info
rm -rf %{buildroot}/%{python_sitelib}/%{name}*.egg-info

# Touch ghost files (these won't be packaged)
mkdir -p %{buildroot}/etc/yum.repos.d
touch %{buildroot}/etc/yum.repos.d/pulp.repo

# Pulp CDS
# This should match what's in gofer_cds_plugin.conf and pulp-cds.conf
mkdir -p %{buildroot}/var/lib/pulp-cds/repos
mkdir -p %{buildroot}/var/lib/pulp-cds/packages

# Pulp CDS Logging
mkdir -p %{buildroot}/var/log/pulp-cds

# Apache Configuration
mkdir -p %{buildroot}/etc/httpd/conf.d/
cp etc/httpd/conf.d/pulp-cds.conf %{buildroot}/etc/httpd/conf.d/

# Install SELinux policy modules
%if %{pulp_selinux}
cd selinux/server
./install.sh %{buildroot}%{_datadir}
mkdir -p %{buildroot}%{_datadir}/pulp/selinux/server
cp enable.sh %{buildroot}%{_datadir}/pulp/selinux/server
cp uninstall.sh %{buildroot}%{_datadir}/pulp/selinux/server
cp relabel.sh %{buildroot}%{_datadir}/pulp/selinux/server
cd -
%endif

# Admin Client Extensions
mkdir -p %{buildroot}/var/lib/pulp_client/admin/extensions
cp -R extensions/pulp_admin_auth %{buildroot}/var/lib/pulp_client/admin/extensions
cp -R extensions/pulp_admin_consumer %{buildroot}/var/lib/pulp_client/admin/extensions
cp -R extensions/pulp_repo %{buildroot}/var/lib/pulp_client/admin/extensions
cp -R extensions/pulp_tasks %{buildroot}/var/lib/pulp_client/admin/extensions
cp -R extensions/rpm_admin_consumer %{buildroot}/var/lib/pulp_client/admin/extensions
cp -R extensions/rpm_repo %{buildroot}/var/lib/pulp_client/admin/extensions
cp -R extensions/rpm_sync %{buildroot}/var/lib/pulp_client/admin/extensions
cp -R extensions/rpm_units_copy %{buildroot}/var/lib/pulp_client/admin/extensions
cp -R extensions/rpm_units_search %{buildroot}/var/lib/pulp_client/admin/extensions
cp -R extensions/rpm_upload %{buildroot}/var/lib/pulp_client/admin/extensions

# Consumer Client Extensions
mkdir -p %{buildroot}/var/lib/pulp_client/consumer/extensions
cp -R extensions/pulp_consumer %{buildroot}/var/lib/pulp_client/consumer/extensions

# Agent content handlers
mkdir -p %{buildroot}/%{_libdir}/pulp/agent/handler
mkdir -p %{buildroot}/%{_sysconfdir}/pulp/agent/handler
cp -R handlers/* %{buildroot}/%{_libdir}/pulp/agent/handler
cp -R etc/pulp/agent/handler/* %{buildroot}/%{_sysconfdir}/pulp/agent/handler

# -- clean --------------------------------------------------------------------

%clean
rm -rf %{buildroot}

# -- post - pulp server -------------------------------------------------------

%post
# chown -R apache:apache /etc/pki/pulp/content/

# -- post - pulp cds ----------------------------------------------------------

%post cds
#chown -R apache:apache /etc/pki/pulp/content/

# Create the cluster related files and give them Apache ownership;
# both httpd (apache) and gofer (root) will write to them, so to prevent
# permissions issues put them under apache
touch /var/lib/pulp-cds/.cluster-members-lock
touch /var/lib/pulp-cds/.cluster-members

chown apache:apache /var/lib/pulp-cds/.cluster-members-lock
chown apache:apache /var/lib/pulp-cds/.cluster-members

# -- post - pulp consumer ------------------------------------------------------

%post consumer
if [ "$1" = "1" ]; then
  ln -s %{_sysconfdir}/rc.d/init.d/goferd %{_sysconfdir}/rc.d/init.d/pulp-agent
fi

%if %{pulp_selinux}
%post selinux-server
# Enable SELinux policy modules
if /usr/sbin/selinuxenabled ; then
 %{_datadir}/pulp/selinux/server/enable.sh %{_datadir}
fi

# restorcecon wasn't reading new file contexts we added when running under 'post' so moved to 'posttrans'
# Spacewalk saw same issue and filed BZ here: https://bugzilla.redhat.com/show_bug.cgi?id=505066
%posttrans selinux-server
if /usr/sbin/selinuxenabled ; then
 %{_datadir}/pulp/selinux/server/relabel.sh %{_datadir}
fi

%preun selinux-server
# Clean up after package removal
if [ $1 -eq 0 ]; then
%{_datadir}/pulp/selinux/server/uninstall.sh
%{_datadir}/pulp/selinux/server/relabel.sh
fi
exit 0
%endif

# -- postun - pulp consumer ---------------------------------------------------

%postun consumer
if [ "$1" = "0" ]; then
  rm -f %{_sysconfdir}/rc.d/init.d/pulp-agent
fi

# -- postun - pulp cds --------------------------------------------------------

%postun cds
# Clean up after package removal

# -- files - pulp server -----------------------------------------------------

%files
%defattr(-,apache,apache,-)
%doc
# For noarch packages: sitelib
%attr(-, root, root) %{python_sitelib}/pulp/server/
%attr(-, root, root) %{python_sitelib}/pulp/repo_auth/
%attr(-, root, root) %{python_sitelib}/pulp/yum_plugin/
%config(noreplace) %{_sysconfdir}/httpd/conf.d/pulp.conf
%config(noreplace) %{_sysconfdir}/pulp/pulp.conf
%config(noreplace) %{_sysconfdir}/pulp/repo_auth.conf
%config(noreplace) %{_sysconfdir}/pulp/logging/*
%ghost %{_sysconfdir}/yum.repos.d/pulp.repo
%attr(-, apache, apache) /srv/pulp/webservices.wsgi
%attr(-, apache, apache) /srv/pulp/repo_auth.wsgi
/var/lib/pulp
/var/www/pub
/var/log/pulp
%config(noreplace) %{_sysconfdir}/pki/pulp
%attr(755, root, root) %{_sysconfdir}/rc.d/init.d/pulp-server
%{_bindir}/pulp-migrate

# -- files - common ----------------------------------------------------------

%files common
%defattr(-,root,root,-)
%doc
%{python_sitelib}/pulp/__init__.*
%{python_sitelib}/pulp/common/
%{_bindir}/pulp-package-migrate

# -- files - pulp client lib -----------------------------------------------------

%files client-lib
%defattr(-,root,root,-)
%doc
# For noarch packages: sitelib
%{python_sitelib}/pulp/client/api
%{python_sitelib}/pulp/client/lib
%{python_sitelib}/pulp/client/pluginlib
%{python_sitelib}/pulp/client/plugins
%{python_sitelib}/pulp/client/*.py*
%{python_sitelib}/pulp/gc_client/

# -- files - pulp client -----------------------------------------------------

%files consumer
%defattr(-,root,root,-)
%doc
# For noarch packages: sitelib
%{python_sitelib}/pulp/client/consumer
%{_bindir}/pulp-consumer
%{_bindir}/pulp-v2-consumer
%{_libdir}/gofer/plugins/
%{_libdir}/pulp/agent/handler/
%{_usr}/lib/yum-plugins/pulp-profile-update.py*
%{_sysconfdir}/gofer/plugins/pulp.conf
%{_sysconfdir}/gofer/plugins/pulpplugin.conf
%{_sysconfdir}/gofer/plugins/consumer.conf
%{_sysconfdir}/pulp/agent/handler/
%{_sysconfdir}/yum/pluginconf.d/pulp-profile-update.conf
%attr(755,root,root) %{_sysconfdir}/pki/pulp/consumer/
%config(noreplace) %attr(644,root,root) %{_sysconfdir}/yum/pluginconf.d/pulp-profile-update.conf
%config(noreplace) %{_sysconfdir}/pulp/consumer/consumer.conf
%config(noreplace) %{_sysconfdir}/pulp/consumer/v2_consumer.conf
%ghost %{_sysconfdir}/rc.d/init.d/pulp-agent
/var/lib/pulp_client/consumer

# -- files - pulp admin -----------------------------------------------------

%files admin
%defattr(-,root,root,-)
%doc
# For noarch packages: sitelib
%{python_sitelib}/pulp/client/admin
%{_bindir}/pulp-admin
%{_bindir}/pulp-v2-admin
%config(noreplace) %{_sysconfdir}/pulp/admin/admin.conf
%config(noreplace) %{_sysconfdir}/pulp/admin/v2_admin.conf
%config(noreplace) %{_sysconfdir}/pulp/admin/task.conf
%config(noreplace) %{_sysconfdir}/pulp/admin/job.conf
/var/lib/pulp_client/admin

# -- files - pulp cds --------------------------------------------------------

%files cds
%defattr(-,apache,apache,-)
%doc
%{python_sitelib}/pulp/cds/
%{python_sitelib}/pulp/repo_auth/
%{_sysconfdir}/gofer/plugins/cdsplugin.conf
%{_libdir}/gofer/plugins/cdsplugin.*
%attr(775, apache, apache) /srv/pulp
%attr(750, apache, apache) /srv/pulp/cds.wsgi
%config %{_sysconfdir}/httpd/conf.d/pulp-cds.conf
%config(noreplace) %{_sysconfdir}/pulp/cds.conf
%config(noreplace) %{_sysconfdir}/pulp/repo_auth.conf
%attr(775, apache, apache) %{_sysconfdir}/pki/pulp
%attr(775, root, root) %{_sysconfdir}/rc.d/init.d/pulp-cds
%attr(3775, apache, apache) /var/lib/pulp-cds
%attr(3775, apache, apache) /var/lib/pulp-cds/repos
%attr(3775, apache, apache) /var/lib/pulp-cds/packages
%attr(3775, apache, apache) /var/log/pulp-cds

%if %{pulp_selinux}
%files selinux-server
%defattr(-,root,root,-)
%doc selinux/server/pulp-server.fc selinux/server/pulp-server.if selinux/server/pulp-server.te
%{_datadir}/pulp/selinux/server/*
%{_datadir}/selinux/*/pulp-server.pp
%{_datadir}/selinux/devel/include/%{moduletype}/pulp-server.if
%endif

# -- changelog ---------------------------------------------------------------

%changelog
* Fri Jun 08 2012 Jeff Ortel <jortel@redhat.com> 0.0.295-1
- bump to gofer 0.69. (jortel@redhat.com)
- Add support for linking rpms units referenced with in a errata
  (pkilambi@redhat.com)
- Automatic commit of package [gofer] minor release [0.69-1].
  (jortel@redhat.com)
- Copying comps_util.py from pulp.server to pulp.yum_plugin so YumImporter may
  use this (jmatthews@redhat.com)
- YumImporter: test data for a simple repo with no comps (jmatthews@redhat.com)
- Added a warning in pulp-dev for when a dir exists but we expected it to be a
  symlink (jmatthews@redhat.com)
- Added unit copy extension to the RPM (jason.dobies@redhat.com)
- YumImporter/YumDistributor update unit tests to configure logger and redirect
  output from console to log file (jmatthews@redhat.com)
* Mon Jun 04 2012 Jeff Ortel <jortel@redhat.com> 0.0.294-1
- updated copyright information (jason.connor@gmail.com)
- Hide the auth ca cert, just show if one is present (jason.dobies@redhat.com)
- Changed triggers for consistency across the UI (jason.dobies@redhat.com)
- consumer cli extension for bind, unbind and minor re-structuring of
  consumerid function (skarmark@redhat.com)
- Changing order of consumer history result and removing unwanted _id
  (skarmark@redhat.com)
- removing consumer id validation from consumer history querying to allow
  querying for unregistered consumer as well (skarmark@redhat.com)
- Fixing unbind client extension error (skarmark@redhat.com)
- Update .gitignore to ignore test coverage output files (jmatthews@redhat.com)
- YumImporter:  Change 'fileName' to 'filename' for drpm (jmatthews@redhat.com)
- added deprecated notice to doctring (jason.connor@gmail.com)
- Fixed async response handling (jason.dobies@redhat.com)
- YumDistributor:  Added check to see if createrepo pid is running before
  canceling (jmatthews@redhat.com)
- YumDistributor: continue to debug errors from running with jenkins
  (jmatthews@redhat.com)
- Python 2.4 compatibility change for determining if Iterable
  (jmatthews@redhat.com)
- YumDistributor, debugging intermittent test failure when run from jenkins
  (jmatthews@redhat.com)
- YumImporter:  removed filename from srpm unit key (jmatthews@redhat.com)
- Fix for rhel5 unit tests, collections.Iterable doesn't exist
  (jmatthews@redhat.com)
- Fixed to use correct link call (jason.dobies@redhat.com)
- Revert "idempotent misspelled" (jason.connor@gmail.com)
- Revert "removed not_implemented() controllers" (jason.connor@gmail.com)
- Revert "removed unnecessary quotes around controller class names"
  (jason.connor@gmail.com)
- Revert "added _href fields to resources in repositories collection"
  (jason.connor@gmail.com)
- Revert "added _href field to new created repository" (jason.connor@gmail.com)
- Revert "added _href for repo resources" (jason.connor@gmail.com)
- added _href for repo resources (jason.connor@gmail.com)
- added _href field to new created repository (jason.connor@gmail.com)
- added _href fields to resources in repositories collection
  (jason.connor@gmail.com)
- changed sync overrides to a keyword argument (jason.connor@gmail.com)
- removed unnecessary quotes around controller class names
  (jason.connor@gmail.com)
- removed not_implemented() controllers (jason.connor@gmail.com)
- idempotent misspelled (jason.connor@gmail.com)
- changed task lookups to use new task_queue factory instead of accessing it
  via the coordinator (jason.connor@gmail.com)
- 827221 - Added individual resource GET methods and hrefs to resources
  (jason.dobies@redhat.com)
- 827220 - Removed old error_handler directives (jason.dobies@redhat.com)
- YumDistributor:  cancel_publish implementation and unit tests
  (jmatthews@redhat.com)
- Test data for simulating a long running createrepo process
  (jmatthews@redhat.com)
- added cleanup of mocked-out factory functions (jason.connor@gmail.com)
- fixed consumer controller entry (jason.connor@gmail.com)
- Delete the upload request if its rejected (jason.dobies@redhat.com)
- fix relativepath of the rpm during upload (pkilambi@redhat.com)
- Updated user guide for 1.1 (jason.dobies@redhat.com)
- utilized new factory access to move complete lifecycle callback out of
  scheduler class to a stand-alone function (jason.connor@gmail.com)
- changed tests to reflect changes in scheduler (jason.connor@gmail.com)
- remoced collection instance from scheduler as well (jason.connor@gmail.com)
- while I was at it I eliminated the task resource collection as state as well
  and instead use the get_collection factory method that is a part of every
  Model class (jason.connor@gmail.com)
- changed unit tests to reflect changes in coordinator (jason.connor@gmail.com)
- changed initialization of scheduler and coordinator to reflect changes in
  constructors (jason.connor@gmail.com)
- removed task queue as internal state and instead access it through the
  dispatch factory (jason.connor@gmail.com)
- added task queue factory function and updated the return types of the factory
  functions while I was at it (jason.connor@gmail.com)
- updated unittests to reflect changes in scheduler (jason.connor@gmail.com)
- removed the coordinator as state and instead use the factory to access it
  (jason.connor@gmail.com)
- removed unused imports (jason.connor@gmail.com)
- removed unused import (jason.connor@gmail.com)
- moved all imports into initialization methods to avoid circulary imports this
  will allow the different modules of the dispatch package to access each other
  via the factory in order keep the amount of state (read: references to each
  other) to a minimum (jason.connor@gmail.com)
- added super setup/teardown of old mocked async to keep clean happy
  (jason.connor@gmail.com)
- cleaned up imports and future proofed json_util import
  (jason.connor@gmail.com)
- moved exception handling into loop for better reporting
  (jason.connor@gmail.com)
- change mkdir to makedirs for better parental supervision
  (jason.connor@gmail.com)
- Added handling for async responses when importing units
  (jason.dobies@redhat.com)
- Added UG for repo tasks (jason.dobies@redhat.com)
- Added UG section for describing postponed and rejected tasks
  (jason.dobies@redhat.com)
- Fixed incongruences in the sync user guide (jason.dobies@redhat.com)
- Added user guide entry for repo publish (jason.dobies@redhat.com)
- User guide for package upload (jason.dobies@redhat.com)
- remove filename from rpm unit key (pkilambi@redhat.com)
- Cleanup for the consumer packages section of the user guide
  (jason.dobies@redhat.com)
- Corrected handling/display for operations postponed by the coordinator
  (jason.dobies@redhat.com)
- Refactored out bool conversion so it can be used directly
  (jason.dobies@redhat.com)
- Added publish schedule support to the RPM CLI extensions
  (jason.dobies@redhat.com)
- Added direct publish support (jason.dobies@redhat.com)
- Added enabled/disabled support for all RPM extensions
  (jason.dobies@redhat.com)

* Fri May 25 2012 Jeff Ortel <jortel@redhat.com> 0.0.293-1
- Fix .spec for moving agent handlers. (jortel@redhat.com)
- Add comments with Config usage and examples. (jortel@redhat.com)

* Fri May 25 2012 Jeff Ortel <jortel@redhat.com> 0.0.292-1
- Better section filtering in gc_config. (jortel@redhat.com)
- YumImporter:  Added cancel sync (jmatthews@redhat.com)
- Implement upload_unit in yum importer (pkilambi@redhat.com)
- Final code clean up and tweaks (jason.dobies@redhat.com)
- Removed delete call from import, it doesn't belong there
  (jason.dobies@redhat.com)
- Don't return the report, it will be stuffed into history instead
  (jason.dobies@redhat.com)
- Added upload extension to the RPM (jason.dobies@redhat.com)
- Added filename to unit key temporarily (jason.dobies@redhat.com)
- Wrong call to import the unit (jason.dobies@redhat.com)
- Default the relative URL to repo ID for feedless repos
  (jason.dobies@redhat.com)
- Turned on the import step (jason.dobies@redhat.com)
- admin consumer bind and unbind extension (skarmark@redhat.com)
- Fix agent unregistered(), delete of consumer cert. (jortel@redhat.com)
- Rename (distributor) handler role to: (bind). (jortel@redhat.com)
- Move GC agent handlers to: /etc/pulp/agent & /usr/lib/pulp/agent.
  (jortel@redhat.com)
- Fix epydoc typos. (jortel@redhat.com)
- Initial working version of the upload CLI (jason.dobies@redhat.com)
- Remove default {} from report signatures; fix epydoc. (jortel@redhat.com)
- Add linux system handler to git. (jortel@redhat.com)
- Add a ton of missing GC packages and tests. (jortel@redhat.com)
- Fixing syntax error at the end of params in the api doc (skarmark@redhat.com)
- GC agent: add (system) role and refactor reboot(). (jortel@redhat.com)
- Fix title for consistency (jason.dobies@redhat.com)
- Another minor rendering fix for consumer history api doc (3rd time's the
  charm) (skarmark@redhat.com)
- Minor rendering fix for consumer history api doc (skarmark@redhat.com)
- updated docstring (jason.connor@gmail.com)
- Fixing title of consumer history api doc (skarmark@redhat.com)
- In GC agent, add initial mapping for package group installs.
  (jortel@redhat.com)
- Update epydocs. (jortel@redhat.com)
- Refactor Handler interface for clarity.  Fix bind handler using
  ConsumerConfig. (jortel@redhat.com)

* Thu May 24 2012 Jeff Ortel <jortel@redhat.com> 0.0.291-1
- yum_importer proxy fix to force config values to be in ascii
  (jmatthews@redhat.com)
- minor fix in consumer history retrieval (skarmark@redhat.com)
- converting consumer history query call to GET from POST (skarmark@redhat.com)
- added skeleton Profiler loading support (jason.connor@gmail.com)
- added skeleton Profiler class (jason.connor@gmail.com)
- Added sample response for retrieving a single consumer api
  (skarmark@redhat.com)
- Removing importer retrieval doc pasted by mistake in consumer docs
  (skarmark@redhat.com)
- For consistency, use repo-id in all cases (jason.dobies@redhat.com)
- updating display_name argument coming from client extension to display-name
  and updating argument to MissingResource exception (skarmark@redhat.com)
- removing (optional) from cli arguments (skarmark@redhat.com)
- Add the repo to the upload_unit API (jason.dobies@redhat.com)
- Fixing minor errors in consumer extensions and correcting rendering methods
  for failure cases (skarmark@redhat.com)
- Remove unused files from gc_client/. (jortel@redhat.com)
- Factor out references to: credentials/config in: gc_client/consumer and
  gc_client/lib. (jortel@redhat.com)
- Added call report example (jason.dobies@redhat.com)
- Added client upload manager and unit tests (jason.dobies@redhat.com)
- added tags to delete operations (jason.connor@gmail.com)
- changed field names and provided sample request (jason.connor@gmail.com)
- remove unicode indicators from sample response (jason.connor@gmail.com)
- changed content_type to content_type_id and content_id to unit_id for
  consistency across apis (jason.connor@gmail.com)
- moved key checking to manager (jason.connor@gmail.com)
- updated copyright (jason.connor@gmail.com)
- changed new schedules to always have their "first run" in the future
  (jason.connor@gmail.com)
- moved schedule validation out of db model (jason.connor@gmail.com)
- much more comprehensive parameter validation in for additions and updates
  (jason.connor@gmail.com)
- added unsupported value exception class (jason.connor@gmail.com)
- Using consumer config loaded by launcher instead of using hardcoded config in
  ConsumerBundle and ConsumerConfig classes (skarmark@redhat.com)
- move heartbeat and registration detection to GC agent (jortel@redhat.com)
- Add rpm admin consumer extension unit test. (jortel@redhat.com)
- Add package install UG pages. (jortel@redhat.com)
- combining all consumer history record and query invalid values together to
  raise an exception with a list of all invalid values instead of separate
  exceptions for each invalid value (skarmark@redhat.com)
- Changing consumer history query extension arguments from '_' to '-' according
  to v2 coding standard; updating input to MissingResource exceptions
  (skarmark@redhat.com)
- support veriety of input on construction. (jortel@redhat.com)
- Fixed incorrect lookup for display-name in update (jason.dobies@redhat.com)
- adding new fields to publish report (pkilambi@redhat.com)
- Display remaining runs for a schedule (jason.dobies@redhat.com)
- Added middleware support for arg parsing exception (jason.dobies@redhat.com)
- Add strict vs. non-strict flag on config graph. (jortel@redhat.com)
- Add dict-like configuration object and updated validation.
  (jortel@redhat.com)
- Added repo sync schedule user guide documentation (jason.dobies@redhat.com)
- Load content handlers on gofer plugin loading. (jortel@redhat.com)
- validation placeholders (jason.connor@gmail.com)
- couple of tweaks (jason.connor@gmail.com)
- orphan rest api docs (jason.connor@gmail.com)
- added schedule validation for updates (jason.connor@gmail.com)
- moved scheduler constants back into scheduler module and absolutely no one
  else uses them... (jason.connor@gmail.com)
- added missing coordinator reponses for updated and delete sync/publish
  schedules (jason.connor@gmail.com)
- bz 798281 add status call to service pulp-cds (whayutin@redhat.com)
- 821041 - packagegroup install of custom groups seems to be failing
  (jmatthews@redhat.com)
- Flushed out date/time conventions in the user guide (jason.dobies@redhat.com)
- Added cleaner message when no schedules are present (jason.dobies@redhat.com)
- mod auth token prototype (pkilambi@redhat.com)
- Added generic schedule commands and repo sync schedule usage of them
  (jason.dobies@redhat.com)
- re-captured isodate parsing and raising InvalidValue error instead for proper
  handling in the middleware (jason.connor@gmail.com)
- re-introduced v1 task queue feature of caching completed tasks
  (jason.connor@gmail.com)
- added orphan manager unittests (jason.connor@gmail.com)

* Fri May 18 2012 Jeff Ortel <jortel@redhat.com> 0.0.290-1
- Fix broken GC package install CLI. (jortel@redhat.com)
- Utilities for handling CLI argument conventions (jason.dobies@redhat.com)
- removing checks to support no pulishing (pkilambi@redhat.com)
- GC bind: hook up handler and repolib. (jortel@redhat.com)
- Upgraded okaara to 1.0.18 (jason.dobies@redhat.com)
- Updated base command class to use okaara's option description prefixing
  (jason.dobies@redhat.com)
- temp disablement of task archival task until race condition can be resolved
  (jason.connor@gmail.com)
- Disable all tasks view by default (enabled in .conf)
  (jason.dobies@redhat.com)
- orphan manager unit tests (jason.connor@gmail.com)
- fixed missing .items() while iterating over dictionary
  (jason.connor@gmail.com)
- removed unused options argument to collection constructor which just went
  away in pymongo 2.2 anyway (jason.connor@gmail.com)
- place running tasks before waiting tasks when returning all tasks to maintain
  a closer representation of the enqueue time total ordering on the task set
  (jason.connor@gmail.com)
- added archive to all delete requests (jason.connor@gmail.com)
- added auth_required decorators to all orphan controllers
  (jason.connor@gmail.com)
- added mac special dir to ignore (jason.connor@gmail.com)
- moved archival test to task queue tests (jason.connor@gmail.com)
- removed archival from task tests (jason.connor@gmail.com)
- moved call archival from task into task queue to prevent race condition in
  task queries (jason.connor@gmail.com)
- converted to _id for unit ids (jason.connor@gmail.com)
- initial implementation of delete orphans action (jason.connor@gmail.com)
- utilizing changed field names (jason.connor@gmail.com)
- changed fields to more managable content_type and content_id
  (jason.connor@gmail.com)
- initial implementation of orphan collections and resources
  (jason.connor@gmail.com)
- added get_orphan method (jason.connor@gmail.com)
- added orphan manager to factory (jason.connor@gmail.com)
- added comment (jason.connor@gmail.com)
- Add yum repo (bind) handler; more bind plumbing. (jortel@redhat.com)
- Update mock distributor bind payload. (jortel@redhat.com)
- Updated bind (GET) to include distributor payload. (jortel@redhat.com)
- updating payload info (pkilambi@redhat.com)
- Last docs tweak for today, I swear (jason.dobies@redhat.com)
- Added background functionality to repo sync run (jason.dobies@redhat.com)
- fix for updating the state when a distribution symlink step fails
  (pkilambi@redhat.com)
- Consumer history manager layer, controller and adminclient extension
  (skarmark@redhat.com)
- Added a status call to the repo to see if it is synccing
  (jason.dobies@redhat.com)
- Added ability to resume tracking an in progress sync and refactored extension
  to separate sync running and scheduling commands (jason.dobies@redhat.com)
- Fixed tags lookup from query parameters (jason.dobies@redhat.com)
- Tasks extension unit tests and code cleanup (jason.dobies@redhat.com)
- Update GC content handler framework to support bind(). (jortel@redhat.com)
- Implementation of task list, details, and delete commands
  (jason.dobies@redhat.com)
- Flushed out client-side task API (jason.dobies@redhat.com)
- Refactored response object structure in client API (jason.dobies@redhat.com)
- Updated 404 exception handling to handle new data dict format
  (jason.dobies@redhat.com)
- moved log file to get full path into message (jason.connor@gmail.com)
- implementation of orphan manager (jason.connor@gmail.com)
- fixed some spelling errors (jason.connor@gmail.com)
- Move GC agent lib under (lib); Add pulp bindings to agent.
  (jortel@redhat.com)
- Update RPM handler and gofer plugin for GC agent move to gc_client.
  (jortel@redhat.com)
- Update pulp.spec for GC agent moved to gc_client. (jortel@redhat.com)
- Move GC agent under gc_client. (jortel@redhat.com)
- Add bindings query by consumer/repo in API; Add binding query to GC client
  API. (jortel@redhat.com)
- adding host_urls and renaming few keys in payload (pkilambi@redhat.com)
- minor changes to payload structure (pkilambi@redhat.com)
- implement the consumer payload in distributor (pkilambi@redhat.com)
- Fix GC agent & rpm handler reboot logic; support update ALL.
  (jortel@redhat.com)
- Ported v1 protected repositories into the v2 documentation
  (jason.dobies@redhat.com)
* Fri May 11 2012 Jeff Ortel <jortel@redhat.com> 0.0.289-1
- Updated to correct importer/distributor config values
  (jason.dobies@redhat.com)
- Corrected _ to - in the user guide (jason.dobies@redhat.com)
- Unit tests for unit copy (jason.dobies@redhat.com)
- Added gt, gte, lt, lte, after, and before functionality to unit copy
  (jason.dobies@redhat.com)
- Added unit copy API to client bindings (jason.dobies@redhat.com)
- fix test districutor to use mock (pkilambi@redhat.com)
- fix tests to use a mock object (pkilambi@redhat.com)
- Initial implementation of the unit copy extension (jason.dobies@redhat.com)
- Protected Repos: - support for writing consumer cert to specific location
  based on repo_auth.conf - update protected_repo_listings file - implement
  distributor_remove hook to clean up on repo delete (pkilambi@redhat.com)
- Renamed underscore CLI flags to use the hyphens convention
  (jason.dobies@redhat.com)
- added cross references for asynchronous call reports and the task dispatch
  api (jason.connor@gmail.com)
- initial placeholder for orphan manager (jason.connor@gmail.com)
- added dispatch to index (jason.connor@gmail.com)
- start of dispatch apis (jason.connor@gmail.com)

* Tue May 08 2012 Jeff Ortel <jortel@redhat.com> 0.0.288-1
- 819589 - casting all kwarg keys to str (jason.connor@gmail.com)
- removed cast to timedelta from isodate.Duration (jason.connor@gmail.com)
- Consumer 'rpm' extension replaces generic 'content' extension when installed.
  (jortel@redhat.com)
- some json v python corrections and start of new section on iso8601
  (jason.connor@gmail.com)
- Add --no-commit to GC content extension. (jortel@redhat.com)
- Changed handling of http/https flags so they are only defaulted in create
  (jason.dobies@redhat.com)
- changed _do_request to allow multiple polls to be sent to task url
  (jason.connor@gmail.com)
- changed aynchronous support to only set success or failure if the task is
  actually running changed asynchronous support to guaruntee only 1 call into
  coordinator changed asynchronous support to allow multiple calls into
  controllers per unittest so long as set_success or set_failure is called
  before each asynchronous controller is called (jason.connor@gmail.com)
- Unit metadata is optional for unit import (jason.dobies@redhat.com)
- Create the necessary directories for content uploads
  (jason.dobies@redhat.com)
- convert the ssl certs queried from mongo to utf8 before passing to m2crypto
  (pkilambi@redhat.com)
- GC agent; enable authorization. (jortel@redhat.com)
- CallRequest(asynchronous=True); Simulate agent reply in GC consumer
  controller unit test. (jortel@redhat.com)
- make --importkeys a flag. (jortel@redhat.com)
- removed generic scheduled tag and added schedule resource tag
  (jason.connor@gmail.com)

* Thu May 03 2012 Jeff Ortel <jortel@redhat.com> 0.0.287-2
- move gc_client to client-lib. (jortel@redhat.com)

* Thu May 03 2012 Jeff Ortel <jortel@redhat.com> 0.0.287-1
- Support -n alias for GC content install CLI. (jortel@redhat.com)
- Add support for str|list|tuple tracebacks. (jortel@redhat.com)
- Enhanced gc & rpm content install CLI. (jortel@redhat.com)
- Better error handling in generic content install CLI. (jortel@redhat.com)
- Refactor admin cli to split generic content unit vs. rpm install.
  (jortel@redhat.com)
- YumImporter:  Fix for rhel5 issue with itertools.chain.from_iterable
  (jmatthews@redhat.com)
- Added REST APIs for content upload (jason.dobies@redhat.com)
- publish added to index (jason.connor@gmail.com)
- publish api documentation (jason.connor@gmail.com)
- corrected a number of typos (jason.connor@gmail.com)
- fixes to sync doc (jconnor@redhat.com)
- no longer recording duplicate reasons for postponed and rejected
  (jconnor@redhat.com)
- updated tags to use new resource_tag generation (jconnor@redhat.com)
- replaced spaces in resource types with underscores (jconnor@redhat.com)
- removed leading underscores for scheduled call object fields
  (jconnor@redhat.com)
- removed superfluous part of child path for sync/publish schedules
  (jconnor@redhat.com)
- fixed typo in docstring (jconnor@redhat.com)
- Render content install,update,uninstall results. (jortel@redhat.com)
- YumDistributor:  Update to remove http/https link if no longer set to True in
  config (jmatthews@redhat.com)
- convert the cert strings to utf-8 before passing to grinder; also fixed
  default sslverify value if not specified (pkilambi@redhat.com)
- Differentiate association owner for uploaded v. syncced units
  (jason.dobies@redhat.com)
- YumImporter:  First pass at handling sync of a protected repo
  (jmatthews@redhat.com)
- Added distribution support for repo units display (jason.dobies@redhat.com)
- Docs cleanup (jason.dobies@redhat.com)
- YumDistributor:  Fix for unicode relative_url validation
  (jmatthews@redhat.com)
- forgot to use $set, so I was completely overwriting the fields instead of
  just setting a sub-set of them (jason.connor@gmail.com)
- fixed too short underline (jason.connor@gmail.com)
- repo sync documentation (jason.connor@gmail.com)
- fixed up scheduled call serialization (jason.connor@gmail.com)
- added sync to index (jason.connor@gmail.com)
- changed all scheduled sync and publish controllers to use new serialization
  (jason.connor@gmail.com)
- added specific serialization for scheduled sync and publish
  (jason.connor@gmail.com)
- fixed comment typo (jason.connor@gmail.com)
- added more fields to call report (jason.connor@gmail.com)
- removed assumptions and generalized scheduled call object
  (jason.connor@gmail.com)
- added iso8601 interval to gloassary (jason.connor@gmail.com)
- added call report to glossary (jason.connor@gmail.com)
- Added publish progress support to sync status. (jason.dobies@redhat.com)
- Adding multiple content unit install support (skarmark@redhat.com)
- Ensure report contains 'details' on exceptoin as well. (jortel@redhat.com)
- Refactored out the progress report rendering (jason.dobies@redhat.com)
- client extension for a consumer content unit install (skarmark@redhat.com)
- Docs cleanup (jason.dobies@redhat.com)
- including http/https publish progress info in report (pkilambi@redhat.com)
- Implementation of v2 storage of uploaded files (jason.dobies@redhat.com)
- YumDistributor:  Implementation of 'http' publishing option
  (jmatthews@redhat.com)
- Added 'keys()' method to return a set of all keys available from the
  underlying dicts (jmatthews@redhat.com)
- YumImporter:  Made feed_url optional and ensure we invoke progress report for
  NOT_STARTED as first step (jmatthews@redhat.com)
- Client bindings for consumer content unit install (skarmark@redhat.com)
- updating doc strings to  include progress callback description
  (pkilambi@redhat.com)
- default progress arg to None (pkilambi@redhat.com)
- first pass at changes to support Yum Distributor publish progress reporting
  (pkilambi@redhat.com)
- Base unit addition/linking conduit (jason.dobies@redhat.com)
- Refactored out base unit add conduit support to better scope the upload
  conduit (jason.dobies@redhat.com)
- Adding consumer credential support from v1 to v2 (skarmark@redhat.com)
- Added ability to store consumer cert bundle for v2 consumers
  (skarmark@redhat.com)
- schedule creation using configured create_weight (jconnor@redhat.com)
- converted all tags to use new generic tags functions (jconnor@redhat.com)
- adding tag generating functions to common (jconnor@redhat.com)
- changed scheduled sync/publish to use controller (jason.connor@gmail.com)
- re-implementation of sync and publish schedule controllers using schedule
  manager (jason.connor@gmail.com)
- added schedule_manager to managers factory (jason.connor@gmail.com)
- fixed override config keyword argument publish schedule update fixed schedule
  update keyword arguments (jason.connor@gmail.com)
- added return of schedule_id to publish create (jason.connor@gmail.com)
- fixed schedule update keyword arguments fixed repo importer manager
  constructor arguments (jason.connor@gmail.com)
- converting _id to string in schedule report (jason.connor@gmail.com)
- removed _id that needed more processing, added failure_threshold
  (jason.connor@gmail.com)
- fixed check for schedule (jason.connor@gmail.com)
- added required flag for dict validation (jconnor@redhat.com)
- add/remove/list publish schedule functionality (jconnor@redhat.com)
- add/remove/list sync schedule functionality (jconnor@redhat.com)
- finished implementation of scheduled sync/publish cud operations
  (jconnor@redhat.com)
- removed old import (jconnor@redhat.com)
- schedule managers skeletons (jconnor@redhat.com)
- sync schedule method place holders (jconnor@redhat.com)
- sync schedule collection list (jconnor@redhat.com)
- Add TODO: in consumer controller. (jortel@redhat.com)
- Initial add of repo sync 'schedule' subsection. (jortel@redhat.com)
- Added importer API for upload and manager to call into it
  (jason.dobies@redhat.com)
- Updated epydocs. (jortel@redhat.com)
- YumImporter:  implementation for import_units (jmatthews@redhat.com)
- YumDistributor:  Reduce logging output (jmatthews@redhat.com)
- Correct API docs. (jortel@redhat.com)

* Mon Apr 30 2012 Jeff Ortel <jortel@redhat.com> 0.0.286-1
- (hack) disabled agent authentication on GC Agent for v1 compat.
  (jortel@redhat.com)
- update perms. (jortel@redhat.com)
- Fixing notes referenced before assignment when not provided by user at the
  registration time (skarmark@redhat.com)
- v1 compat; updated pulp-dev for content handlers (jortel@redhat.com)
- symlink distribution files publishing in distributor (pkilambi@redhat.com)
- updated epydocs. (jortel@redhat.com)
- Update pulp.spec to install agent content handlers. (jortel@redhat.com)
- Refined handler dispatching and rpm handler. (jortel@redhat.com)
- Refactor agent proxy into hub/direct; initial add of rpm handler.
  (jortel@redhat.com)
- 816808 - fixing consumer unbind through goferplugin failing to delete repo
  from pulp.repo file due to wrong encoding for i18n repo ids
  (skarmark@redhat.com)
- 802447 - consumer and consumergroup bind to be able to bind to repos with
  i18n id (skarmark@redhat.com)
- updating spec with new grinder needed for skip list changes
  (pkilambi@redhat.com)
- Automatic commit of package [grinder] minor release [0.1.3-1].
  (pkilambi@redhat.com)
- bumping grinder (pkilambi@redhat.com)
- Automatic commit of package [gofer] minor release [0.68-2].
  (jortel@redhat.com)
- unifying the skip list between importer and distributor (pkilambi@redhat.com)
- Add missing gofer 0.68 tarball. (jortel@redhat.com)
* Thu Apr 26 2012 Jeff Ortel <jortel@redhat.com> 0.0.285-2
- Update .spec for client/agent python package. (jortel@redhat.com)

* Wed Apr 25 2012 Jeff Ortel <jortel@redhat.com> 0.0.285-1
- Better gofer/agenthub cross compat. (jortel@redhat.com)
- Refector gc agent into capabilities. (jortel@redhat.com)
- Move task context lookup. (jortel@redhat.com)
- Move GC agent directly under (client) package. (jortel@redhat.com)
- RHEL 5/6 iniparse compat. (jortel@redhat.com)
- 814772 - adding i18n repo id encoding when searching through scheduled tasks
  (skarmark@redhat.com)
  (jortel@redhat.com)
- changing the verify_exists mock to use util call (pkilambi@redhat.com)
- Automatic commit of package [grinder] minor release [0.1.2-1].
  (pkilambi@redhat.com)
- first pass at distribution support in yumImporter; also updating grinder
  version (pkilambi@redhat.com)
- 800525 - fix paths in /var/lib/pulp-cds/.cds_repo_list to be: repos
  /<relative-path>. (jortel@redhat.com)
- Initial add of GC agent content handler framework. (jortel@redhat.com)
- consumer notes cli input refactoring for admin and consumer register as well
  as updates (skarmark@redhat.com)
- YumDistributor: Update to use same method for getting relative_url in
  conflict detection as used in publishing (jmatthews@redhat.com)
- YumDistributor: update to account for pulp_configs being a list - Basic
  functionalty working from Pulp (jmatthews@redhat.com)
- Rename metadata to: unit_key for content install flows. (jortel@redhat.com)
- YumDistributor: First pass at adding relative_url uniqueness
  (jmatthews@redhat.com)
- Added a number of new importer/distributor config options to the CLI
  (jason.dobies@redhat.com)
- adding config option validation to yum distributor (pkilambi@redhat.com)
- change assumption of cert config values being paths instead of certs
  themselves (pkilambi@redhat.com)
- Implemented distributor API and manager call for consumer payload generation
  (jason.dobies@redhat.com)

* Wed Apr 18 2012 Jeff Ortel <jortel@redhat.com> 0.0.284-1
- 802447 - removing wrong unicode encoding of file handler instead of file
  contents (skarmark@redhat.com)
- adding config voption validation to yum importer (pkilambi@redhat.com)
- added custom call report that records the schedule_id (jconnor@redhat.com)
- added schedule_id field to call report (jconnor@redhat.com)
- added ability to pass in custom call report on all single call request
  execution calls (jconnor@redhat.com)
- moved constants to constants module (jconnor@redhat.com)
- added scheduled call update method (jconnor@redhat.com)
- moved key validation into a utility function (jconnor@redhat.com)
- fixed passing None into dateutils (jconnor@redhat.com)
- update key comparison (jconnor@redhat.com)
- removed unnecessary interval_in_seconds field and calculate the interval on
  the fly, allowing cleaner reporting as well as variable length interval such
  as 1 month, 1 year, etc (jconnor@redhat.com)
- added subdict utilty class (jconnor@redhat.com)
- Implemented related repos concept in plugin validate config
  (jason.dobies@redhat.com)
- 802447 - encoding i18n repoid in repo file before installing on the consumer
  (skarmark@redhat.com)
- Removing failing outdated v1 consumer controller tests (skarmark@redhat.com)
- Adding checks to verify checksum/size to verify package exists
  (pkilambi@redhat.com)
- Added repo create and update documentation. (jason.dobies@redhat.com)
- Added ability to manipulate notes on repo create/update
  (jason.dobies@redhat.com)
- Update invalid_ca & invalid_ca_key for test_oid (jmatthews@redhat.com)
- Changed semantics on how repo update works on notes (jason.dobies@redhat.com)
- Changes to importer API for import_units (jason.dobies@redhat.com)
- Making consumer list default to summary and adding --details option to list
  details (skarmark@redhat.com)

* Fri Apr 13 2012 Jeff Ortel <jortel@redhat.com> 0.0.283-1
- Adding /var/lib/pulp_client/consumer in specfile to consumer's list of file
  (skarmark@redhat.com)
- Adding copying of pulp_admin_consumer and pulp_consumer client extensions in
  specfile (skarmark@redhat.com)
- 798803 - added missing premission remove when revoking permissions from a
  role (jconnor@redhat.com)
- Publish progress reports will now merge with sync results on auto publish
  (jason.dobies@redhat.com)
* Thu Apr 12 2012 Jeff Ortel <jortel@redhat.com> 0.0.282-1
- 796292 - adding simple check for None return from package lookup
  (jconnor@redhat.com)
- 790919 - updated parametes to reflect acutal parameters not outdated ones
  (jconnor@redhat.com)
- 791341 - moved role removal into own loop (jconnor@redhat.com)
- 791341 - removing role name from user roles when role is deleted
  (jconnor@redhat.com)
- Connect agent_manager to agent proxy; update unit tests. (jortel@redhat.com)
- Add agent proxy unit tests and mocks. (jortel@redhat.com)
- 809234 - added content-length header for base class response returns
  (jconnor@redhat.com)
- tests to validate drpms on filesystem (pkilambi@redhat.com)
- YumImporter:  Fix path issue on resync of a rpm and update CLI to display
  error message (jmatthews@redhat.com)
- Automatic commit of package [python-okaara] minor release [1.0.14-1].
  (jason.dobies@redhat.com)
- Upgraded okaara to 1.0.14 (jason.dobies@redhat.com)
- Added errata count to sync output (jason.dobies@redhat.com)
- adding pulp-v2-consumer and v2_consumer.conf to spec file
  (skarmark@redhat.com)
- updating spec to include pulp.yum_plugin (pkilambi@redhat.com)
- clean up and move updateinfo to yum_plugin package (pkilambi@redhat.com)
- change the utils to use new yum_plugin package (pkilambi@redhat.com)
- Automatic commit of package [grinder] minor release [0.0.146-1].
  (jmatthews@redhat.com)
- Bump to Grinder .146 (jmatthews@redhat.com)
- YumImporter:  Remove exception from being added to sync report/progress
  (jmatthews@redhat.com)
- fixing the drpm sync to store the units in the correct location and symlink
  to working directory (pkilambi@redhat.com)
- changed get and find interfaces to return scheduled call requests instead of
  tuples (jconnor@redhat.com)
- added schedule_id filed to scheduled call request (jconnor@redhat.com)
- copy importer repodata to the distributor location on publish and before
  generating metadata (pkilambi@redhat.com)
- Automatic commit of package [grinder] minor release [0.0.145-1].
  (jmatthews@redhat.com)
- Bumped grinder to .145 (jmatthews@redhat.com)
- changing the call to get the info from scratchpad (pkilambi@redhat.com)
- Wrap exceptions from the conduit in the proper wrapper
  (jason.dobies@redhat.com)
- Fixed missing string substitution (jason.dobies@redhat.com)
- Default generate_metadata to true in the added distributor
  (jason.dobies@redhat.com)
- Consolidate agent manager API. (jortel@redhat.com)
- move GC agent proxy onto separate package. (jortel@redhat.com)
- YumDistributor:  added a full publish test (jmatthews@redhat.com)
- 807002 - Fixed incorrect help on RPM unit search (jason.dobies@redhat.com)
- Convert SSL certificate expiration into a PermissionException
  (jason.dobies@redhat.com)
- Removing V1 test_remove_filters test which is randomly failing because of
  repodata unavailable, this will changed in v2 (skarmark@redhat.com)
- Add missing (options) to content.uninstall(). (jortel@redhat.com)
- Rename (jason.dobies@redhat.com)
- Slight restructuring of rpm user guide (jason.dobies@redhat.com)
- Restructured API documents into subdirectories to keep the api_* files from
  getting out of control (jason.dobies@redhat.com)
- Updating consumer register api to use create_weight from config and
  execute_sync_created call (skarmark@redhat.com)
- Fixing manager layer to pass property name instead of property value to
  InvalidType exception and fixing unit tests accordingly (skarmark@redhat.com)
- Removing register from v2 admin_consumer section description
  (skarmark@redhat.com)
- YumDistributor:  Fix to handle when relative_url starts or ends with "/"
  (jmatthews@redhat.com)
- Update units for GC content install. (jortel@redhat.com)
- YumDistributor: Simple support for relative_url and override of
  https_publish_dir (jmatthews@redhat.com)
- trim the drpm storage path to include only drpm file (pkilambi@redhat.com)
- seeting packages dir for drpm test (pkilambi@redhat.com)
- Changed definition to binding to describe what the definition is for
  (jason.dobies@redhat.com)
- Alphabetized the glossary (jason.dobies@redhat.com)
- OCD renaming (jason.dobies@redhat.com)
- YumImporter: consolidated test data into same location (jmatthews@redhat.com)
- metadata types dict to lookup what types to include and skip during
  createrepo (pkilambi@redhat.com)
- added postponed middleware to test stack (jconnor@redhat.com)
- changed MissingResource to accept keyword arggumets as per our sprint review
  while maintaining backward compatability with single resource_id positional
  argument (jconnor@redhat.com)
- converted scheuler add to use scheduled call request instance
  (jconnor@redhat.com)
- added scheduled call request (jconnor@redhat.com)
- simplifying group logic to its own call (pkilambi@redhat.com)
- Initial add support for GC content install in consumer controller.
  (jortel@redhat.com)
- Initial structure of the Pulp RPM user guide (jason.dobies@redhat.com)
- Add initial agent manager tests. (jortel@redhat.com)
- Return fetched object on bind create; add _href in returned bind object.
  (jortel@redhat.com)
- Added basic handling for sync v. async responses (jason.dobies@redhat.com)
- Added bindings call for update_repo_and_plugins and changed repo update to
  use it (jason.dobies@redhat.com)
-  create a pulp.yum_plugin package with common calls between importer and
  distributor (pkilambi@redhat.com)
- Updated REST API for update to use the aggregate call
  (jason.dobies@redhat.com)
- YumDistributor: initial changes to support metadata generation in the
  distributor publish (pkilambi@redhat.com)
- Added manager aggregate method for update repo and plugins
  (jason.dobies@redhat.com)
- Removing return from pulp_admin_auth extension as extension loading failure
  is fixed now (skarmark@redhat.com)
- consumer client bindings (skarmark@redhat.com)
- Minor enhancements and comments in consumer manager and webservices
  (skarmark@redhat.com)
- added comment (jconnor@redhat.com)
- moving the dispatch initialization until *after* the v2 plugins are loaded
  which might help when kicking off tasks that rely on them... duh
  (jconnor@redhat.com)
- turns out I was incrementing the running weight when I kicked off tasks, but
  never decrementing it when they completed AWESOME (jconnor@redhat.com)
- YumDistributor: rename unit test (jmatthews@redhat.com)
- YumDistributor: unit tests for basic symlink functionality
  (jmatthews@redhat.com)
- YumImporter: Remove AssociatedUnit from being stored in error report
  (jmatthews@redhat.com)
- Automatic commit of package [python-okaara] minor release [1.0.13-1].
  (jason.dobies@redhat.com)
- Fixed consumer unregister to use latest changes to agent.unregistered call
  which was causing unit tests to fail (skarmark@redhat.com)
- added pymongo 1.6 compatability (jconnor@redhat.com)
- using ObjectId for lookups in db now (jconnor@redhat.com)
- re-implemented execute and execute_sync that now return the call result if
  all goes well (jconnor@redhat.com)
- converted all postponed calls to use new OperationPostponed exception and
  postponed middleware (jconnor@redhat.com)
- added postponed operation middleware to application stack
  (jconnor@redhat.com)
- added postponed operation middleware (jconnor@redhat.com)
- added OperationPostponed exception (jconnor@redhat.com)
- removed unused middleware (jconnor@redhat.com)
- initial scheduled_call serialization (jconnor@redhat.com)
- added scheduled syncs and publishes to importer and distributor models
  (jconnor@redhat.com)
- added operational placeholders for scheduled syncs and publishes
  (jconnor@redhat.com)
- added schedule resource type (jconnor@redhat.com)
- added handling of ObjectId and basestring instances for schedule_id
  (jconnor@redhat.com)
- Syntax correction in ReST docs for bind. (jortel@redhat.com)
- Repository controller exception cleanup (jason.dobies@redhat.com)
- YumDistributor: First attempt at symlink creation and publish
  (jmatthews@redhat.com)
- YumImporter unit test data for packages under sub directories
  (jmatthews@redhat.com)
- add terms (repository, consumer & bind to sphinx glossery.
  (jortel@redhat.com)
- Refactored for proper namespacing. (jortel@redhat.com)
  (jmatthews@redhat.com)
- changed all importer/distributor operations to also be update operations on
  the repo itself for better conflict detection in the coordinator
  (jconnor@redhat.com)
- Added manager factory test (jason.dobies@redhat.com)
- Fixed for removed manager (jason.dobies@redhat.com)
- Exception cleanup after middleware introduction (jason.dobies@redhat.com)
- Removed in_progress flags for importers/distributors; the tasking subsystem
  handles that (jason.dobies@redhat.com)

* Fri Mar 30 2012 Jay Dobies <jason.dobies@redhat.com> 0.0.281-1
- Cleaned up stale exceptions left over after middleware introduction
  (jason.dobies@redhat.com)
- Fixing unit test failures - fixed test_consumer_utils to use v2 repos and
  distributors and removed irrelevant repo api tests with v2 patching changes
  (skarmark@redhat.com)
- Added admin_auth extension to build (jason.dobies@redhat.com)
- Fixed monkey patch to restore the original implementation
  (jason.dobies@redhat.com)
- Added more docs (jason.dobies@redhat.com)
- Finished porting to role based template (jason.dobies@redhat.com)
- Added build and section information (jason.dobies@redhat.com)
- Renamed so I can toss all of the docs in here (jason.dobies@redhat.com)
- Tweaks to rest-api roles. Added API template. Formatted repo APIs.
  (jason.dobies@redhat.com)
- Added type translation safety net (jason.dobies@redhat.com)
- Added rest-api extension and relevant roles (jason.dobies@redhat.com)
- consumer controller crud unit tests (skarmark@redhat.com)
- fixed string substitution (jconnor@redhat.com)
- added docstrings (jconnor@redhat.com)
- added NotImplemented pulp exception (jconnor@redhat.com)
- added consumer binding resource type (jconnor@redhat.com)
- added actual docstrings to link serialization  module (jconnor@redhat.com)
- fixed outdated docstring (jconnor@redhat.com)

* Thu Mar 29 2012 Jay Dobies <jason.dobies@redhat.com> 0.0.280-1
- Added files used in the creation of updated certs (jason.dobies@redhat.com)
- Webservices controller for consumer crud operations (skarmark@redhat.com)
- Fixing tasking unicode error in unit tests (skarmark@redhat.com)
- Fixing consumer_manager unit tests, adding get_consumer call to
  consumer_manager which raises MissingResource exception, fixing a bunch of
  docstrings (skarmark@redhat.com)
- Updated test certificates to expire in 2016 (jason.dobies@redhat.com)
- Adding missing resource exception in bind (skarmark@redhat.com)
- Generated new test certs that don't expire until 2016
  (jason.dobies@redhat.com)

* Wed Mar 28 2012 Jeff Ortel <jortel@redhat.com> 0.0.279-1
- determine the checksum type from the repodata and set on repo level
  scratchpad for distributor access. Default to sha256 if type cannot be
  determined (pkilambi@redhat.com)
- Upgraded okaara to 1.0.13 (jason.dobies@redhat.com)
- Removing repoids from consumer db model and moving update_notes to a
  different manager function (skarmark@redhat.com)
- Correct bind POST to use execute_sync_created() and return 201.
  (jortel@redhat.com)
- Fixed reST warnings coming out of sphinx (jason.dobies@redhat.com)
- Updates to rest API docs (jason.dobies@redhat.com)
- Include dereferenced distributor in bind GET result. (jortel@redhat.com)
- Initial pass at setting up sphinx for our REST APIs (mostly for backup
  purposes) (jason.dobies@redhat.com)
- add consumer query manager; apply deep dive comments to consumer
  manager/controller. (jortel@redhat.com)
- Revert "change the drpm info to return new package keys"
  (pkilambi@redhat.com)
- change the drpm info to return new package keys (pkilambi@redhat.com)
- adding delta rpm support to yum importer (pkilambi@redhat.com)
- Removing unused consumer notes manager (skarmark@redhat.com)
- Removing separate CRUD api calls for consumer notes and making it a part of
  single consumer update call (skarmark@redhat.com)
- removed resetting of _queue to None as base class clean still needs there to
  be something there (jconnor@redhat.com)
- added comment to cancel (jconnor@redhat.com)
- Added v2 client support for login/logout using the new v2 API calls.
  (jason.dobies@redhat.com)
- added dynamic permissions for tasks (jconnor@redhat.com)
- added sectional comment (jconnor@redhat.com)
- changed drop to safe remove to guarantee the queued call collection is
  cleared (jconnor@redhat.com)
- added intermediate variable for better debugging/introspection
  (jconnor@redhat.com)
- 806976 - fix overlapping references to /etc/pulp/*. (jortel@redhat.com)
- Ported user certificate generation to v2 codebase (jason.dobies@redhat.com)
- Add epydocs; notify agent on unbind. (jortel@redhat.com)
- First steps towards port of user APIs to managers (this contains certificate
  generation) (jason.dobies@redhat.com)
- Updated sync progress output to use new sync report format
  (jason.dobies@redhat.com)
- moved the clearing of task_resources from the complete life cycle transistion
  to the dequeue life cycle transition to make sure it is synchronized by the
  task_queue (jconnor@redhat.com)

* Mon Mar 26 2012 Jay Dobies <jason.dobies@redhat.com> 0.0.278-1
- removed default_weigh and replaced it with publish_weight this keeps the base
  weight of 1 unconfigurable, giving users a stable baseline with which to
  calculate configuration values for specific types of tasks
  (jconnor@redhat.com)
- YumImporter: fix for updated progress (jmatthews@redhat.com)
- added gc unbind and rest of bind related happy path unit tests.
  (jortel@redhat.com)
- fixed typo in weight for sync (jconnor@redhat.com)
- More gc consumer unit tests. (jortel@redhat.com)
- Update YumImporter test to reduce speed when bandwidth limitation is tested
  (jmatthews@redhat.com)
- Added YumImporter tests (jmatthews@redhat.com)
- Adding test dir for YumImporter tests (jmatthews@redhat.com)
- Automatic commit of package [grinder] minor release [0.0.144-1].
  (jmatthews@redhat.com)
- Bump grinder to 0.144 (jmatthews@redhat.com)
- YumImporter: unit test update to fix hard coded path (jmatthews@redhat.com)
- Initial add of consumer controller unit tests. (jortel@redhat.com)
- Initial add of gc_consumer controller; split agent actions into separate
  consumer manager. (jortel@redhat.com)
- YumImporter: Updated test for errors in sync progress (jmatthews@redhat.com)
- added tags for repo call requests (jconnor@redhat.com)
- added tags field to call report, including automatic adding of corresponding
  call requests tags (jconnor@redhat.com)
- added "tag" filter to tasks collection (jconnor@redhat.com)
- converted v2 repo rest controllers to use new configurable weights
  (jconnor@redhat.com)
- changed task_queue config section to tasks added task weights to said section
  (jconnor@redhat.com)
- bind opts need to qualify distributer by repo_id AND distributor_id.
  (jortel@redhat.com)
- Add bind clean up to consumer, repo and distributer managers and add
  associated unit tests. (jortel@redhat.com)
- Add bindcollection and placeholders for updating the agent.
  (jortel@redhat.com)
- Rename _units to: _content in agent proxy. (jortel@redhat.com)
- Update consumer bind manager unit tests. (jortel@redhat.com)
- Add unit tests for consumer bind manager. (jortel@redhat.com)
- Initial add of GC bind manager. (jortel@redhat.com)
- Changed CLI to use server-side aggregate create method
  (jason.dobies@redhat.com)
- Added create_and_configure_repo call (jason.dobies@redhat.com)
- YumImporter: Testing local_syncs & progress reporting with errors, needs some
  more work (jmatthews@redhat.com)
- YumImporter: cleanup debug print statement from progress
  (jmatthews@redhat.com)
- 805740 - generate metadata on repromotion with filters (pkilambi@redhat.com)
- 805922 - adding sync logic to look for server directory during clone/local
  syncs (pkilambi@redhat.com)
- Manager level operation for single call create/configure repo
  (jason.dobies@redhat.com)
- added return value for all async look up calls (jconnor@redhat.com)
- adding empty list return value for async._queue.find restting the queue to
  None in teardown (jconnor@redhat.com)
- Fixed unit test (jason.dobies@redhat.com)
- Added back repo ID checking in the manager (jason.dobies@redhat.com)
- Added client base test class and exception handler unit tests
  (jason.dobies@redhat.com)
- consumergroup changes for repo bind and unbind with V2 repos
  (skarmark@redhat.com)
- added OperationTimedOut to base exceptions and converted coordinater et al to
  use base exceptions instead of derived exceptions, except where they still
  made some sense (jconnor@redhat.com)

* Wed Mar 21 2012 Jeff Ortel <jortel@redhat.com> 0.0.277-1
- YumImporter: Add num_errata to progress info (jmatthews@redhat.com)
- YumImporter:  Updated sync progress status, reworked how we handle an
  exception occuring to generate a failure report (jmatthews@redhat.com)
- Added client-side exception handler to consistently format and resolve both
  server-side and client-side exceptions that can occur
  (jason.dobies@redhat.com)
- 805196 drop indexes from repo.packagegroups and repo.packagegroupcategories
  to avoid index on description field (jslagle@redhat.com)
- Automatic commit of package [grinder] minor release [0.0.142-1].
  (pkilambi@redhat.com)
- bumping grinder to 0.142; updating src (pkilambi@redhat.com)
- changed sync create calls to have weights of 0 and to not archive the calls
  (jconnor@redhat.com)
- changed create importer and distributor to sync (jconnor@redhat.com)
- Fixing CDS to check repos from 'gc_repositories' collection in pulp_database
  instead of 'repos' collection (skarmark@redhat.com)
- Fixing consumer and consumer group api tests to work with V2 repos and mocked
  distributor (skarmark@redhat.com)
- Consumer api, utils and controller changes to make v1 consumers work with v2
  repositories (skarmark@redhat.com)
- changed MissingData -> MissingValue missed in the merge (jconnor@redhat.com)
- updated repo controllers unittests (jconnor@redhat.com)
- changed pass through to converto to data exception (jconnor@redhat.com)
- changed resources dict to only include distributor_id if it is not None
  (jconnor@redhat.com)
- fixed dummy plugin classes to *not* use mock-isms (jconnor@redhat.com)
- refactored execution module to separate ok and created calls
  (jconnor@redhat.com)
- cannot json serialize timedelta (jconnor@redhat.com)
- added complete states to waiting for running state as task usually completes
  before first poll (jconnor@redhat.com)
- reverted string change (jconnor@redhat.com)
- shortened default coordinator poll interval (jconnor@redhat.com)
- little cleaner formatting of call request __str__ (jconnor@redhat.com)
- fixed typo (jconnor@redhat.com)
- missing self as first arg to super call (jconnor@redhat.com)
- added overridden _do_request to v2 webservice test class (jconnor@redhat.com)
- clean up and import organization (jconnor@redhat.com)
- pickle friendly dummy plugins (jconnor@redhat.com)
- added try/except and logging around dispatch loop (jconnor@redhat.com)
- added support for objects without __name__ attribute, thank you very much
  mock... (jconnor@redhat.com)
- moved complete life cyclce callback execution to after the task is actually
  complete (jconnor@redhat.com)
- fixed indentation (jconnor@redhat.com)
- added exception handling middleware to webservice test class
  (jconnor@redhat.com)
- changed middleware to return list of str instead of str directly to keep it
  from pissing off paste in the unittests (jconnor@redhat.com)
- added conditional loading of snapshotted fields to accomodate future change
  (jconnor@redhat.com)
- 804188 - added removal of persisted tasks as part of regular migration
  (jconnor@redhat.com)
- raise default concurrency from 4 to 9 as syncs are weighted at 2
  (jconnor@redhat.com)
- converted rest api to utilize execution via the coordinator and the new
  exception handling middleware (jconnor@redhat.com)
- Add v2 agent call back controller. (jortel@redhat.com)
- Removed extra unused data exceptions (jason.dobies@redhat.com)
- Removed InvalidType exception; just use InvalidValue instead
  (jason.dobies@redhat.com)
- Minor docs and actually deleted the OperationFailed exception
  (jason.dobies@redhat.com)
- Removed OperationFailed exception; it's redundant with PulpExecutionException
  (jason.dobies@redhat.com)
- Changed signature of ConflictingOperation exception (jason.dobies@redhat.com)
- Removed InvalidConfiguration exception (jason.dobies@redhat.com)
- Fix bug in migrations (jslagle@redhat.com)
- 805195, 805196 new migration v 41 (jslagle@redhat.com)
- Improve performance of migration 35 and add missing index
  (jslagle@redhat.com)
- Fix CDS unit tests. (jortel@redhat.com)
- Hardened the logic in case the feed URL has no relative path that we can
  extract (jason.dobies@redhat.com)
- Missed a few references to content_unit_count (jason.dobies@redhat.com)
- Fix manager to match removed Repo.content_unit_count in model object.
  (jortel@redhat.com)
- hack display_name into repo object for cds sync. (jortel@redhat.com)
- patch v1 api/cds for cds sync in v2 entironment. (jortel@redhat.com)
- hack api/cds to work in v2 world to associate repo. (jortel@redhat.com)
- Removed content_unit_count from repo model (jason.dobies@redhat.com)
- Automatic commit of package [grinder] minor release [0.0.141-1].
  (jmatthews@redhat.com)
- Added grinder 0.0.141 to rpms dir (jmatthews@redhat.com)
- Bump grinder to .141 (jmatthews@redhat.com)
- YumImporter: Updates for 'filename' and tests with local_sync
  (jmatthews@redhat.com)
- bump grinder version (pkilambi@redhat.com)
- spec file changes to include migration script and bump grinder
  (pkilambi@redhat.com)
- Merge branch 'master' of git+ssh://git.fedorahosted.org/git/pulp
  (pkilambi@redhat.com)
- 798656 - include full checksum when constructing package paths. Including
  migration script to migrate existing content (pkilambi@redhat.com)
- Added validation on selected fields for filter (jason.dobies@redhat.com)
- Added 404 support to repo unit association query (jason.dobies@redhat.com)
- Only generate the relative path if it's not specified
  (jason.dobies@redhat.com)
- Initial implementation of adding the yum distributor when creating a repo
  (jason.dobies@redhat.com)
- Added okaara as a requirement for pulp-admin (jason.dobies@redhat.com)
- "Temporarily reverting previous commit to figure out unit test failure"
  (skarmark@redhat.com)
- 802447 - encoding i18n repoid in repo file before installing on the consumer
  (skarmark@redhat.com)
- Automatic commit of package [gofer] minor release [0.67-1].
  (jortel@redhat.com)
- gofer 0.67. (jortel@redhat.com)
- fix permissions issue, remove empty dirs from migrate script
  (pkilambi@redhat.com)

* Fri Mar 16 2012 Jeff Ortel <jortel@redhat.com> 0.0.276-1
- 802447 - Fixing unicode handling bug on the client side while binding a i18n
- Docs and i18n for units search (jason.dobies@redhat.com)
- Cleanup of errata list and details handling (jason.dobies@redhat.com)
- Tweaking the title width percentage a bit (jason.dobies@redhat.com)
- Upgraded version of okaara to 1.0.12 (jason.dobies@redhat.com)
- Changed repo ID flag to --repo_id (jason.dobies@redhat.com)
- Renamed feed_url to feed as it is in v1 (jason.dobies@redhat.com)
- lowered logging level to debug (jconnor@redhat.com)
- simplified logic in execute_call accepted conditional (jconnor@redhat.com)
- changed synchronous call timeout to generate a 509 service unavailable error
  along with __str__ and data_dict implementations (jconnor@redhat.com)
- defactored? execute calls into more specific implementations to accomodte
  timeouts on sync calls (jconnor@redhat.com)
- including reboot_suggested field for errata (pkilambi@redhat.com)
- pulp.spec now copies plugins/distributors (jmatthews@redhat.com)
- forgot to commit actual distributor code on prior commits
  (jmatthews@redhat.com)
- YumDistributor introduced validate_config (jmatthews@redhat.com)
- Additions to unit search; going to refactor out errata but wanted to commit
  this first (jason.dobies@redhat.com)
- adding missing count to migrate summary (pkilambi@redhat.com)
- changed exception instances to pass (now) required constructor arguments
  (jconnor@redhat.com)
- re-implementation of __init__, __str__, and data_dict for derived exceptions
  (jconnor@redhat.com)
- removed success/failure callbacks from context (jconnor@redhat.com)
- fixed return for _execute_single (jconnor@redhat.com)
- Minor refactoring of unit search extension (jason.dobies@redhat.com)
- Added units search for rpm, srpm, drpm, errata, and all
  (jason.dobies@redhat.com)
- adding support for dryrun (pkilambi@redhat.com)
- Wired up set_progress in the conduits to the tasking subsystem
  (jason.dobies@redhat.com)
- Get taskid from dispatch context. (jortel@redhat.com)
- Initial working version of rpm units list (jason.dobies@redhat.com)
- Load the current unit count into the repo before returning
  (jason.dobies@redhat.com)
- instead of guessing using introspection, now making caller pass in the
  exepected response if all goes well (jconnor@redhat.com)
- added introspection to figure out if we need to return created or ok
  (jconnor@redhat.com)
- changed repos to use new single operation syntax (jconnor@redhat.com)
- got rid of the notion that operations is a list in resources, we only perform
  one operation on a resource at time (jconnor@redhat.com)
- added reminder comment (jconnor@redhat.com)
- abstracted out coordinator execution as its the same in almost every case
  (jconnor@redhat.com)
- simplified call rejected exception (jconnor@redhat.com)
- adding relevant serialization fields for dispatch (jconnor@redhat.com)

* Thu Mar 15 2012 Jay Dobies <jason.dobies@redhat.com> 0.0.275-1
- Added RPM extensions to the build (jason.dobies@redhat.com)
- script to migrate package content to new path format (pkilambi@redhat.com)
- Added conduit access to repo-level scratchpad (jason.dobies@redhat.com)
- Added repo-level scratchpad support (jason.dobies@redhat.com)

* Thu Mar 15 2012 Jay Dobies <jason.dobies@redhat.com> 0.0.274-1
- Initial coordinator implementation and usage
- Initial implementation of RPM extensions
* Fri Mar 09 2012 Jeff Ortel <jortel@redhat.com> 0.0.273-1
- adding srpm json to pulp-dev (pkilambi@redhat.com)
- Adding srpms to yumimporter (pkilambi@redhat.com)
- YumImporter test for remove old packages (jmatthews@redhat.com)
- Moved UnknownArgsParser to okaara, import it from there
  (jason.dobies@redhat.com)
- Added RPM units search extension (jason.dobies@redhat.com)
- Made semantics around distributor configs and updating them cleaner
  (jason.dobies@redhat.com)
- Added erratum type definition to pulp-dev (jason.dobies@redhat.com)
- Added stricter rules around importer configs and updating them
  (jason.dobies@redhat.com)
- Import Criteria so it's easier to access by plugins (jason.dobies@redhat.com)
- Changed return type on distributor's validate_config
  (jason.dobies@redhat.com)
- 801174 Fix several issues in migration. (jslagle@redhat.com)
- 801174 Preserve permissions during migration (jslagle@redhat.com)
- 801161 Add missing db migration (jslagle@redhat.com)
- Fixed names of extensions (jason.dobies@redhat.com)
- Missed some changed from pulp/client to pulp_client (jason.dobies@redhat.com)
- Changed return type for validate_config for importers
  (jason.dobies@redhat.com)
- Renamed rpm repo extension to make it a smaller set of changes from generic
  (jason.dobies@redhat.com)
- Implemented repo update (still needs server-side tweaks to work)
  (jason.dobies@redhat.com)
- Initial (working) implementation of yum repo create (jason.dobies@redhat.com)
- Fixed issue in server.py where multiple calls can't be made to a single
  connection (jason.dobies@redhat.com)
- fixed unittests for call that are now async (jconnor@redhat.com)
- added archive for delete call for testing purposes (jconnor@redhat.com)
- made all managers inherit from object (jconnor@redhat.com)
- fixed typo (jconnor@redhat.com)
- added new intermediate sub-class PulpCoordinatorTest (jconnor@redhat.com)
- added clear queued calls option to stop (jconnor@redhat.com)
- made exception handler debug flag configurable (jconnor@redhat.com)
- renamed error middleware to exception (jconnor@redhat.com)
- made dispatch parameters cofigurable (jconnor@redhat.com)
- renamed to from wait interval to poll interval (jconnor@redhat.com)
- added timestamp to queued calls so that restart can properly order call
  requests (jconnor@redhat.com)
- added start call to factory initialization (jconnor@redhat.com)
- added interrupted task restart and conflict metadata clearing on startup
  (jconnor@redhat.com)
- added more comments to run task (jconnor@redhat.com)
- removed misplaced comment (jconnor@redhat.com)
- comment on external locking of task queue (jconnor@redhat.com)
- /var/lib/pulp/client -> /var/lib/pulp_client (jconnor@redhat.com)
- moved plugins to plugins/ in script (jconnor@redhat.com)
- added start calls for both the task queue and the scheduler
  (jconnor@redhat.com)
- added call rejected exception (jconnor@redhat.com)
- added importer and distributor types (jconnor@redhat.com)
- made publish async (jconnor@redhat.com)
- fixed location of v2 plugins (jconnor@redhat.com)
- removed get_ prefix from dispatch factory functions (jconnor@redhat.com)
- added v2 admin to installation (jconnor@redhat.com)
- remove superfluous )( (jconnor@redhat.com)
- needed parent dirs (jconnor@redhat.com)
- changes to pulp-dev for installing what is need for v2 development
  (jconnor@redhat.com)
- tied repo delete in to coordinator (jconnor@redhat.com)
- converted repo sync into async :) (jconnor@redhat.com)
- Adding unit tests for errata support (pkilambi@redhat.com)
- Work towards the yum support extension (jason.dobies@redhat.com)
- 799120 - Added package filtering at package import stage as well as it is
  processing packages from source dir and not destination dir
  (skarmark@redhat.com)
- Update YumImporter config values and provide descriptions
  (jmatthews@redhat.com)
- Adding some util methods for yum importer (pkilambi@redhat.com)
- Comment out errata logging so we can run unit tests as non-root
  (jmatthews@redhat.com)
- Initial work towards the yum extensions (jason.dobies@redhat.com)

* Thu Mar 08 2012 Jeff Ortel <jortel@redhat.com> 0.0.272-1
- Adding errata detail info (pkilambi@redhat.com)
- Added v2 client/extensions and plugins to RPM build (jason.dobies@redhat.com)
- Renamed extensions to differentiate from RPM client extensions
  (jason.dobies@redhat.com)
- SELinux update for developer setup of GC plugins (jmatthews@redhat.com)
- renaming the sync call (pkilambi@redhat.com)
- Errata sync support for Yum importer plugin * Erratum type definition * type
  module to sync errata * refactor importer.py and move rpm specific logic to
  rpm.py (pkilambi@redhat.com)
- Disabled the ping command until it works (jason.dobies@redhat.com)
- Upgraded version of okaara (jason.dobies@redhat.com)
- Moved RPM plugins out of playpen into production location
  (jason.dobies@redhat.com)
- 800468 Use collection.update instead of collection.save to avoid race
  condition (jslagle@redhat.com)
- Added safeties for first-run missing files/dirs. (jason.dobies@redhat.com)
- pulp migrate to add task weight to snapshots (jconnor@redhat.com)
- Fixed indentation calculation (jason.dobies@redhat.com)
- 790806 - Added utf-8 encoding of distribution file path when path contains
  non-ascii characters (skarmark@redhat.com)
- More tests for rpm importer (jmatthews@redhat.com)
- 796854 - Removing encode_unicode from task list as changes to tasking now
  converts all task information in unicode format (skarmark@redhat.com)

* Fri Mar 02 2012 Jeff Ortel <jortel@redhat.com> 0.0.271-1
- Fixed reST formatting in docs (jason.dobies@redhat.com)
- Apply some basic filters/ordering to unit list (jason.dobies@redhat.com)
- Made render_document_list a bit more robust (jason.dobies@redhat.com)
- Playing with color in cli map output to make it more readable
  (jason.dobies@redhat.com)
- Refactored so all logging configuration is done in the launcher. Removed
  hardcoded logging filename client.log. (jason.dobies@redhat.com)
- Tweaks and additions to render_document_list. (jason.dobies@redhat.com)
- Added getResponseLogger to gc_client to remove it's dependecy on v1 client
  and moved exceptions into seperate file (skarmark@redhat.com)
- Update search indexes for rpm type (jmatthews@redhat.com)
- Added support for logging HTTP calls in the admin config
  (jason.dobies@redhat.com)
- Raised priority for built in extensions (should probably be a constant
  somewhere, I'm just not sure where). (jason.dobies@redhat.com)
- tied new dispatch collections into webservices (jconnor@redhat.com)
- finished first pass implementation of new dispatch controllers
  (jconnor@redhat.com)
- add _ in front of href fields as per specification (jconnor@redhat.com)
- refactored find to allow methods for tasks and call_reports
  (jconnor@redhat.com)
- changes to content and unit association managers and controllers to use new
  exception middleware (skarmark@redhat.com)
- Refactored unknown args parsing to fit better into the CLI framework and
  added probably the coolest testing fixture I've ever set up to test it.
  (jason.dobies@redhat.com)
- Updating manager unit tests for updated exceptions (skarmark@redhat.com)
- Initial implementation of the list units command (jason.dobies@redhat.com)
- Initial implementation of repo sync (jason.dobies@redhat.com)
- Added wrapper for creating a threaded spinner (jason.dobies@redhat.com)
- Manager layer and controller changes for repo sync and publish functionality
  to use newly added exception middleware (skarmark@redhat.com)
- Manager layer and controller changes to use newly added exception middleware
  (skarmark@redhat.com)
- Update to sync pulp_unittest repo for harness testing of rpm importer
  (jmatthews@redhat.com)
- RPM Importer updates to begin unit tests (jmatthews@redhat.com)
- Initial implementation of add importer (jason.dobies@redhat.com)
- Implemented unknown argument parser (jason.dobies@redhat.com)

* Wed Feb 29 2012 Jeff Ortel <jortel@redhat.com> 0.0.270-1
- Exclude pulp-v2-admin from setup.py until it can be packaged.
  (jortel@redhat.com)
- Exclude pulp.gc_client.* from packages in setup.py (jortel@redhat.com)
- Fixed 2.4 incompatibility (jason.dobies@redhat.com)

* Wed Feb 29 2012 Jeff Ortel <jortel@redhat.com> 0.0.269-1
- Initial implementation of the repo extension (jason.dobies@redhat.com)
- Tweaks to render_document_list and support for recursively displaying lists
  of dicts (jason.dobies@redhat.com)
- Added hook to call CLI map (jason.dobies@redhat.com)

* Wed Feb 29 2012 Jeff Ortel <jortel@redhat.com> 0.0.268-1
- Renamed okaara RPM (jason.dobies@redhat.com)
- 797929 add requirement on semanage command (jslagle@redhat.com)
- Require grinder 0.139 (jmatthews@redhat.com)
- Initial implementation of server info extension (jason.dobies@redhat.com)
- added queued call controllers and application (jconnor@redhat.com)
- changed history to be a sub-collection still need to fix publish history to
  filter by distributor instead of having extraneous distributor id in the uri
  path (jconnor@redhat.com)
- Using _href instead of href and updating __str__ to return a better error
  message now that we have http_request_method in the exception object
  (skarmark@redhat.com)
- Updating repo history client api to update path according to changes in
  server api (skarmark@redhat.com)
- Adding support for removing metadata, updating index and finalizing sqlite
  files (pkilambi@redhat.com)
- Added server plugin bindings (jason.dobies@redhat.com)
- Added bindings creation to client launcher (jason.dobies@redhat.com)
- For now use the same user cert location as the v1 client until we add in auth
  to the v2 client (jason.dobies@redhat.com)
- Refactored extensions loading to use a priority concept
  (jason.dobies@redhat.com)
- enhancing gc cli server.py to add request exceptions, response objects for
  successful response, removing http connection and ability to connect without
  credentials (skarmark@redhat.com)
- re-based dispatch models off of new base (jconnor@redhat.com)
- added work-around for _id=id upsert (jconnor@redhat.com)
- gzip the updated xmls and get checksums (pkilambi@redhat.com)
- adding .id = ._id hack (jconnor@redhat.com)
- Updates to RPM Importer plugin, basic rpm import functionality working, needs
  more work on verifying list of contents from WS (jmatthews@redhat.com)
- 796934 - Do not apply repo unassociations to the whole CDS cluster during CDS
  removal (jslagle@redhat.com)
- first real pass at trying to make _id an ObjectId (jconnor@redhat.com)
- new gc base model class that does not override _id generation
  (jconnor@redhat.com)
- 790806 - encoding repo cert filenames before trying to access them
  (skarmark@redhat.com)
- 795819 - account for the relativepath from the metadata location field
  (pkilambi@redhat.com)
- fixed named tuple utilization for inspect module returns (2.4 compatability)
  (jconnor@redhat.com)
- changed interval_in_seconds computation to be 2.4 compatible
  (jconnor@redhat.com)
- First cut at a rpm importer plugin, needs more testing (jmatthews@redhat.com)
- Rquires for grinder to 0.138 (jmatthews@redhat.com)
- 790806 - Fixed encoding error thrown when repo cloning with unicode id,
  filters and relativepath (skarmark@redhat.com)
- 790806 - fixed client task list to not convert task args to str instead
  encode them with 'utf-8' (skarmark@redhat.com)
- 790806 - fixes to cancel_sync which was resulting in sync not found due to
  improper encoding of unicode ids (skarmark@redhat.com)
- skip add if pkg already exists (pkilambi@redhat.com)
- update scripts to add package to existing metadata (pkilambi@redhat.com)
- 790806 - urlparse is not handling unicode urls correctly, so encoding them
  with utf-8 before parsing (skarmark@redhat.com)
- 790005 Require exact matching version and release of pulp-selinux-server for
  pulp (jslagle@redhat.com)
- Added optional .conf file loading for extensions (jason.dobies@redhat.com)
- added stricter check for kwarg match between task and search criteria
  (jconnor@redhat.com)
- implemented cancellation for tasks and jobs (jconnor@redhat.com)
- removing callable_name from constructor arguments (jconnor@redhat.com)
- removed archive from task and utilized task history module for archival
  (jconnor@redhat.com)
- Add requires for updated m2crypto (jmatthews@redhat.com)
- Small change to allow harness to be reused by other gc plugins
  (jmatthews@redhat.com)
- SELinux dev setup for gc plugins (jmatthews@redhat.com)
- Adding repo bindings functionality tests, Storing data coming from server
  exceptions to binding exceptions according to response codes
  (skarmark@redhat.com)
- converted scheduler to be coordinator execturion only (jconnor@redhat.com)
- Exception catching at the root of CLI execution (jason.dobies@redhat.com)
- Moved ClientContext out to core (jason.dobies@redhat.com)
- Made max_width command 2.4 compatible (jason.dobies@redhat.com)
- Shadow abort to decouple extensions from okaara directly
  (jason.dobies@redhat.com)
- 795570 Fix repo auth oid substitution when the oid ends with a yum variable
  (jslagle@redhat.com)
- User-friendly message when one or more packs fails to load
  (jason.dobies@redhat.com)
- Extension loading will now fail on any extension failure
  (jason.dobies@redhat.com)
- Made repo an attribute instead of a method; just feels better
  (jason.dobies@redhat.com)
- 790285 - fix the error message to be similar for both file and package
  deletes (pkilambi@redhat.com)
- Import clean up (jason.dobies@redhat.com)
- Cleaning up server.py and adding ServerWrapper class that can mock http
  connection api (skarmark@redhat.com)
- changing base class pulp exceptions and added some intermediate classes as
  well as automatic handling by error middleware to map said exceptions to http
  errors (jconnor@redhat.com)
- 790806 - Changes to encode task args and kwargs to unicode before
  snapshotting (skarmark@redhat.com)
- Added tag support for progress bar and spinner; unit test for both
  (jason.dobies@redhat.com)
- Added single document rendering and fixed issue in render doc list
  (jason.dobies@redhat.com)
- Quite a bit of work on the core rendering methods (jason.dobies@redhat.com)
- Added pulp subclasses for options and flags (jason.dobies@redhat.com)
- Can't deepcopy the config (jason.dobies@redhat.com)
- Adding repo history, actions and search related REST bindings
  (skarmark@redhat.com)
- initial dispatch entity factory (jconnor@redhat.com)
- greatly simplified coordinator api by moving callback indicators into
  CallRequest objects, where they belong (jconnor@redhat.com)
- added progress, success, and failure callback keyword argument names
  (jconnor@redhat.com)
- correcting year in the CR information (skarmark@redhat.com)
- V2 api rest bindings for respository, importers and distributors
  (skarmark@redhat.com)
- refactored execute api to be more readible added docstrings
  (jconnor@redhat.com)
- simplified progress callbacks to make folks do their processing
  (jconnor@redhat.com)
- refactored execution methods to allow callback assignment
  (jconnor@redhat.com)
- realized my get postponing/rejecting operations logic was inverted
  (jconnor@redhat.com)
- first pass at a sane find conflicts algorithm (jconnor@redhat.com)
- added more sane task resource model to allow more efficient queries by the
  coordinator (jconnor@redhat.com)
- added existentially lock and unlock methods (jconnor@redhat.com)
- added resource operations matrix (jconnor@redhat.com)
- added coordinator task model (jconnor@redhat.com)
- added resouce types and operations (jconnor@redhat.com)
- added to_string functions for execution and control hook numbers
  (jconnor@redhat.com)
- moved dequeue execution callback addition to run instead of add so that the
  callback does not get pickled (jconnor@redhat.com)
- added ascii encoding for pickling to account for unicode coming out of the
  database added desialization of None to return None (jconnor@redhat.com)
- consolidated all custom pickling functions (jconnor@redhat.com)
- deterministic scheduler unit tests (jconnor@redhat.com)
- added collection drop to teardown (jconnor@redhat.com)
- removed singleton (jconnor@redhat.com)
- un-protected call_execution_hooks as it is used by the task queue
  (jconnor@redhat.com)
- made call archival optional (jconnor@redhat.com)
- removed superfluous , when missing args or kwargs (jconnor@redhat.com)
- added custom exceptions for missing control hooks (jconnor@redhat.com)
- added custom exceptions for missing kwargs (jconnor@redhat.com)
- removed progess control hook (jconnor@redhat.com)
- removed progress callback from constructor (jconnor@redhat.com)
- removed confusing asynchronous flag (jconnor@redhat.com)
- added async call validation to AsyncTask constructor (jconnor@redhat.com)
- moved call archival to task._complete moved complete callback reset to
  taskqueue.deque (jconnor@redhat.com)
- made progress callback kwargs name a argument to the constuctor
  (jconnor@redhat.com)
- re-factored out asynchronous support into derived class changed setting of
  complete state until task is actually complete made non-public methods
  protected (jconnor@redhat.com)
- added state assertions for succeeded and failed (jconnor@redhat.com)
- simplified consecutive failur math (jconnor@redhat.com)
- added loging of scheduled task disable clearing consecutive failures on
  success (jconnor@redhat.com)
- added direct task queue dispatch (jconnor@redhat.com)
- added failure threshold tracking to the scheduler (jconnor@redhat.com)
- adding failure threshold and consecutive failures fields to scheduled calls
  (jconnor@redhat.com)
- converted task queue to handle blocking tasks implemented query methods
  (jconnor@redhat.com)
- added blocking tasks set (jconnor@redhat.com)
- purely fifo implementation of new task queue (jconnor@redhat.com)
- cleanup in light of new tasking (jconnor@redhat.com)
- added call complete execution hook (jconnor@redhat.com)
- added constructor for queued call and added archived call class
  (jconnor@redhat.com)
- added calls to execution hooks for finished, error, and complete
  (jconnor@redhat.com)
- changed im_class logic to make pycharm happy (jconnor@redhat.com)
- setting progress callback with defualt key word of: progress_callback
  (jconnor@redhat.com)
- changed task to be a call request and report aggregate type added
  asynchronous behavior (jconnor@redhat.com)
- added start and finish times to call report (jconnor@redhat.com)
- had presentation twice instead of progress (jconnor@redhat.com)
- added execution and control hook constants changed call request to use new
  constants (jconnor@redhat.com)
- changed finished call update to utilize call dequeue hook execution
  (jconnor@redhat.com)
- changed so that even disabled calls are still re-scheduled
  (jconnor@redhat.com)
- query api for scheduler (jconnor@redhat.com)
- added docstrings (jconnor@redhat.com)
- removed history in leiu of history module (jconnor@redhat.com)
- added enable/disable scheduled call api (jconnor@redhat.com)
- updates to dispatch (jconnor@redhat.com)
- added recording of raw schedule and list_run as well as start_date using new
  dateutils naive utc cast (jconnor@redhat.com)
- added history module (jconnor@redhat.com)
- added super constructor call and put tzinfo manipulation into conditional,
  assumes utc tz if absent (jconnor@redhat.com)
- initial scheduling algorithm (jconnor@redhat.com)
- added unique indices and and fixed indicies spelling (jconnor@redhat.com)
- removed task call report factory (jconnor@redhat.com)
- removed last references to now unsupported timeout (jconnor@redhat.com)
- renamed to: taskqueue (jconnor@redhat.com)
- renamed module to: dispatch (jconnor@redhat.com)
- skeleton scheduler (jconnor@redhat.com)
- place holder for async specific errors (jconnor@redhat.com)
- initial implementation of task wrappers for call requests
  (jconnor@redhat.com)
- initial call request and report implementations (jconnor@redhat.com)
- initial async_ module layout (jconnor@redhat.com)
- removed scheduling module (jconnor@redhat.com)
* Fri Feb 17 2012 Jeff Ortel <jortel@redhat.com> 0.0.267-1
- 733312 - Make sure sync does not remove already existing packages from a repo
  during filter operation (skarmark@redhat.com)
- 790157 override ssl_ca_cert config in unit test (jslagle@redhat.com)
- 790157 Fix variable reference (jslagle@redhat.com)
- 790157 Fix variable reference (jslagle@redhat.com)
- 790157 Only set cacert if the repo is protected (jslagle@redhat.com)
- 790005 SELinux fix for qpidd https (jslagle@redhat.com)
- 790157 Use ssl_ca_certificate config to send down for cacert to consumer
  during repo bind operation (jslagle@redhat.com)
- 790806 - Added handling for proper encoding of i18n relativepath with utf-8
  encoding (skarmark@redhat.com)
- 790198 - write the updated comps information to the repo
  (pkilambi@redhat.com)
- Update URLs in functional tests to use v1 testing (jmatthews@redhat.com)
- 790069 - pulp repo sync from mounted ISO - Permission denied:
  repodata.old/repomd.xml (jmatthews@redhat.com)
- 789083, 790838, 790791 - Added regex checking and validation error when repo
  id or relative path contains whitespace characters (skarmark@redhat.com)
- Adding a dependency on mkiosfs/genisoimage to pulp for iso generation on
  exports (pkilambi@redhat.com)
- 790602 assuring that if None is passed up from the client, we are not using
  it as the sync_options (jconnor@redhat.com)
- 790285 - adding a reference check to file with repo associate on delete
  (pkilambi@redhat.com)
- Moved pic under pulp.common (jason.dobies@redhat.com)
- 790140 added same check in grant for asserting that a user or a role is
  passed in (jconnor@redhat.com)
- 790141 added automatic permissions for newly created user that gives them the
  ability to read and update their own information as well as fetch their admin
  certificate so they can log in (jconnor@redhat.com)
- 790218 - adding fix to ensure urls with missing slash are discovered
  (pkilambi@redhat.com)
- 790015 - adding support for ppc arch on repos (pkilambi@redhat.com)
- Adding errata update support to cli and web services (pkilambi@redhat.com)
- 788565 - fix selinux relabel of files from CDS rpm install
  (jmatthews@redhat.com)
* Mon Feb 13 2012 Jay Dobies <jason.dobies@redhat.com> 0.0.266-1
- 789505 - move encode_unicode() and decode_unicode() to common/utils.py
  functions referenced in repo_cert_utils.py which is used by the CDS.
  (jortel@redhat.com)
- Fixing conversion of task args and kwargs so as to handle unicode as well as
  other exception correctly (skarmark@redhat.com)
- Reduce concurrent sync tasks and number of threads (jmatthews@redhat.com)
- Added unit test runner script from RHEL test debugging
  (jason.dobies@redhat.com)
- 712065 - limit the logging when we upload/associate packages
  (pkilambi@redhat.com)

* Mon Feb 06 2012 Jeff Ortel <jortel@redhat.com> 0.0.265-1
- 787310 - fixing error during repo sync when trying to access a variable
  before assignment when failed to load repo-md data (skarmark@redhat.com)
- Not sure what changed, but unique is no longer in the returned data
  (jason.dobies@redhat.com)
- 761039 - fixed in gofer 0.65; python 2.4 compat. (jortel@redhat.com)
- 784876 - added handling for multiple checksums for same nvrea during 'content
  list' (skarmark@redhat.com)
- 784638 Bump required version of mod_wsgi to 3.3-3.pulp (jslagle@redhat.com)
- The inclusion of CDS instances into the URI creation is crippling for
  performance and I suspect incorrect in the first place. Commented it out and
  we can discuss again in the future. (jason.dobies@redhat.com)
- 787003 - silencing the test (jconnor@redhat.com)
- Refactored capabilities; improved consumer info|list CLI output.
  (jortel@redhat.com)
- Allow qpidd_t context to open files with the cert_t context
  (jslagle@redhat.com)
- Update qpidd_t debugging (jmatthews@redhat.com)
- Update example selinux rules, for qpid debugging (jmatthews@redhat.com)
- Playpen SELinux module to help debug SELinux problems (jmatthews@redhat.com)
- updating api doc strings (pkilambi@redhat.com)
- 785922 - lookup the checksum type of a feed repo from its metadata instead of
  defaulting to sha256; this should keep the metadata in sync with filesystem
  and db (pkilambi@redhat.com)

* Wed Feb 01 2012 Jeff Ortel <jortel@redhat.com> 0.0.264-1
- 784638 Update pulp apache config and repo auth to use WSGIAccessScript
  (jslagle@redhat.com)
- 784638 Add patch to mod_wsgi so that mod_ssl hook runs before
  WSGIAccessScript (jslagle@redhat.com)
- 784876 - fixing wrong checksum key in content list cli (skarmark@redhat.com)
- 772350 - had to write new plumping to actually remove completed tasks from
  the task queue (jconnor@redhat.com)
- 772350 - hopefully last fix pertaining to this bug added task and task
  history removal for tasks related to the repo being deleted god help us all
  (jconnor@redhat.com)
- Encapsulate agent capabilities in a common class and refit client/server.
  (jortel@redhat.com)
- Made max num of certs supported in a chain a config option
  (jmatthews@redhat.com)
- Changed logic in repo_cert_utils to avoid potential for inifite loop and
  support a max num of certs in a chain (jmatthews@redhat.com)
- repo_cert_utils if our patch is missing limit the tests we will run
  (jmatthews@redhat.com)
- 784280 - SELinux denials during system cli test (jmatthews@redhat.com)
- Add capabilities to agent status; leverage in CLI. (jortel@redhat.com)
- fix to improve dep solver performance (pkilambi@redhat.com)
- 784346 - fixing unpublish logic to remove empty directories after a repo is
  unlinked from published dir (pkilambi@redhat.com)

* Fri Jan 27 2012 Jeff Ortel <jortel@redhat.com> 0.0.263-1
- fix depsolver to include file based deps (pkilambi@redhat.com)
- 783251 - Implements support for i18n ids for entities like repo, user,
  filter, consumer group etc. Also includes unit tests to avoid regressions
  related to unicode handling. (skarmark@redhat.com)
- Revert "783251 - reverting previous fix to add a more effficient fix with
  less code" (skarmark@redhat.com)
- "783251 - reverting part of the fix for i18n ids" (skarmark@redhat.com)
- 784724 - fix add package to use the correct package object when setting the
  repo id  value (pkilambi@redhat.com)
- 773752 - pulp-admin packagegroup add_package does not add pkg to repo
  (jmatthews@redhat.com)

* Thu Jan 26 2012 Jeff Ortel <jortel@redhat.com> 0.0.262-1
- dep solver on el5 picks up some false positives as search provides in yum
  only uses name. Adding a CheckProc to verify if the po is indeed providing
  the dep (pkilambi@redhat.com)
- Fix to skip metadata update on re-promotions if the repo has a parent
  associated (pkilambi@redhat.com)
- Add importer/distributor information to retrieve repo calls
  (jason.dobies@redhat.com)
- 782128 - Add support to repo auth code to verify requests against a CA chain
  file (jmatthews@redhat.com)
- 783251 - added support to be able to create pulp entities(except consumers)
  with i18n id (skarmark@redhat.com)
- 783251 - added support to be able to create pulp entities(except consumers)
  with i18n id (skarmark@redhat.com)
- Added ability to update notes in repo update (jason.dobies@redhat.com)
- added docstring (jconnor@redhat.com)
- fixed bug in bug fix that would erroniously compare None and datetime
  instances (jconnor@redhat.com)
- changing reliance on ordering of sync tasks from server to actually find the
  latest task (jconnor@redhat.com)
- 782128 - Add support to repo auth code to verify requests against a CA chain
  file (jmatthews@redhat.com)
* Mon Jan 23 2012 Jeff Ortel <jortel@redhat.com> 0.0.261-1
- 784098 - make 'capabilities' optional in consumer registration as intended.
  (jortel@redhat.com)
- trigger metadata update if a filter alters the repo state during clone
  (pkilambi@redhat.com)
- 783499 - fixing key error when selective syncing (pkilambi@redhat.com)
- Examples of CA Certificate Chain verification (jmatthews@redhat.com)

* Mon Jan 23 2012 James Slagle <jslagle@redhat.com> 0.0.260-1
- Automatic commit of package [mod_wsgi] minor release [3.3-2.pulp].
  (jslagle@redhat.com)

* Fri Jan 20 2012 Jeff Ortel <jortel@redhat.com> 0.0.259-1
- 760601 - Added missing CancelException during removal of packages and errata
  that no longer exist in the sync task (skarmark@redhat.com)
- 782109 added better error handling for UnscheduledTaskException in
  async.enqueue (jconnor@redhat.com)
- 781559 changed from using kwargs to args to that the uniqueness detection in
  the tasking subsystem will recognize different repo deletes as unique
  (jconnor@redhat.com)
- 782844 - fix the or query to check if the query is empty before woring on or
  query; also fix the cli to not make an api call to lookup deps if deps are
  empty (pkilambi@redhat.com)
- Automatic commit of package [m2crypto] minor release [0.21.1.pulp-7].
  (jmatthews@redhat.com)
- Bumping M2Crypto.spec to include getLastUpdate/getNextUpdate CRL support as
  well as M2Crypto unit tests (jmatthews@redhat.com)
- Added getLastUpdate, getNextUpdate to M2Crypto CRL wrapper plus M2Crypto
  tests (jmatthews@redhat.com)
- 782877 - fix the file syncs to use the default checksum; also fixed empty
  files default to null in mongo causing metadata parse errors
  (pkilambi@redhat.com)
- Fix unit tests. (jortel@redhat.com)
- 782480 - private key no longer stored; shared secret updated; consumer
  capabilities added; database version 36 (jortel@redhat.com)
- Update for location of temp CA&CRL combination (jmatthews@redhat.com)
- 782841 - fixing the package upload with no repoids (pkilambi@redhat.com)
- Updated generation of CRL/CA/Cert data for m2crypto unit tests
  (jmatthews@redhat.com)
- 773439 - enhanced GET /consumers/applicable_errata_in_repos/ api to accept
  send_only_applicable_errata flag and return more information about errata
  (skarmark@redhat.com)
- 757825 assure the kwargs is a dict (jconnor@redhat.com)
- 757825 add only copies of the task to the history so that editing them does
  not edit the task (jconnor@redhat.com)
- 772660 Update requires on mod_wsgi in pulp.spec (jslagle@redhat.com)
- 772660 Remove KeyError patch from mod_wsgi build, it is already included in
  version 3.3 (jslagle@redhat.com)
- 772660 Bump mod_wsgi version to 3.3 (jslagle@redhat.com)
* Mon Jan 16 2012 Jeff Ortel <jortel@redhat.com> 0.0.258-1
- Add support for enabled repository reporting; add support for soft bind.
  (jortel@redhat.com)
- updating publish help and adding response examples to distro api
  (pkilambi@redhat.com)
- 760601 - updated code for adding distribution and files to catch
  CancelException in case of cancel_clone or cancel_sync (skarmark@redhat.com)
- 773344 - fixed repo delete failure for non existing clone ids by adding
  exception handling (skarmark@redhat.com)
- Adding publish option to repo create and clone api calls
  (pkilambi@redhat.com)
- file objects dont currently have repoids (pkilambi@redhat.com)
- changed auditing interval to use local timezone (jconnor@redhat.com)
- 707884 fixed both comsumer history and auditing initialization to start in
  the future (jconnor@redhat.com)
- 773375 - fix for syncs to set the repoids directly instead of post pkg object
  creation (pkilambi@redhat.com)
- 772282 removed schedule update options from repogroup update
  (jconnor@redhat.com)
- 767763 changed util to until... (jconnor@redhat.com)
- 772072 - must use _usr/lib/ instead of _libdir macro for yum plugins.
  (jortel@redhat.com)
- Removed about half a year's changelog entries; it needed some pruning.
  (jason.dobies@redhat.com)

* Mon Jan 09 2012 Jeff Ortel <jortel@redhat.com> 0.0.257-1
- Refit for upstream agent API changes; requires gofer 0.64.
  (jortel@redhat.com)
- 772707 - fix to handle checksum mismatch when a sync uses sha va sha256
  (pkilambi@redhat.com)
- Update example responses for package group/categories (jmatthews@redhat.com)
- 772711 - fixing the repoids field in package objects (pkilambi@redhat.com)
- removing superfluous error: prefixes (jconnor@redhat.com)
- 767763 removing superfluous and weird client-side check for running sync
  (jconnor@redhat.com)
- 767763 - changed the clone action to return a conflict if the parent repo is
  syncing (jconnor@redhat.com)
- 772350 - fixed improper handling of None progress (jconnor@redhat.com)
- expose repoids when quering repo errata (pkilambi@redhat.com)
- 772348 - added missing command at the end of valid_filters to get a list
  instead of string of repoids as input to the api (skarmark@redhat.com)
- 761653 - adding package groups to repo broken (jmatthews@redhat.com)
- Change to logging for unittest code, logs in unittest drivers will
  additionally log to their own file, /tmp/pulp_unittests_only.log
  (jmatthews@redhat.com)
- Refactored out a base distributor conduit (jason.dobies@redhat.com)
- Refactored out some base functionality for importer conduits
  (jason.dobies@redhat.com)
- Added support for unit association to test harness (jason.dobies@redhat.com)
- Fixed call into conduit to use the repo transfer object
  (jason.dobies@redhat.com)
- Added associate_from_repo REST call and unit tests (jason.dobies@redhat.com)
- These are not expected to be strings but rather serialized exceptions. The
  methods themselves need to be cleaned up, but for now removing the type
  indicator from the docstring so it's not flagged as a warning when passing in
  a serialized error dict. (jason.dobies@redhat.com)
- Minor changes to consumer webservices to fix return codes
  (skarmark@redhat.com)
- Minor consumer api fixes correcting return codes (skarmark@redhat.com)
* Wed Jan 04 2012 Jeff Ortel <jortel@redhat.com> 0.0.256-1
- Fix job list. (jortel@redhat.com)
- Move consumer cert to: /etc/pki/pulp/consumer/ (jortel@redhat.com)
- fixed bug the wrongfully required user on permission grant
  (jconnor@redhat.com)
- added do not edit header to genereated wiki pages (jconnor@redhat.com)
- Refactored out the unit association query stuff into its own manager, it was
  getting way too big. (jason.dobies@redhat.com)
- changed resource description to be less confusing (jconnor@redhat.com)
- added correct failure reponse to show permissions (jconnor@redhat.com)
- Untested implementation of association from repo. Need to refactor out query
  stuff from that manager to reduce the noise before I write the tests.
  (jason.dobies@redhat.com)
- Removed unused import (jason.dobies@redhat.com)
- re-ran restapi.py (jconnor@redhat.com)
- added example key, preformatted formatted :), and required list entries
  (jconnor@redhat.com)
- Moved logic for differentiating between get_units_* calls into the manager
  (jason.dobies@redhat.com)
- Changed reporting output in the test harness (jason.dobies@redhat.com)
- Renamed get_units to get_units_across_types to make room for a syntactic
  sugar get_units method that makes the appropriate differentiation
  (jason.dobies@redhat.com)
- Bump grinder to 0.136 (jmatthews@redhat.com)
- 710153 - Fixed incorrect parsing of intervals in sync schedules. Added
  iso8601 format examples to --help. (jason.dobies@redhat.com)
- Changing return codes for some of the consumer group apis for more restful
  approach (skarmark@redhat.com)
- fix migrate script to use right collection (pkilambi@redhat.com)
- add cloned repoid to packages during the clone process (pkilambi@redhat.com)
- 765849 - RFE: include repoids reference in packages and errata * db change to
  include repoid for packages and errata * migration script * manager layer
  changes * client updates * unit test updates (pkilambi@redhat.com)
- Added association query support to the v2 harness (jason.dobies@redhat.com)
- 750847 Expose next sync time on repo schedule and sync status
  (jslagle@redhat.com)
- 760172 Change consumer history logging from consumer created/deleted to
  registered/unregistered (jslagle@redhat.com)
- Add RHEL-6-SE to list of commented out brew tags that are used
  (jslagle@redhat.com)
- 713576 Check for write permission to correct paths before attempting consumer
  register, unregister, bind, or unbind. (jslagle@redhat.com)
- 760717 Add info subcommand to pulp-admin repo command. (jslagle@redhat.com)
- Brought the conduits in line with new unit association query functionality
  (jason.dobies@redhat.com)
- improving the package import step during clone (pkilambi@redhat.com)
- Implemented unit association advanced query (jason.dobies@redhat.com)
- Made it easier to use mock objects in the manager factory
  (jason.dobies@redhat.com)
- Added validation and integrity logic to Criteria (jason.dobies@redhat.com)
- Adding some performance enhancements to cloning rpms step
  (pkilambi@redhat.com)
- Added regex example for filter value (jason.dobies@redhat.com)
- Working around for unittests since rhel5 has a problem syncing our f16 repos
  (jmatthews@redhat.com)
- Added ability to control the returned fields (jason.dobies@redhat.com)
- Greatly cleaned up criteria objects (jason.dobies@redhat.com)
- Fixed unfinished refactoring; offset doesn't have to be a parameter
  (jason.dobies@redhat.com)
- Having been the dev to come up with the name "content unit", you'd think I
  wouldn't accidentally call it "user" half the time. (jason.dobies@redhat.com)
- rpmlint fix for anything under /etc being marked as config
  (jmatthews@redhat.com)
- SELinux fix for cds httpd mod_wsgi configuration (jmatthews@redhat.com)
- rpmlint: removing zero-length file (jmatthews@redhat.com)
- rpmlint adjustments for permissions (jmatthews@redhat.com)
- rpmlint fixes to get ready for Fedora submission (jmatthews@redhat.com)
-  747661 - more pulp.spec changes (jmatthews@redhat.com)
- 747661 - Content Certificate permission errors in an AWS guest
  (jmatthews@redhat.com)
- 760683 - Move location of certs away from /etc/pki/content to a Pulp specific
  directory (jmatthews@redhat.com)
- 768126 - fix typo in pulp-admin errata install. (jortel@redhat.com)
- Flushed out get_units_by_type tests and starting on stress tests.
  (jason.dobies@redhat.com)
- 761173 - SELinux related: Move grinder usage of /tmp/grinder to
  /var/run/grinder (jmatthews@redhat.com)
- Massive work towards unit association queries. Still need some cleaning up
  and to write the tests for get_units_by_type, but this is enough work that I
  really wanted it backed up. (jason.dobies@redhat.com)
- Added webservice controllers to v2 test script (jason.dobies@redhat.com)
- Added script to run tests and coverage numbers for v2 code
  (jason.dobies@redhat.com)
- Propagated owner API changes to the sync conduit (jason.dobies@redhat.com)
- Association manager changes to accomodate association owner
  (jason.dobies@redhat.com)
- Added owner and timestamp information to unit association
  (jason.dobies@redhat.com)

* Thu Dec 15 2011 Jeff Ortel <jortel@redhat.com> 0.0.255-1
- Bump grinder to 0.133 (jmatthews@redhat.com)
- 766944 - exposing all fields when querying consumer errata
  (pkilambi@redhat.com)
- 745142 - changing delete filter api to more restful DELETE on
  /filters/filter_id and removing 'force' delete option (skarmark@redhat.com)
- 767618 - Fixed error when uploading content to a repo with filter
  (skarmark@redhat.com)
- 767246 - decompress metadata passed to modifyrepo to work around the f16
  modifyrepo issues (pkilambi@redhat.com)
- 729760 - Repo Sync - seems to be hung and status is confusing
  (jmatthews@redhat.com)
- 760458 - add makedirs() that fixes http://bugs.python.org/issue1675.
  (jortel@redhat.com)
- ran restapi.py (jconnor@redhat.com)
- 752803 added detailed list of parameters that can be updated to wiki doc
  (jconnor@redhat.com)
- 761039 - Task.exception = str(exception); more complete exception
  information. (jortel@redhat.com)
- 760777 added examples provided by mmccune :) (jconnor@redhat.com)
- 750302 added generic error exit for required append options along with
  utilization in users for permission grant (jconnor@redhat.com)
- 747975 made repo delete async (jconnor@redhat.com)
- 766705 - fixing UnboundLocalError when uploading a file due to filters
  (pkilambi@redhat.com)
- 765853 fixing race condition between task snapshot and setting of progress
  callback for repo clone and sync (jconnor@redhat.com)
- fist pass at /tasks/ controller testing (jconnor@redhat.com)
- added archived tasks to /tasks/ collection iff state=archived is passed in
  (jconnor@redhat.com)
- added id as valid filter on /tasks/ (jconnor@redhat.com)
- 765874 - Fixed amqp event handler loading. (jortel@redhat.com)
- Refinements to the relative path validation logic (jason.dobies@redhat.com)
- Automatic commit of package [python-isodate] minor release [0.4.4-4.pulp].
  (jslagle@redhat.com)
- removing yum_repo_grinder_lock from YumSynchronizer (skarmark@redhat.com)
- 760673 - Fix consumer group package install; Add support for remote class
  constuctor args. (jortel@redhat.com)
- 761205 - Nested relative paths are no longer allowed by Pulp
  (jason.dobies@redhat.com)
- Removing instantiation of repoapi from RepoCloneTask which can cause pickling
  of threading lock issue (skarmark@redhat.com)
- 742320 - fix group logicwhen running createrepo to use tyep.ext instead of
  whole filename causing file name too long errors (pkilambi@redhat.com)
- requires gofer 0.63; bump for project alignment. (jortel@redhat.com)
- SELinux: relabel files when rpm is uninstalled (jmatthews@redhat.com)
- 761232 - fix applied to pulp-cds for F16 compat. (jortel@redhat.com)
- SELinux: Change pulp log files to httpd_sys_content_rw_t
  (jmatthews@redhat.com)
- 761232 - replace /etc/init.d/ references to use /sbin/service instead for F16
  compat. (jortel@redhat.com)
- 760958 - Fixing DB validation error (skarmark@redhat.com)
- SELinux: quiet output from uninstall (jmatthews@redhat.com)
- 760310 - fix cloning a empty repo to handle gracefully (pkilambi@redhat.com)
- SELinux: fix for pulp_cert_t (jmatthews@redhat.com)
- 760766 - Updated content upload cli to parse new return format for
  repo.add_packages() with filters correctly (skarmark@redhat.com)
- SELinux: move setsebool to enable script to be executed during post
  (jmatthews@redhat.com)
- SELinux: rewrite rules to be based off of httpd content
  (jmatthews@redhat.com)
- Fixed 8 typos in the word "omitting" (jason.dobies@redhat.com)
- 710153 - Significant reworking of CDS status CLI command. Brought in line
  with the work done in this area on RHUI 2.0. (jason.dobies@redhat.com)
- SELinux: add file context for initrc script pulp-server
  (jmatthews@redhat.com)
- SELinux: changes for certs pulp creates, pulp_certs_t (jmatthews@redhat.com)
- 760745 - The CLI should pass None for consumer client bundle if no entries
  are present. (jason.dobies@redhat.com)
- Added updated count to harness display (jason.dobies@redhat.com)
- SELinux: leveraging apache_content_template(pulp) macro to simplify rules
  Updates for developer setup/uninstall scripts (jmatthews@redhat.com)
- SELinux: added error checking to making a policy (jmatthews@redhat.com)
- SELinux:  Adding bools to allow http to network and execute tmp files
  (jmatthews@redhat.com)
- SELinux rules update to leverage apache_content_template macro
  (jmatthews@redhat.com)
- Adding filtering capability for manually uploaded packages and custom errata
  (skarmark@redhat.com)
- 760607 - fixing the pkg list param (pkilambi@redhat.com)
- 745458 - Separated asynchronous operations in cloning process from
  synchronous operations such that clone task can be reloaded from db from a
  saved state in case pulp-server dies during cloning (skarmark@redhat.com)
* Fri Dec 02 2011 Jeff Ortel <jortel@redhat.com> 0.0.254-1
- fixing the clone to accoutn for el5 type metadata paths causing missing
  imports (pkilambi@redhat.com)
- SELinux update developer scripts, added a developer uninstall, fixed possible
  issue with grinder (jmatthews@redhat.com)
- Moved api_responses config from admin.conf to environment variables
  (skarmark@redhat.com)
- 756417 - ignore foreground option for group exports and let the server bad
  requests pass to clients (pkilambi@redhat.com)
- Added conduit utility method for building the publish report
  (jason.dobies@redhat.com)
- Renamed terminology in the managers to reflect referenced instead of
  parent/child units (jason.dobies@redhat.com)
- Parser and database changes for changing unique indexes to unit key.
  (jason.dobies@redhat.com)
- Updating bash completion script for latest changes (skarmark@redhat.com)
- Making pulp 'eval' free and updating repo list --note to accept a note in
  key:value format instead of dictionary (skarmark@redhat.com)
- 759153 - Add INI file validation. (jortel@redhat.com)
- README files to instruct on how to use the v2 plugins
  (jason.dobies@redhat.com)
- Added conduit syntactic sugar method for building sync reports.
  (jason.dobies@redhat.com)
- Added updated_count and split out summary and detail logs in plugin reports
  (jason.dobies@redhat.com)
- Added ability to override scenario properties at command line
  (jason.dobies@redhat.com)
- Made the delete repo not fail on an HTTP error code (jason.dobies@redhat.com)
- 756454 - Fixed package search with --repoids and removed eval
  (skarmark@redhat.com)