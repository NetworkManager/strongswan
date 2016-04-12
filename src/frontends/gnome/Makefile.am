AUTOMAKE_OPTIONS = foreign

SUBDIRS = properties auth-dialog po

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-strongswan-service.conf

nmvpnservicedir = $(prefix)/lib/NetworkManager/VPN
nmvpnservice_DATA = nm-strongswan-service.name

oldnmvpnservicedir = $(sysconfdir)/NetworkManager/VPN
oldnmvpnservice_DATA = $(nmvpnservice_DATA)

@INTLTOOL_DESKTOP_RULE@

nm-strongswan-service.name: $(srcdir)/nm-strongswan-service.name.in
	$(AM_V_GEN) \
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|' \
	    -e 's|[@]PLUGINDIR[@]|$(libdir)/NetworkManager|g' \
	    -e 's|[@]CHARON[@]|$(charon)|' $< >$@

EXTRA_DIST = nm-strongswan-service.name.in \
    $(dbusservice_DATA)  \
    intltool-extract.in  \
    intltool-merge.in    \
    intltool-update.in

CLEANFILES = $(nmvpnservice_DATA) *~
DISTCLEANFILES = intltool-extract intltool-merge intltool-update

ACLOCAL_AMFLAGS = -I m4
