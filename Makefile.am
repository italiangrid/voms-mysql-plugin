SUBDIRS = config src 
ACLOCAL_AMFLAGS = -I m4

rpmbuild_dir=@WORKDIR@/rpmbuild
debbuild_dir=@WORKDIR@/debbuild

distsrc: dist
	mv $(distdir).tar.gz $(DISTTAR)/$(distdir)_src.tar.gz

distclean-local:
	rm -f configure aclocal.m4 $(distdir).tar.gz
	rm -f m4/libtool.m4 m4/ltoptions.m4 m4/ltsugar.m4 m4/ltversion.m4 m4/lt~obsolete.m4
	rm -rf autom4te.cache aux src/autogen $(rpmbuild_dir) $(debbuild_dir)
	find . -name Makefile.in -exec rm {} \;

clean-local:
	rm -rf $(rpmbuild_dir) $(debbuild_dir) $(distdir).tar.gz dist
