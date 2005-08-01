
SUBDIRS = config src 

ACLOCAL_AMFLAGS = -I project

stage:
	@set fnord $(MAKEFLAGS); amf=$$2; \
	dot_seen=no; \
        target="install"; \
	prefix_arg=@prefix@; \
        list='$(SUBDIRS)'; for subdir in $$list; do \
          echo "Making $$target $$prefix_arg in $$subdir"; \
          if test "$$subdir" = "."; then \
            dot_seen=yes; \
            local_target="$$target-am"; \
          else \
            local_target="$$target"; \
          fi; \
          (cd $$subdir && $(MAKE) $(AM_MAKEFLAGS) $$local_target $$prefix_arg) \
           || case "$$amf" in *=*) exit 1;; *k*) fail=yes;; *) exit 1;; esac; \
        done; \
        if test "$$dot_seen" = "no"; then \
          $(MAKE) $(AM_MAKEFLAGS) "$$target-am" $$prefix_arg || exit 1; \
        fi; test -z "$$fail"

distsrc: dist
	mv $(distdir).tar.gz $(DISTTAR)/$(distdir)_src.tar.gz

distbin:
	pushd @prefix@; \
	$(AMTAR) -czf $(DISTTAR)/$(distdir)_bin.tar.gz lib/libvomsmysql.* lib/libmysqlplus.* etc/voms/voms-mysql*; \
	popd

