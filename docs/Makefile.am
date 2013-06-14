if HAVE_DOXYGEN
htmldocdir = $(docdir)/html

doxygen/html/index.html: Doxyfile $(top_srcdir)/include/
	doxygen $<

all-local: doxygen/html/index.html

install-html:
	$(INSTALL) -d $(DESTDIR)$(htmldocdir)
	cd doxygen/html && \
           find . -type f -exec $(INSTALL_DATA) -D {} $(DESTDIR)$(htmldocdir)/{} \;

install-data-local: install-html

uninstall-local:
	rm -rf $(DESTDIR)$(htmldocdir)

clean-local:
	rm -rf doxygen/

endif
