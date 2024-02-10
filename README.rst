sfparse - Structured Field Values parser
========================================

sfparse is a Structured Field Values parser written in C.

- `RFC 8941 <https://www.rfc-editor.org/rfc/rfc8941.html>`_
- `draft-ietf-httpbis-sfbis <https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-sfbis>`_

`Online documentation <https://nghttp2.org/sfparse/>`_ is available.

`examples.c <examples.c>`_ contains usage examples of this library.

Build from git
---------------

.. code-block:: shell

   $ git clone https://github.com/ngtcp2/sfparse
   $ cd sfparse
   $ git submodule update --init
   $ autoreconf -i
   $ ./configure
   $ make -j$(nproc) check
