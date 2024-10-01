sfparse - Structured Field Values parser
========================================

sfparse is a `RFC 9651
<https://datatracker.ietf.org/doc/html/rfc9651>`_ Structured Field
Values parser written in C.

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
