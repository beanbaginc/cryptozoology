=======================================
Cryptozoology: Cryptography's Companion
=======================================

**Project:** |license-badge| |reviewed-badge|

**Latest release:** |latest-version-badge| |latest-pyvers-badge|

Cryptozoology_ is a companion to the popular Cryptography_ package,
implementing common patterns for key and secrets management

This helps projects manage sensitive data in a responsible way, using
best practices for long-term storage and transmission of encrypted data.

Cryptozoology was built to help develop `Review Board`_, the code review tool
crafted for the modern world by Beanbag_, and we're making it available for
use in other projects.

See the documentation_ for more information and release notes.


.. _Cryptography: https://cryptography.io/
.. _Cryptozoology: https://pypi.org/project/cryptozoology
.. _Beanbag: https://www.beanbaginc.com
.. _Review Board: https://www.reviewboard.org
.. _documentation: https://cryptozoology.readthedocs.io/en/latest/

.. |latest-pyvers-badge| image:: https://img.shields.io/pypi/pyversions/cryptozoology
   :target: https://pypi.org/project/cryptozoology
.. |latest-version-badge| image:: https://img.shields.io/pypi/v/cryptozoology
   :target: https://pypi.org/project/cryptozoology
.. |license-badge| image:: https://img.shields.io/badge/license-MIT-green.svg
   :target: https://opensource.org/licenses/MIT
.. |reviewed-badge| image:: https://img.shields.io/badge/Review%20Board-d0e6ff?label=reviewed%20with
   :target: https://www.reviewboard.org


Features
========

* **Secrets management**, supporting encoding and decoding of plaintext data.

* **AES key management**, supporting key generation, deserialization,
  encryption/decryption, key wrapping/unwrapping, key exchange, and key
  derivation.

* **Elliptic Curve key management**, supporting key generation,
  deserialization, and ECDH key exchange.

* **Project-defined key types** using registries_.

* **Patterns for sensitive data management**

Future plans:

* **Key storage backends**, with versioning and key rotation.

* **ECIES** (Elliptic Curve Integrated Encryption Scheme) operations.


.. _registries: https://pypi.org/project/registries


Installation
============

To install Cryptozoology, run:

.. code-block:: console

   $ pip install cryptozoology

Cryptozoology follows `semantic versioning`_, meaning no surprises when you
upgrade.

.. _semantic versioning: https://semver.org/


Our Other Projects
==================

* `Review Board`_ -
  Our open source, extensible code review, document review, and image review
  tool built for the modern world.

* `Djblets <https://github.com/djblets/djblets/>`_ -
  Our pack of Django utilities for datagrids, API, extensions, and more. Used
  by Review Board.

* `Buildthings <https://github.com/beanbaginc/buildthings>`_ -
  A Python build backend that takes the pain out of working with
  in-development projects that need to depend on each other.

* `Housekeeping <https://github.com/beanbaginc/housekeeping>`_ -
  Deprecation management for Python modules, classes, functions, and
  attributes.

* `kgb <https://github.com/beanbaginc/kgb>`_ -
  A powerful function spy implementation to help write Python unit tests.

* Registries_ -
  A flexible, typed implementation of the Registry Pattern for more
  maintainable and extensible codebases.

* `Typelets <https://github.com/beanbaginc/python-typelets>`_ -
  Type hints and utility objects for Python and Django projects.

You can see more on `github.com/beanbaginc <https://github.com/beanbaginc>`_
and `github.com/reviewboard <https://github.com/reviewboard>`_.
