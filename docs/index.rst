.. _cryptozoology-docs:

========================
Cryptozoology for Python
========================

Cryptozoology is a companion to the popular Cryptography_ package,
implementing common patterns for key and secrets management

This helps projects manage sensitive data in a responsible way, using
best practices for long-term storage and transmission of encrypted data.

Cryptozoology was built to help develop `Review Board`_, the code review
tool crafted for the modern world from Beanbag_, and we're making it available
for use in other projects.


.. _Beanbag: https://www.beanbaginc.com
.. _Cryptography: https://cryptography.io/
.. _Review Board: https://www.reviewboard.org


Features
========

* **Secrets management**, supporting encoding and decoding of plaintext data.

* **AES key management**, supporting key generation, deserialization,
  encryption/decryption, key wrapping/unwrapping, key exchange, and key
  derivation.

* **Elliptic Curve key management**, supporting key generation,
  deserialization, and ECDH key exchange.

* **Project-defined key types** using :pypi:`registries`.

* **Patterns for sensitive data management**.

Future plans:

* **Key storage backends**, with versioning and key rotation.

* **ECIES** (`Elliptic Curve Integrated Encryption Scheme <ecies_>`_)
  operations.


.. _ecies: https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme


Installation
============

To install Cryptozoology, run:

.. code-block:: console

   $ pip install cryptozoology

Cryptozoology follows `semantic versioning`_, meaning no surprises when you
upgrade.

.. _semantic versioning: https://semver.org/


Documentation
=============

.. toctree::
   :maxdepth: 3

   releasenotes/index
   coderef/index


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
