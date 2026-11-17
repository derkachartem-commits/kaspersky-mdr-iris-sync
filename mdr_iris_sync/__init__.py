"""Bidirectional Kaspersky MDR <-> DFIR-IRIS synchronization.

The package contains a small, dependency-light integration:

* :mod:`mdr_iris_sync.mdr_client` - MDR REST API client with rotating tokens.
* :mod:`mdr_iris_sync.iris_client` - DFIR-IRIS REST API v2 client.
* :mod:`mdr_iris_sync.sync` - the synchronization engine.
"""

__version__ = "1.0.1"
