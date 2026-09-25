
"""
Unit tests for Static Binary Cryptographic detector.
"""

import os
import tempfile

from scanner.detectors.binary_detector import scan_binary_file


def test_binary_embedded_pem():
    content = (
        b"header\n"
        b"-----BEGIN CERTIFICATE-----\n"
        b"MIIC...\n"
        b"-----END CERTIFICATE-----\n"
        b"footer"
    )

    with tempfile.NamedTemporaryFile("wb", suffix=".so", delete=False) as f:
        f.write(content)
        f_path = f.name

    try:
        results = scan_binary_file(f_path)

        cert_finding = next(
            (r for r in results if r.get("artifact_type") == "certificate"),
            None,
        )

        assert cert_finding is not None
        assert cert_finding.get("detection_method") == "binary_embedded_cert"
    finally:
        os.unlink(f_path)


def test_binary_malformed():
    content = b"NOT_A_VALID_BINARY_OR_ELF"

    with tempfile.NamedTemporaryFile("wb", suffix=".dll", delete=False) as f:
        f.write(content)
        f_path = f.name

    try:
        results = scan_binary_file(f_path)

        assert isinstance(results, list)
    finally:
        os.unlink(f_path)


def test_elf_crypto_symbol_detection(monkeypatch):
    """
    Verify that an ELF .dynstr/.strtab section containing a known
    cryptographic symbol produces a binary ELF finding.
    """

    class FakeSection:
        name = ".dynstr"

        def data(self):
            return b"\x00RSA_generate_key_ex\x00"

    class FakeELF:
        def iter_sections(self):
            return [FakeSection()]

    class FakeELFFile:
        def __init__(self, file_object):
            pass

        def iter_sections(self):
            return FakeELF().iter_sections()

    import scanner.detectors.binary_detector as binary_detector

    monkeypatch.setattr(binary_detector, "ELFFile", FakeELFFile)

    with tempfile.NamedTemporaryFile("wb", suffix=".so", delete=False) as f:
        f.write(b"fake elf content")
        f_path = f.name

    try:
        results = scan_binary_file(f_path)

        finding = next(
            (
                r
                for r in results
                if r.get("detection_method") == "binary_elf_symbol"
            ),
            None,
        )

        assert finding is not None
        assert finding.get("algorithm") == "RSA"
        assert finding.get("library") == "OpenSSL"
    finally:
        os.unlink(f_path)


def test_elf_crypto_library_detection(monkeypatch):
    """
    Verify that an ELF string section containing a known crypto library
    produces a library finding.
    """

    class FakeSection:
        name = ".dynstr"

        def data(self):
            return b"\x00libcrypto.so\x00"

    class FakeELFFile:
        def __init__(self, file_object):
            pass

        def iter_sections(self):
            return [FakeSection()]

    import scanner.detectors.binary_detector as binary_detector

    monkeypatch.setattr(binary_detector, "ELFFile", FakeELFFile)

    with tempfile.NamedTemporaryFile("wb", suffix=".so", delete=False) as f:
        f.write(b"fake elf content")
        f_path = f.name

    try:
        results = scan_binary_file(f_path)

        finding = next(
            (
                r
                for r in results
                if r.get("detection_method") == "binary_elf_needed"
            ),
            None,
        )

        assert finding is not None
        assert finding.get("artifact_type") == "library"
        assert finding.get("library") == "OpenSSL libcrypto"
    finally:
        os.unlink(f_path)


def test_pe_crypto_import_detection(monkeypatch):
    """
    Verify that a PE import containing a known cryptographic function
    produces a crypto finding.
    """

    class FakeImport:
        name = b"BCryptEncrypt"

    class FakeImportEntry:
        dll = b"bcrypt.dll"
        imports = [FakeImport()]

    class FakePE:
        def __init__(self, file_path, fast_load=True):
            self.DIRECTORY_ENTRY_IMPORT = [FakeImportEntry()]

        def parse_data_directories(self):
            pass

    import scanner.detectors.binary_detector as binary_detector

    monkeypatch.setattr(binary_detector.pefile, "PE", FakePE)

    with tempfile.NamedTemporaryFile("wb", suffix=".dll", delete=False) as f:
        f.write(b"fake pe content")
        f_path = f.name

    try:
        results = scan_binary_file(f_path)

        symbol_finding = next(
            (
                r
                for r in results
                if r.get("detection_method") == "binary_pe_symbol"
            ),
            None,
        )

        library_finding = next(
            (
                r
                for r in results
                if r.get("detection_method") == "binary_pe_import"
            ),
            None,
        )

        assert symbol_finding is not None
        assert symbol_finding.get("algorithm") == "AES"
        assert symbol_finding.get("library") == "Windows CNG"

        assert library_finding is not None
        assert library_finding.get("library") == "Windows CNG"
    finally:
        os.unlink(f_path)


def test_pe_crypto_export_detection(monkeypatch):
    """
    Verify that a PE exported cryptographic function produces a finding.
    """

    class FakeExport:
        name = b"RSA_generate_key_ex"

    class FakeExportDirectory:
        symbols = [FakeExport()]

    class FakePE:
        def __init__(self, file_path, fast_load=True):
            self.DIRECTORY_ENTRY_EXPORT = FakeExportDirectory()

        def parse_data_directories(self):
            pass

    import scanner.detectors.binary_detector as binary_detector

    monkeypatch.setattr(binary_detector.pefile, "PE", FakePE)

    with tempfile.NamedTemporaryFile("wb", suffix=".exe", delete=False) as f:
        f.write(b"fake pe content")
        f_path = f.name

    try:
        results = scan_binary_file(f_path)

        finding = next(
            (
                r
                for r in results
                if r.get("detection_method") == "binary_pe_symbol"
            ),
            None,
        )

        assert finding is not None
        assert finding.get("algorithm") == "RSA"
        assert finding.get("library") == "OpenSSL"
    finally:
        os.unlink(f_path)


def test_binary_extensionless_elf_dispatch(monkeypatch):
    """
    Verify that an extensionless file is sent to the ELF scanner.
    """

    called = {"value": False}

    def fake_elf_scan(file_path):
        called["value"] = True
        return []

    import scanner.detectors.binary_detector as binary_detector

    monkeypatch.setattr(binary_detector, "_scan_elf_binary", fake_elf_scan)

    with tempfile.NamedTemporaryFile("wb", suffix="", delete=False) as f:
        f.write(b"fake binary")
        f_path = f.name

    try:
        scan_binary_file(f_path)
        assert called["value"] is True
    finally:
        os.unlink(f_path)


def test_binary_unknown_extension_does_not_run_elf_or_pe(monkeypatch):
    """
    Verify that an unsupported extension does not incorrectly enter
    the ELF or PE parser.
    """

    called = {"elf": False, "pe": False}

    def fake_elf_scan(file_path):
        called["elf"] = True
        return []

    def fake_pe_scan(file_path):
        called["pe"] = True
        return []

    import scanner.detectors.binary_detector as binary_detector

    monkeypatch.setattr(binary_detector, "_scan_elf_binary", fake_elf_scan)
    monkeypatch.setattr(binary_detector, "_scan_pe_binary", fake_pe_scan)

    with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as f:
        f.write(b"not a supported binary")
        f_path = f.name

    try:
        results = scan_binary_file(f_path)

        assert isinstance(results, list)
        assert called["elf"] is False
        assert called["pe"] is False
    finally:
        os.unlink(f_path)

