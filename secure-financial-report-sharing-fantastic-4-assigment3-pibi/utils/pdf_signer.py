import io
import os
import tempfile
from pyhanko.sign import signers, fields
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.pdf_utils.reader import PdfFileReader

# Import dari PyHanko untuk memuat Key & Cert dengan benar
from pyhanko.sign.general import load_cert_from_pemder, load_private_key_from_pemder
from pyhanko_certvalidator.registry import SimpleCertificateStore
from pyhanko_certvalidator.context import ValidationContext

# Import cryptography untuk serialisasi kunci
from cryptography.hazmat.primitives import serialization

def sign_pdf(file_bytes, private_key_obj, cert_pem_bytes):
    """
    Menanamkan tanda tangan digital PAdES ke dalam file PDF.
    Menggunakan file sementara untuk memastikan kompatibilitas objek Key & Cert.
    """
    
    tmp_cert_path = None
    tmp_key_path = None

    try:
        # --- LANGKAH 1: SIAPKAN FILE SEMENTARA ---
        
        # A. Simpan Sertifikat ke temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as tmp_cert:
            tmp_cert.write(cert_pem_bytes)
            tmp_cert_path = tmp_cert.name

        # B. Simpan Private Key ke temp file (Format PEM tanpa enkripsi password)
        # Kita harus melakukan ini agar loader PyHanko bisa membacanya dan mengonversi
        # menjadi objek yang memiliki metode .dump()
        key_pem_bytes = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as tmp_key:
            tmp_key.write(key_pem_bytes)
            tmp_key_path = tmp_key.name

        # --- LANGKAH 2: MUAT ULANG MENGGUNAKAN LOADER PYHANKO ---
        
        # Load Certificate & Key menggunakan loader bawaan PyHanko
        # Ini mengatasi error AttributeError 'dump' dan TypeError
        cert_obj = load_cert_from_pemder(tmp_cert_path)
        key_obj = load_private_key_from_pemder(tmp_key_path, password=None)

        # --- LANGKAH 3: PROSES SIGNING ---

        # Siapkan Registry
        cert_registry = SimpleCertificateStore()
        cert_registry.register(cert_obj)

        # Siapkan Signer dengan objek yang sudah kompatibel
        signer = signers.SimpleSigner(
            signing_cert=cert_obj,
            signing_key=key_obj,
            cert_registry=cert_registry
        )

        pdf_input = io.BytesIO(file_bytes)
        
        # strict=False membantu menangani file PDF yang mungkin sedikit tidak standar
        w = IncrementalPdfFileWriter(pdf_input, strict=False)

        # Buat signature field visual
        fields.append_signature_field(
            w,
            sig_field_spec=fields.SigFieldSpec(
                sig_field_name="Signature1",
                on_page=0,
                box=(50, 50, 250, 100)
            )
        )

        out = io.BytesIO()

        # Eksekusi Signing
        signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(
                field_name="Signature1",
                reason="Financial Report Approval",
                location="Secure System"
            ),
            signer=signer,
            output=out
        )

        return out.getvalue()

    finally:
        # Bersihkan file-file sementara
        for path in [tmp_cert_path, tmp_key_path]:
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except:
                    pass

def verify_pdf(file_bytes):
    """
    Memverifikasi tanda tangan PDF.
    """
    if not file_bytes:
        return {"valid": False, "message": "File kosong"}

    try:
        reader = PdfFileReader(io.BytesIO(file_bytes))

        if not reader.embedded_signatures:
            return {"valid": False, "message": "Tidak ada tanda tangan"}

        sig = reader.embedded_signatures[0]
        vc = ValidationContext()

        status = validate_pdf_signature(sig, validation_context=vc)

        # Ambil info penanda tangan
        cert = sig.signer_cert
        # Menggunakan subject.human_friendly agar lebih mudah dibaca
        subject = cert.subject.human_friendly if hasattr(cert.subject, 'human_friendly') else "Unknown"

        result = {
            "valid": status.intact and status.valid,
            "signer": subject,
            "integrity": status.intact,
            "timestamp": status.signer_reported_dt.strftime("%Y-%m-%d %H:%M:%S") if status.signer_reported_dt else "N/A",
            "summary": status.summary()
        }

        return result

    except Exception as e:
        return {"valid": False, "message": f"Error validasi: {e}"}