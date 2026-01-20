import streamlit as st
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# =========================
# GENERATE RSA KEY
# =========================
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    with open("private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open("public_key.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

# =========================
# LOAD KEYS
# =========================
def load_private_key():
    with open("private_key.pem", "rb") as f:
        return serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

def load_public_key():
    with open("public_key.pem", "rb") as f:
        return serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )

# =========================
# STREAMLIT UI
# =========================
st.title("🔐 Aplikasi Digital Signature Dokumen")
st.write("Implementasi Digital Signature menggunakan Hash dan RSA")

if st.button("Generate RSA Key"):
    generate_keys()
    st.success("Kunci RSA berhasil dibuat!")

st.divider()

# =========================
# SIGN FILE
# =========================
st.header("✍️ Penandatanganan Dokumen")

file = st.file_uploader("Upload Dokumen", type=None)

if file is not None and st.button("Buat Digital Signature"):
    data = file.read()

    # Hash file
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    hash_value = digest.finalize()

    private_key = load_private_key()

    signature = private_key.sign(
        hash_value,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    with open("signature.sig", "wb") as f:
        f.write(signature)

    st.success("Digital Signature berhasil dibuat!")
    st.download_button("Download Signature", signature, file_name="signature.sig")

st.divider()

# =========================
# VERIFY SIGNATURE
# =========================
st.header("🔍 Verifikasi Dokumen")

file_verify = st.file_uploader("Upload Dokumen untuk Verifikasi", key="file2")
signature_file = st.file_uploader("Upload Signature", key="sig")

if file_verify and signature_file and st.button("Verifikasi"):
    data = file_verify.read()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    hash_value = digest.finalize()

    public_key = load_public_key()
    signature = signature_file.read()

    try:
        public_key.verify(
            signature,
            hash_value,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        st.success("✅ Dokumen ASLI dan TIDAK BERUBAH")
    except:
        st.error("❌ Dokumen TIDAK VALID atau TELAH DIUBAH")
