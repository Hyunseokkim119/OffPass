#!/usr/bin/env python3
"""
OffPass PoC - Offline Derived Credential (ODC) pipeline
  credential(CBOR) -> COSE_Sign1(ES256) -> HPKE-style envelope (ECDH-P256 + HKDF-SHA256 + AES-256-GCM)
  -> zlib(optional) -> Base45 -> QR (alphanumeric mode) -> scan -> verify (offline)
All measurements are produced by this script (no hand-written numbers).
"""
import io, os, sys, time, json, zlib, hashlib, secrets, datetime as dt
import cbor2
import numpy as np
from PIL import Image
from skimage import data
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
import qrcode
from qrcode.constants import ERROR_CORRECT_L, ERROR_CORRECT_M, ERROR_CORRECT_Q
import zxingcpp

OUT = os.path.join(os.path.dirname(__file__), "out")
os.makedirs(OUT, exist_ok=True)

# ---------------- Base45 (RFC 9285) ----------------
B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
def b45encode(b: bytes) -> str:
    out = []
    for i in range(0, len(b), 2):
        chunk = b[i:i+2]
        if len(chunk) == 2:
            n = chunk[0] * 256 + chunk[1]
            e, n = n % 45, n // 45
            d, c = n % 45, n // 45
            out += [B45[e], B45[d], B45[c]]
        else:
            n = chunk[0]
            d, c = n % 45, n // 45
            out += [B45[d], B45[c]]
    return "".join(out)

def b45decode(s: str) -> bytes:
    out = bytearray()
    vals = [B45.index(ch) for ch in s]
    for i in range(0, len(vals), 3):
        chunk = vals[i:i+3]
        if len(chunk) == 3:
            n = chunk[0] + chunk[1]*45 + chunk[2]*45*45
            out += bytes([n // 256, n % 256])
        else:
            n = chunk[0] + chunk[1]*45
            out += bytes([n])
    return bytes(out)

# ---------------- Keys ----------------
issuer_sk = ec.generate_private_key(ec.SECP256R1())          # 발급기관 서명키 (ES256)
issuer_pk = issuer_sk.public_key()
verifiers = {}
for vid in ["KICE-CSAT-2027", "KMA-GATE-01", "OTHER-VERIFIER"]:
    sk = ec.generate_private_key(ec.SECP256R1())
    verifiers[vid] = sk                                      # 검증기관 복호키 (HSM/보안영역에 보관 가정)

def pk_bytes(pk):  # compressed point (33 bytes)
    return pk.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)

def kid_of(pk):
    return hashlib.sha256(pk_bytes(pk)).digest()[:4]

# ---------------- Sample photo (public-domain test image, face region) ----------------
def sample_face():
    img = data.astronaut()                 # NASA public-domain test image (skimage)
    face = img[20:200, 150:330]            # face region crop (approx.)
    return Image.fromarray(face).convert("L")

def photo_bytes(size=(96, 120), quality=50):
    im = sample_face().resize(size, Image.LANCZOS)
    buf = io.BytesIO()
    im.save(buf, format="JPEG", quality=quality, optimize=True, progressive=False)
    return buf.getvalue()

# ---------------- Credential ----------------
def make_credential(photo: bytes, vid: str, purpose: str, ref: str,
                    name="홍길동", birth="20080315", id_type="RRC",
                    valid_from=None, valid_to=None):
    now = int(time.time())
    return {
        1: 1,                       # ver
        2: id_type,                 # 신분증 종류 (RRC=주민등록증, DL=운전면허증 ...)
        3: name,                    # 성명
        4: birth,                   # 생년월일 (YYYYMMDD)
        5: photo,                   # 축소 사진 (JPEG bytes)
        6: ref,                     # 참조번호(수험번호/방문번호), optional
        7: vid,                     # 검증기관 ID (용도·장소 바인딩)
        8: purpose,                 # 용도 (EXAM/VISIT/EMERG)
        9: valid_from or now,       # 유효 시작 (epoch)
        10: valid_to or now + 12*3600,  # 유효 종료 (epoch)
        11: secrets.token_bytes(8), # 일련번호 (1회용 사용 체크)
        12: now,                    # 발급시각
    }

def cose_sign1(payload: bytes, sk, kid: bytes) -> bytes:
    protected = cbor2.dumps({1: -7, 4: kid})               # alg=ES256, kid
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    der = sk.sign(sig_structure, ec.ECDSA(hashes.SHA256()))
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(der)
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")    # raw r||s (64 bytes)
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, sig]))

def cose_verify1(msg: bytes, pk) -> bytes:
    tag = cbor2.loads(msg)
    assert tag.tag == 18
    protected, _unprot, payload, sig = tag.value
    hdr = cbor2.loads(protected)
    assert hdr[1] == -7
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    pk.verify(der, sig_structure, ec.ECDSA(hashes.SHA256()))   # raises InvalidSignature
    return payload

def envelope_encrypt(plain: bytes, verifier_pk, vid: str) -> bytes:
    """HPKE-style: DHKEM(P-256) + HKDF-SHA256 + AES-256-GCM (simplified labels)."""
    eph = ec.generate_private_key(ec.SECP256R1())
    shared = eph.exchange(ec.ECDH(), verifier_pk)
    enc = pk_bytes(eph.public_key())
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"OffPass-v1|" + vid.encode() + b"|" + enc + b"|" + pk_bytes(verifier_pk)).derive(shared)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, plain, b"OffPass-v1")
    return cbor2.dumps([1, kid_of(verifier_pk), enc, nonce, ct])   # version, verifier kid, enc, nonce, ct

def envelope_decrypt(env: bytes, verifier_sk, vid: str) -> bytes:
    ver, kid, enc, nonce, ct = cbor2.loads(env)
    vpk = verifier_sk.public_key()
    if kid != kid_of(vpk):
        raise ValueError("검증기관 불일치(kid mismatch): 이 기관용 증표가 아님")
    eph_pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), enc)
    shared = verifier_sk.exchange(ec.ECDH(), eph_pk)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"OffPass-v1|" + vid.encode() + b"|" + enc + b"|" + pk_bytes(vpk)).derive(shared)
    return AESGCM(key).decrypt(nonce, ct, b"OffPass-v1")

PREFIX = "OP1:"

def issue(photo: bytes, vid: str, purpose="EXAM", ref="12345678", compress=False, **kw):
    cred = make_credential(photo, vid, purpose, ref, **kw)
    payload = cbor2.dumps(cred)
    signed = cose_sign1(payload, issuer_sk, kid_of(issuer_pk))
    env = envelope_encrypt(signed, verifiers[vid].public_key(), vid)
    body = zlib.compress(env, 9) if compress else env
    text = PREFIX + b45encode(body)
    return cred, dict(payload=len(payload), signed=len(signed), env=len(env), body=len(body), text=len(text)), text

def verify(text: str, vid: str, now=None, used=set(), compress=False):
    t0 = time.perf_counter()
    assert text.startswith(PREFIX)
    body = b45decode(text[len(PREFIX):])
    env = zlib.decompress(body) if compress else body
    signed = envelope_decrypt(env, verifiers[vid], vid)
    payload = cose_verify1(signed, issuer_pk)
    cred = cbor2.loads(payload)
    now = now or int(time.time())
    if cred[7] != vid: raise ValueError("용도/기관 바인딩 불일치")
    if not (cred[9] <= now <= cred[10]): raise ValueError("유효기간 외")
    if cred[11] in used: raise ValueError("이미 사용된 증표(일련번호 중복)")
    used.add(cred[11])
    return cred, (time.perf_counter() - t0) * 1000.0

def qr_for(text: str, ec_level):
    q = qrcode.QRCode(error_correction=ec_level, border=4, box_size=4)
    q.add_data(text)      # library auto-selects alphanumeric mode for Base45 charset
    q.make(fit=True)
    return q

def main():
    results = []
    sizes = [(64, 80), (80, 100), (96, 120), (112, 140), (128, 160)]
    quals = [40, 50, 60]
    for size in sizes:
        for qv in quals:
            ph = photo_bytes(size, qv)
            cred, sz, text = issue(ph, "KICE-CSAT-2027")
            row = dict(w=size[0], h=size[1], q=qv, jpeg=len(ph), **sz)
            for name, lvl in [("L", ERROR_CORRECT_L), ("M", ERROR_CORRECT_M), ("Q", ERROR_CORRECT_Q)]:
                try:
                    q = qr_for(text, lvl)
                    row[f"qr_{name}"] = q.version
                except Exception:
                    row[f"qr_{name}"] = None
            results.append(row)
    # compression check on one config
    ph = photo_bytes((96, 120), 50)
    _, s_nc, _ = issue(ph, "KICE-CSAT-2027", compress=False)
    _, s_c, _ = issue(ph, "KICE-CSAT-2027", compress=True)
    comp_note = dict(no_zlib=s_nc, zlib=s_c)

    # Reference config: 96x120 q50, EC-M -> generate PNG and round-trip through a real QR decoder
    ph = photo_bytes((96, 120), 50)
    cred, sz, text = issue(ph, "KICE-CSAT-2027", ref="12345678")
    q = qr_for(text, ERROR_CORRECT_M)
    img = q.make_image(fill_color="black", back_color="white").convert("L")
    qr_path = os.path.join(OUT, "offpass_qr_demo.png")
    img.save(qr_path)
    # decode with zxing-cpp (real scanner library)
    res = zxingcpp.read_barcode(np.array(img))
    assert res is not None and res.text == text, "QR round-trip failed"
    scan_ok = res.text == text
    # verify timing (offline)
    used = set()
    times = []
    for _ in range(50):
        c, ms = verify(text, "KICE-CSAT-2027", used=set())
        times.append(ms)
    v_ms = float(np.median(times))
    # negative tests
    neg = {}
    try: verify(text, "OTHER-VERIFIER")
    except Exception as e: neg["other_verifier"] = type(e).__name__ + ": " + str(e)
    try: verify(text, "KICE-CSAT-2027", now=cred[10] + 3600)
    except Exception as e: neg["expired"] = type(e).__name__ + ": " + str(e)
    try:
        bad = text[:-10] + ("A" if text[-10] != "A" else "B") + text[-9:]
        verify(bad, "KICE-CSAT-2027")
    except Exception as e: neg["tampered"] = type(e).__name__ + ": " + str(e)
    try:
        u = set(); verify(text, "KICE-CSAT-2027", used=u); verify(text, "KICE-CSAT-2027", used=u)
    except Exception as e: neg["replay_same_verifier"] = type(e).__name__ + ": " + str(e)
    # recovered photo
    c, _ = verify(text, "KICE-CSAT-2027", used=set())
    Image.open(io.BytesIO(c[5])).save(os.path.join(OUT, "recovered_photo.png"))

    summary = dict(results=results, compression=comp_note, reference=dict(
        size="96x120", quality=50, **sz, qr_version_M=q.version, modules=q.modules_count,
        scan_roundtrip=scan_ok, verify_ms_median=round(v_ms, 2), negative_tests=neg,
        qr_png=qr_path))
    with open(os.path.join(OUT, "measurements.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2, default=str)
    print(json.dumps(summary, ensure_ascii=False, indent=1, default=str))

if __name__ == "__main__":
    main()
