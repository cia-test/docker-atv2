import os
import argparse
import ipaddress
import getpass
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes


def generate_name(common_name):
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NO"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Trd"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Trd"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Nordicsemi"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def generate_san(dns_names, dns_ips):
    alt_names = list()
    if dns_names:
        alt_names.extend([x509.DNSName(x) for x in dns_names])
    if dns_ips:
        alt_names.extend([x509.IPAddress(ipaddress.ip_address(x)) for x in dns_ips])

    alt_names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    alt_names.append(x509.DNSName("localhost"))
    return x509.SubjectAlternativeName(alt_names)


def load_cert(certfile):
    print(f"Loaded certificate file: {certfile}")
    with open(certfile, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_key(key, password=None):
    with open(key, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)


def check_overwrite(filename):
    if os.path.isfile(filename):
        overwrite = input(f"{filename} exsists, overwrite? [yN] ")
        if overwrite != "y":
            print("Exiting")
            exit()


def write_key(filename, key, password=None):
    if password:
        alg = serialization.BestAvailableEncryption(password)
    else:
        alg = serialization.NoEncryption()

    with open(filename, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=alg,
            )
        )
    print(f"Created: {filename}")


def write_cert(filename, cert):
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Created: {filename}")


def build_cert(subject, issuer, pubkey, privkey, san):
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pubkey.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    )
    if subject == issuer:
        cert = cert.add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=False,
        )
    if san:
        cert = cert.add_extension(san, False)
    return cert.sign(privkey, hashes.SHA256())


def generate_root_cert(name, san):
    print(f"Generating self-signed {name}")

    key = generate_private_key()

    issuer = subject = generate_name(f"root-{name}")
    cert = build_cert(subject, issuer, key, key, san)

    try:
        os.mkdir("ca")
    except:
        pass

    cert_name = f"ca/{name}-ca.pem"
    privkey_name = f"ca/{name}-privkey.pem"

    check_overwrite(cert_name)

    password = getpass.getpass(f"Create password for private key {name}: ")

    write_cert(cert_name, cert)
    write_key(privkey_name, key, password.encode())


def generate_cert(root_name, cert_name, san):
    print(f"Generating {cert_name} signed by {root_name}")
    cert_key = generate_private_key()
    try:
        os.mkdir("cert")
    except:
        pass
    password = getpass.getpass(f"Enter password for private key {root_name}: ")

    root_key = load_key(f"ca/{root_name}-privkey.pem", password.encode())
    ca = load_cert(f"ca/{root_name}-ca.pem")
    subject = generate_name(f"cert-{cert_name}")
    cert = build_cert(subject, ca.issuer, cert_key, root_key, san)

    cert_path = f"cert/{cert_name}-cert-signed-by-{root_name}.pem"
    privkey_path = f"cert/{cert_name}-privkey.pem"

    check_overwrite(cert_path)

    write_cert(cert_path, cert)
    write_key(privkey_path, cert_key)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--generate-root")
    parser.add_argument("--generate-cert", nargs=2)
    parser.add_argument("--dns-names", nargs="*")
    parser.add_argument("--dns-ips", nargs="*")
    args = parser.parse_args()
    san = generate_san(args.dns_names, args.dns_ips)
    if args.generate_root:
        generate_root_cert(args.generate_root, san)
    if args.generate_cert:
        generate_cert(*args.generate_cert, san)
