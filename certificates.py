import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import datetime
from cryptography import x509
from cryptography.x509 import CertificateBuilder, Name, NameAttribute, SubjectAlternativeName, DNSName
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature

"""Script para generar CA raíz y CA subordinada"""

'''Certificados'''
# Función para generar una clave RSA
def generate_rsa_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

# Función para crear un certificado autofirmado para la AC raíz
def create_root_ca_certificate(private_key, common_name="www.cripto-boss.com"):
    subject = Name([
        NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
        NameAttribute(NameOID.LOCALITY_NAME, u"Madrid"),
        NameAttribute(NameOID.ORGANIZATION_NAME, u"Crypto Boss Holding. Raiz"),
        NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    cert = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            SubjectAlternativeName([DNSName(common_name)]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )   
    return cert
# Función para guardar la clave privada en un archivo PEM
def save_private_key(private_key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

# Función para guardar un certificado en un archivo PEM
def save_certificate(cert, filename):
    with open(filename, "wb") as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

# Función para crear un certificado firmado por la CA raíz para una CA subordinada
def create_subordinate_ca_certificate(private_key, root_ca_private_key, root_ca_subject, common_name="www.cripto-martin.com"):
    subject = Name([
        NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
        NameAttribute(NameOID.LOCALITY_NAME, u"Madrid"),
        NameAttribute(NameOID.ORGANIZATION_NAME, u"Cripto Martin Subordinada"),
        NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    cert = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_ca_subject)  # Firmado por la CA raíz
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            SubjectAlternativeName([DNSName(common_name)]),
            critical=False,
        )
        .sign(root_ca_private_key, hashes.SHA256())  # Firma con la clave privada de la AC raíz
    )
    return cert

# Función principal que ejecuta todo el proceso
def setup_pki():
    print("Generación claves RSA para la CA raíz y para una CA subordinada:")
    print("-------------------------------------------------------")
    root_ca_private_key = generate_rsa_key()
    subordinate_ca_private_key = generate_rsa_key()
    print("-------------------------------------------------------")
    
    print("Creación certificado autofirmado para la CA raíz:")
    print("-------------------------------------------------------")
    root_ca_cert = create_root_ca_certificate(root_ca_private_key)
    print(root_ca_cert)
    print("-------------------------------------------------------")
    
    print("Creación certificado para la CA subordinada, firmado por la CA raíz:")
    print("-------------------------------------------------------")
    subordinate_ca_cert = create_subordinate_ca_certificate(subordinate_ca_private_key, root_ca_private_key, root_ca_cert.subject)
    print(subordinate_ca_cert)
    print("-------------------------------------------------------")

    print("Guardado de claves y certificados en archivos PEM (Local)")
    print("-------------------------------------------------------")
    save_private_key(root_ca_private_key, "root_ca_private_key.pem")
    save_certificate(root_ca_cert, "root_ca_certificate.pem")

    save_private_key(subordinate_ca_private_key, "subordinate_ca_private_key.pem")
    save_certificate(subordinate_ca_cert, "subordinate_ca_certificate.pem")
    print("-------------------------------------------------------")

    print("PKI setup completado! Certificados y claves guardados.")
    print("-------------------------------------------------------")

setup_pki()