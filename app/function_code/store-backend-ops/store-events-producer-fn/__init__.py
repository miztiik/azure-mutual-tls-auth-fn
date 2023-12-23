import logging
import json
import azure.functions as func

from OpenSSL import crypto
import base64


from base64 import b64decode
import os


def _try_x509_pem(cert):
    import OpenSSL.crypto
    try:
        return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    except OpenSSL.crypto.Error:
        # could not load the pem, try with headers
        try:
            pem_with_headers = '-----BEGIN CERTIFICATE-----\n' \
                               + cert + \
                               '-----END CERTIFICATE-----\n'
            return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_with_headers)
        except OpenSSL.crypto.Error:
            return None
    except UnicodeEncodeError:
        # this must be a binary encoding
        return None


def _try_x509_der(cert):
    try:
        cert = base64.b64decode(cert)
        return crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
    except crypto.Error:
        return None


def _get_public(x509):
    import OpenSSL.crypto
    pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, x509)
    if isinstance(pem, bytes):
        pem = pem.decode("utf-8")
    stripped = pem.replace('-----BEGIN CERTIFICATE-----\n', '')
    stripped = stripped.replace('-----END CERTIFICATE-----\n', '')
    return stripped


def _convert_certificate_pem_to_der(pem):
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem)
    der = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
    return der


def _convert_certificate_der_to_pem(der):
    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der)
    pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    return pem


def verify_chain_of_trust(client_cert, trusted_cert_pems):

    cert_validity_status = False

    try:
        # Create and fill a X509Sore with trusted certs
        store = crypto.X509Store()
        for trusted_cert_pem in trusted_cert_pems:
            trusted_cert = crypto.load_certificate(
                crypto.FILETYPE_PEM, trusted_cert_pem)
            store.add_cert(trusted_cert)

        # Create a X590StoreContext with the cert and trusted certs
        # and verify the the chain of trust
        store_ctx = crypto.X509StoreContext(store, client_cert)
        # Returns None if certificate can be validated
        validation_result = store_ctx.verify_certificate()
        print(validation_result)

        if validation_result is None:
            # Green text
            print("\033[92m Client certificate validation successful \033[0m")
            cert_validity_status = True
        else:
            # Red text
            print("\033[91m Client certificate validation failed \033[0m")
    except Exception as e:
        print(f"ERROR: {e}")

    return cert_validity_status


if __name__ == "__main__":
    # get certificate bytes from base64, could also be be done with file
    cert_base64 = "MIIENTCthXsgHAGkMkw=="
    cert_bytes = b64decode(cert_base64)

    # ASN1 is for der encoded certs
    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bytes)
    thumbprint = cert.digest("SHA1").decode("utf-8")
    print(thumbprint)

    trusted_cert_pems = []
    trusted_cert_pems.append(open("RootCA.pem", "rb").read())
    # trusted_cert_pems.append(open("issuing.crt", "rb").read())
    trusted = verify_chain_of_trust(cert, trusted_cert_pems)
    print(trusted)


def main(req: func.HttpRequest) -> func.HttpResponse:
    _d = {
        "miztiik_event_processed": False,
        "msg": "",
        "cert_status": "",
    }

    try:
        # _d["headers"] = dict(req.headers)
        _d["client_cert_str"] = req.headers.get("X-ARR-ClientCert")
        client_cert_bytes = base64.b64decode(_d["client_cert_str"])

        if _d.get("client_cert_str") is None:
            raise Exception("Client cert required")
        if _d.get("client_cert_str"):

            client_cert = crypto.load_certificate(
                crypto.FILETYPE_ASN1, client_cert_bytes)
            _d["cert_thumbprint"] = client_cert.digest("SHA1").decode("utf-8")

            # Loop to add client certificate attributes to _d dict
            for i in client_cert.get_subject().get_components():
                _d[i[0].decode("utf-8")] = i[1].decode("utf-8")

            logging.info(_d)

            trusted_cert_pems = []
            script_dir = os.path.dirname(os.path.realpath(__file__))
            # client_cert_path = os.path.join(script_dir, 'my_client.key.pem')
            root_cert_path = os.path.join(script_dir, 'RootCA.pem')
            trusted_cert_pems.append(open(root_cert_path, "rb").read())
            # trusted_cert_pems.append(open("issuing.crt", "rb").read())

            _d["cert_status"] = verify_chain_of_trust(
                client_cert, trusted_cert_pems)
            _d["miztiik_event_processed"] = True

    except Exception as e:
        logging.exception(f"ERROR:{str(e)}")
        _d["msg"] = f"ERROR:{str(e)}"

    return func.HttpResponse(f"{json.dumps(_d, indent=4)}", status_code=200)
