__author__ = 'https://github.com/password123456/'
__version__ = '1.0.0-230102'

import os
import ssl
import socket
import OpenSSL
import requests
import json
import time
from datetime import datetime, timezone

_home_path_ = f'{os.getcwd()}'
_scan_list = f'{_home_path_}/list.db'
_result_logs = f'{_home_path_}/output/{datetime.today().strftime("%Y%m%d")}_scan.log'
_notify_d_day = 60


class Bcolors:
    Black = '\033[30m'
    Red = '\033[31m'
    Green = '\033[32m'
    Yellow = '\033[33m'
    Blue = '\033[34m'
    Magenta = '\033[35m'
    Cyan = '\033[36m'
    White = '\033[37m'
    Endc = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def scan_logs(_contents):
    output_dir = f'{_home_path_}/output'
    mode = 'w'
    if os.path.exists(output_dir):
        if os.path.exists(_result_logs):
            mode = 'a'
    else:
        mode = 'w'
        os.makedirs(output_dir)
    with open(_result_logs, mode) as f:
        f.write(f'{_contents}')


def check_certificate(_domain, _port, _user):
    try:
        context = ssl.SSLContext()
        conn = socket.create_connection((_domain, _port))
        sock = context.wrap_socket(conn, server_hostname=_domain)
        sock.settimeout(10)

        certificate = sock.getpeercert(True)
        pem_data = ssl.DER_cert_to_PEM_cert(certificate)
        pem_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_data.encode('ascii'))

        x509_issuer = pem_cert.get_issuer()
        x509_subject = pem_cert.get_subject()
        issuer_str = ''.join(f'/{name.decode()}={value.decode()}' for name, value in x509_issuer.get_components())
        subject_str = ''.join(f'/{name.decode()}={value.decode()}' for name, value in x509_subject.get_components())
        signature = f'{pem_cert.get_signature_algorithm().decode("utf-8")}'
        serial = f'{pem_cert.get_serial_number()}'
        subject_hash = f'{pem_cert.get_subject().hash():x}'
        issuer_hash = f'{pem_cert.get_issuer().hash():x}'

        not_before_obj = datetime.strptime(pem_cert.get_notBefore().decode('utf-8'), '%Y%m%d%H%M%S%z')
        not_before = datetime.strftime(not_before_obj, '%Y-%m-%d %H:%M:%S')
        not_after_obj = datetime.strptime(pem_cert.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%S%z').replace(tzinfo=timezone.utc)
        local_timezone = datetime.now().astimezone().tzinfo
        not_after_local = not_after_obj.astimezone(local_timezone)

        expiration_remaining_days = (not_after_obj - datetime.now(timezone.utc)).days

        scan_result = 'pass'
        contents = f'"{datetime.today().strftime("%Y-%m-%d %H:%M:%S")}",{scan_result},{_domain},{_user},' \
                   f'{expiration_remaining_days},"{not_before}","{not_after_local}","{issuer_str}","{subject_str}",' \
                   f'{signature},{serial},{subject_hash},{issuer_hash}\n'

    except Exception as e:
        print(f'{Bcolors.Yellow}- SSL socket Error::{_domain} {e} {Bcolors.Endc}')

        scan_result = 'fail'
        expiration_remaining_days = 7749
        not_after_local = 'None'
        contents = f'"{datetime.today().strftime("%Y-%m-%d %H:%M:%S")}",{scan_result},{_domain},{_user}' \
                   f',{e}\n'
    return scan_result, expiration_remaining_days, not_after_local, contents


def load_domain_list():
    count_list_of_domain = 0
    count_scan_failed = 0
    count_expiration = 0

    result_scan_failed = ''
    result_expiration = ''

    if os.path.exists(_scan_list):
        with open(_scan_list, 'r') as f:
            for line in f:
                if not line.startswith('#'):
                    if not len(line.strip()) == 0:
                        _domain = line.split(',')[0]
                        _port = line.split(',')[1]
                        _notify_user = line.split(',')[2].strip()
                        count_list_of_domain = count_list_of_domain + 1

                        _scan_result, _expiration_days, _not_after_local, _scan_info = \
                            check_certificate(_domain, _port, _notify_user)

                        logs = f'{count_list_of_domain},{_scan_info}'
                        scan_logs(logs)

                        if _scan_result == 'fail':
                            count_scan_failed = count_scan_failed + 1
                            _contents = f'{count_scan_failed},{_domain},{_notify_user}\n'
                            result_scan_failed += _contents

                        if _scan_result == 'pass':
                            if _expiration_days <= _notify_d_day:
                                count_expiration = count_expiration + 1
                                if _expiration_days < 0:
                                    _expiration_days = f'[already expired] {_expiration_days}'
                                else:
                                    _expiration_days = f'[expire within] {_expiration_days}'
                                _contents = f'{count_expiration},{_expiration_days} days,' \
                                            f'"{_not_after_local}",{_domain},{_notify_user}\n'
                                result_expiration += _contents

    if result_expiration:
        print(f'# Certificate will expire within 90 days.\n{result_expiration}')
        #send_to_telegram SNS webhook

    if result_scan_failed:
        print(f'# Certificate Scan Failed.\n{result_scan_failed}')
        #send_to_telegram SNS webhook

if __name__ == '__main__':
    load_domain_list()

