import socket
import base64
import ssl
import json
from mimetypes import guess_type

HOST = 'smtp.yandex.ru'
PORT = 465  # 25
CRLF = b'\r\n'
LOGIN = '**********'
PASS = '**********'


def get_destination():
    with open('Destination.txt') as file:
        return [address[:-1] for address in file]


def send_cmd(sock, cmd):
    if isinstance(cmd, str):
        cmd = cmd.encode('utf-8')

    sock.sendall(cmd + CRLF)
    return sock.recv(1024).decode('utf-8')


def authenticate():
    coded_login = base64.b64encode(LOGIN.encode('utf-8'))
    coded_pass = base64.b64encode(PASS.encode('utf-8'))
    print(send_cmd(sock, 'AUTH LOGIN'))
    print(send_cmd(sock, coded_login))
    print(send_cmd(sock, coded_pass))


def create_message(address):
    with open('message.txt', encoding='utf-8', mode='r') as mail_file:
        message = ''
        for i in mail_file.readlines():
            if i.__contains__('.'):
                i = '.' + i
            message += i
        print(message)
    with open('header.json') as headers_file:
        headers = json.loads(headers_file.read())

    BOUNDARY = 'myBoundary1001'
    mail_lines = []
    mail_lines.append("From: " + LOGIN)
    mail_lines.append("To: " + address)
    mail_lines.append("Subject: " + headers["Subject"])
    mail_lines.append('MIME-Version: 1.0')
    mail_lines.append(
        'Content-Type: multipart/mixed; boundary="{}"'.format(BOUNDARY))  
    mail_lines.append('')

    mail_lines.append('--{}'.format(BOUNDARY))
    mail_lines.append('Content-Transfer-Encoding: 8bit')
    mail_lines.append('Content-Type: text/html; charset=utf-8')
    mail_lines.append('')

    mail_lines.append(message)

    attachments_names = get_attachments_list()
    attachments_bodies = load_attachments(attachments_names)
    for name, body in zip(attachments_names, attachments_bodies):
        mail_lines.append('--{}'.format(BOUNDARY))
        mime = guess_type(name)[0]

        mail_lines.append('Content-Disposition: attachment; filename="{}"'.format(
            name)) 
        mail_lines.append('Content-Transfer-Encoding: base64')
        mail_lines.append('Content-Type: {0}; name="{1}"'.format(mime, name))
        mail_lines.append('')
        encoded_attachment = base64.b64encode(body)
        mail_lines.append(encoded_attachment)

    mail_lines.append('--{}--'.format(BOUNDARY))
    mail_lines.append('.')

    encoded_mail_lines = []
    for line in mail_lines:
        if isinstance(line, str):
            encoded_mail_lines.append(line.encode('utf-8'))
        else:
            encoded_mail_lines.append(line)

    return b'\n'.join(encoded_mail_lines)


def get_attachments_list():
    with open('config.json', encoding='utf-8') as conf_file:
        conf_json = conf_file.read()
        configs = json.loads(conf_json)
        return configs['attachments']


def load_attachments(attachments):
    for attachment in attachments:
        with open(attachment, 'rb') as attachment_file:
            yield attachment_file.read()


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_SSLv23)
    sock.connect((HOST, PORT))
    response = sock.recv(1024)
    print(response)
    print(send_cmd(sock, 'EHLO {}'.format(LOGIN))) 
    authenticate()
    print(send_cmd(sock, 'MAIL FROM: {}'.format(
        LOGIN))) 
    mail = None
    for address in get_destination():
        mail = create_message(address)
        print(send_cmd(sock, 'RCPT TO: {}'.format(address)))  
    print(mail)
    print(send_cmd(sock,
                       'DATA'))  
    print(send_cmd(sock, mail))  
    print(send_cmd(sock, 'QUIT'))  
