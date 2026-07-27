#!/usr/bin/env python3
import os
import socket
import ssl
import sys
from pathlib import Path


def tls_context(cert_path, key_path, cipher):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(cipher + ":@SECLEVEL=0")
    context.load_cert_chain(cert_path, key_path)
    return context


def read_line(connection):
    line = bytearray()
    while not line.endswith(b"\n"):
        chunk = connection.recv(1)
        if not chunk:
            raise RuntimeError("unexpected SMTP connection close")
        line += chunk
        if len(line) > 4096:
            raise RuntimeError("SMTP line too long")
    return bytes(line)


def serve_webhook(connection, context, port, expected_host):
    connection = context.wrap_socket(connection, server_side=True)
    request = bytearray()
    while b"\r\n\r\n" not in request:
        chunk = connection.recv(4096)
        if not chunk:
            raise RuntimeError("incomplete HTTP headers")
        request += chunk
    headers, body = bytes(request).split(b"\r\n\r\n", 1)
    lines = headers.split(b"\r\n")
    content_length = 0
    header_values = {}
    for line in lines[1:]:
        name, value = line.split(b":", 1)
        header_values[name.lower()] = value.strip()
    content_length = int(header_values[b"content-length"])
    while len(body) < content_length:
        chunk = connection.recv(4096)
        if not chunk:
            raise RuntimeError("incomplete HTTP body")
        body += chunk
    assert lines[0] == b"POST /hook?case=bearssl HTTP/1.1"
    assert header_values[b"host"] == f"{expected_host}:{port}".encode()
    assert header_values[b"content-type"] == b"application/json"
    assert body[:content_length] == b'{"test":"bearssl"}'
    connection.sendall(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
    )
    connection.close()


def serve_smtp(connection, context, implicit_tls):
    tls_active = False
    saw_message = False
    if implicit_tls:
        connection = context.wrap_socket(connection, server_side=True)
        tls_active = True
    connection.sendall(b"220 test ESMTP\r\n")

    while True:
        line = read_line(connection)
        command = line.rstrip(b"\r\n")
        upper = command.upper()
        if upper.startswith(b"EHLO"):
            if tls_active:
                connection.sendall(b"250-test\r\n250 OK\r\n")
            else:
                connection.sendall(b"250-test\r\n250 STARTTLS\r\n")
        elif upper == b"STARTTLS":
            if tls_active:
                raise RuntimeError("duplicate STARTTLS")
            connection.sendall(b"220 Ready to start TLS\r\n")
            connection = context.wrap_socket(connection, server_side=True)
            tls_active = True
        elif upper.startswith(b"MAIL FROM:"):
            connection.sendall(b"250 OK\r\n")
        elif upper.startswith(b"RCPT TO:"):
            connection.sendall(b"250 OK\r\n")
        elif upper == b"DATA":
            connection.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
            message = bytearray()
            while True:
                data_line = read_line(connection)
                if data_line == b".\r\n":
                    break
                message += data_line
            assert b"bearssl smtp\r\n..second\r\n" in message
            saw_message = True
            connection.sendall(b"250 queued\r\n")
        elif upper == b"QUIT":
            connection.sendall(b"221 bye\r\n")
            break
        else:
            raise RuntimeError("unexpected SMTP command: " + repr(command))

    assert tls_active
    assert saw_message
    connection.close()


def main():
    if len(sys.argv) != 7:
        raise SystemExit(
            "usage: tls_test_server.py MODE PORT_FILE CERT KEY RESULT CIPHER"
        )
    mode, port_file, cert_path, key_path, result_file, cipher = sys.argv[1:]
    bind_host = os.environ.get("TLS_TEST_BIND", "127.0.0.1")
    expected_host = os.environ.get("TLS_TEST_HOST", bind_host)
    context = tls_context(cert_path, key_path, cipher)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((bind_host, 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    Path(port_file).write_text(str(port), encoding="ascii")
    connection, _ = listener.accept()
    listener.close()
    if mode == "webhook":
        serve_webhook(connection, context, port, expected_host)
    elif mode == "smtp-starttls":
        serve_smtp(connection, context, False)
    elif mode == "smtp-tls":
        serve_smtp(connection, context, True)
    else:
        raise RuntimeError("unknown mode: " + mode)
    Path(result_file).write_text("ok\n", encoding="ascii")


if __name__ == "__main__":
    main()
