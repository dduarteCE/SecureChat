import argparse
import base64
import json
import socket
import threading

from RSA import Actor


def send_packet(connection, send_lock, packet):
    encoded_packet = json.dumps(packet, ensure_ascii=False).encode("utf-8") + b"\n"
    with send_lock:
        connection.sendall(encoded_packet)


def receive_packet(reader):
    line = reader.readline()
    if not line:
        return None

    packet = json.loads(line.decode("utf-8"))
    if not isinstance(packet, dict):
        raise ValueError("Received a packet that is not a JSON object")
    return packet


def open_connection(args):
    if args.mode == "listen":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((args.host, args.port))
            listener.listen(1)
            print(f"Listening on {args.host}:{args.port}...")
            connection, address = listener.accept()
            print(f"TCP connection from {address[0]}:{address[1]}")
            return connection

    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.connect((args.host, args.port))
    print(f"Connected to {args.host}:{args.port}")
    return connection


def receive_messages(
    reader,
    peer_name,
    connection,
    send_lock,
    actor,
    secure_session,
    initiation_started,
    mode,
):
    try:
        while True:
            packet = receive_packet(reader)
            if packet is None:
                print("Connection closed by the other process.")
                return

            if packet.get("type") == "message":
                if not secure_session.is_set():
                    print("\nRejected chat message: secure session is not established.")
                else:
                    print(f"\n[{peer_name}] {packet.get('text', '')}")
            elif packet.get("type") == "key_offer":
                # If both sides type /init at once, the TCP connector wins the tie.
                # Its offer is the one both sides will use to establish the key.
                if mode == "connect" and initiation_started.is_set():
                    print("\nIgnoring crossed key offer; using this side's offer.")
                    continue
                if secure_session.is_set():
                    print("\nIgnoring key offer; the secure session is already established.")
                    continue
                try:
                    peer_public_key = Actor.load_public_key(packet["public_key"])
                    encrypted_key = actor.produce_and_encrypt_session_key(peer_public_key)
                    send_packet(
                        connection,
                        send_lock,
                        {
                            "type": "session_key",
                            "encrypted_key": base64.b64encode(encrypted_key).decode("ascii"),
                        },
                    )
                    secure_session.set()
                    print("\nSecure session established. You can now chat.")
                except (KeyError, TypeError, ValueError) as error:
                    print(f"\nCould not process public-key offer: {error}")
                    return
            elif packet.get("type") == "session_key":
                try:
                    encrypted_key = base64.b64decode(
                        packet["encrypted_key"], validate=True
                    )
                    actor.get_existing_session_key(encrypted_key)
                    secure_session.set()
                    print("\nSecure session established. You can now chat.")
                except (KeyError, TypeError, ValueError) as error:
                    print(f"\nCould not decrypt session key: {error}")
                    return
            elif packet.get("type") == "bye":
                print(f"\n{peer_name} ended the session.")
                return
            else:
                print("Received an unknown packet.")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        print(f"Receive error: {error}")


def run_chat(args):
    connection = open_connection(args)
    reader = connection.makefile("rb")
    send_lock = threading.Lock()
    actor = Actor()
    secure_session = threading.Event()
    initiation_started = threading.Event()

    try:
        send_packet(connection, send_lock, {"type": "hello", "name": args.name})
        hello = receive_packet(reader)
        if hello is None or hello.get("type") != "hello":
            raise ValueError("The other process did not send a valid hello packet")

        peer_name = hello.get("name", "Unknown participant")
        print(f"Connected with {peer_name}.")
        print("Type /init to establish the secure session, or /quit to exit.")

        receiver = threading.Thread(
            target=receive_messages,
            args=(
                reader,
                peer_name,
                connection,
                send_lock,
                actor,
                secure_session,
                initiation_started,
                args.mode,
            ),
            daemon=True,
        )
        receiver.start()

        while True:
            try:
                text = input(f"[{args.name}] ")
            except EOFError:
                text = "/quit"

            if text == "/quit":
                send_packet(connection, send_lock, {"type": "bye"})
                break
            if text == "/init":
                if secure_session.is_set():
                    print("The secure session is already established.")
                    continue
                if initiation_started.is_set():
                    print("You already started the handshake; waiting for the reply.")
                    continue
                try:
                    initiation_started.set()
                    send_packet(
                        connection,
                        send_lock,
                        {"type": "key_offer", "public_key": actor.export_public_key()},
                    )
                    print("Public key sent; waiting for the encrypted session key...")
                    secure_session.wait()
                except (OSError, ValueError) as error:
                    print(f"Handshake failed: {error}")
                    break
                continue
            if text:
                if not secure_session.is_set():
                    print("Establish the secure session with /init before chatting.")
                    continue
                send_packet(
                    connection,
                    send_lock,
                    {"type": "message", "text": text},
                )
    finally:
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        reader.close()
        connection.close()
        print("Session closed.")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Local chat with an RSA session-key handshake (workshop step 3)"
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    listener = subparsers.add_parser("listen", help="wait for the other participant")
    listener.add_argument("--host", default="127.0.0.1")
    listener.add_argument("--port", type=int, default=5000)
    listener.add_argument("--name", required=True)

    connector = subparsers.add_parser("connect", help="connect to a listening participant")
    connector.add_argument("--host", default="127.0.0.1")
    connector.add_argument("--port", type=int, default=5000)
    connector.add_argument("--name", required=True)

    return parser.parse_args()


if __name__ == "__main__":
    run_chat(parse_args())
