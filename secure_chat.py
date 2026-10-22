import argparse
import base64
import json
import socket
import threading
import time

from actor import Actor, ReplayError


MAX_PACKET_BYTES = 1_048_576
HANDSHAKE_TIMEOUT_SECONDS = 30


def send_packet(connection, send_lock, packet):
    encoded_packet = json.dumps(packet, ensure_ascii=False).encode("utf-8") + b"\n"
    with send_lock:
        connection.sendall(encoded_packet)


def receive_packet(reader):
    line = reader.readline(MAX_PACKET_BYTES + 1)
    if not line:
        return None
    if len(line) > MAX_PACKET_BYTES or not line.endswith(b"\n"):
        raise ValueError("packet is too large or is missing its newline delimiter")

    packet = json.loads(line.decode("utf-8"))
    if not isinstance(packet, dict):
        raise ValueError("Received a packet that is not a JSON object")
    return packet


def wait_for_handshake(secure_session, receiver_done):
    deadline = time.monotonic() + HANDSHAKE_TIMEOUT_SECONDS
    while not secure_session.is_set():
        if receiver_done.is_set():
            print("Handshake failed: the other process disconnected.")
            return False

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            print("Handshake timed out.")
            return False
        secure_session.wait(timeout=min(0.1, remaining))
    return True


def receive_encrypted_message(packet, peer_name, local_name, actor, secure_session):
    if not secure_session.is_set():
        print("\nRejected encrypted message: secure session is not established.")
        return

    try:
        nonce = base64.b64decode(packet["nonce"], validate=True)
        ciphertext = base64.b64decode(packet["ciphertext"], validate=True)
        print(
            f"\n[{peer_name}] ciphertext received: "
            f"nonce={nonce.hex()} data={ciphertext.hex()}"
        )
        plaintext = actor.decrypt_message_aesgcm(nonce, ciphertext)
    except ReplayError as error:
        print(f"\nRejected encrypted message: {error}")
        print(f"[{local_name}] ", end="", flush=True)
        return
    except (KeyError, TypeError, ValueError) as error:
        print(f"\nRejected invalid encrypted message: {error}")
        print(f"[{local_name}] ", end="", flush=True)
        return

    if plaintext is None:
        print("\nMessage rejected: authentication failed.")
        print(f"[{local_name}] ", end="", flush=True)
        return

    try:
        message_text = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        print("\nMessage rejected: authenticated plaintext is not valid UTF-8.")
        print(f"[{local_name}] ", end="", flush=True)
        return

    print(f"\n[{peer_name}] {message_text}")
    print(f"[{local_name}] ", end="", flush=True)


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
    try:
        connection.connect((args.host, args.port))
    except OSError:
        connection.close()
        raise
    print(f"Connected to {args.host}:{args.port}")
    return connection


def receive_messages(
    reader,
    peer_name,
    local_name,
    connection,
    send_lock,
    actor,
    secure_session,
    initiation_started,
    receiver_done,
    mode,
):
    try:
        while True:
            packet = receive_packet(reader)
            if packet is None:
                print("Connection closed by the other process.")
                return

            if packet.get("type") == "message":
                print("\nRejected unencrypted chat message.")
            elif packet.get("type") == "encrypted_message":
                receive_encrypted_message(
                    packet, peer_name, local_name, actor, secure_session
                )
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
                if not initiation_started.is_set() or secure_session.is_set():
                    print("\nIgnoring unsolicited session-key packet.")
                    continue
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
    finally:
        receiver_done.set()


def run_chat(args):
    connection = open_connection(args)
    reader = connection.makefile("rb")
    send_lock = threading.Lock()
    direction_id = 0 if args.mode == "connect" else 1
    actor = Actor(direction_id)
    secure_session = threading.Event()
    initiation_started = threading.Event()
    receiver_done = threading.Event()

    try:
        send_packet(connection, send_lock, {"type": "hello", "name": args.name})
        hello = receive_packet(reader)
        if hello is None or hello.get("type") != "hello":
            raise ValueError("The other process did not send a valid hello packet")

        peer_name = hello.get("name", "Unknown participant")
        print(f"Connected with {peer_name}.")
        print(
            "Notice: exchanged public keys are not authenticated; "
            "this demo does not prevent an active man-in-the-middle attack."
        )
        print("Type /init to establish the secure session, or /quit to exit.")

        receiver = threading.Thread(
            target=receive_messages,
            args=(
                reader,
                peer_name,
                args.name,
                connection,
                send_lock,
                actor,
                secure_session,
                initiation_started,
                receiver_done,
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
                    if not wait_for_handshake(secure_session, receiver_done):
                        break
                except (OSError, ValueError) as error:
                    print(f"Handshake failed: {error}")
                    break
                continue

            corruption_test = False
            if text == "/corrupted":
                print("Usage: /corrupted <message>")
                continue
            if text.startswith("/corrupted "):
                corruption_test = True
                text = text[len("/corrupted "):]
                if not text:
                    print("Usage: /corrupted <message>")
                    continue

            if text:
                if not secure_session.is_set():
                    print("Establish the secure session with /init before chatting.")
                    continue
                print(f"[{args.name}] plaintext local: {text}")
                nonce = actor.generate_nonce()
                ciphertext = actor.encrypt_message_aesgcm(
                    nonce,
                    text.encode("utf-8"),
                )
                if corruption_test:
                    damaged_ciphertext = bytearray(ciphertext)
                    damaged_ciphertext[0] ^= 0x01
                    ciphertext = bytes(damaged_ciphertext)

                label = "corrupted ciphertext sent" if corruption_test else "ciphertext sent"
                print(
                    f"[{args.name}] {label}: "
                    f"nonce={nonce.hex()} data={ciphertext.hex()}"
                )
                send_packet(
                    connection,
                    send_lock,
                    {
                        "type": "encrypted_message",
                        "nonce": base64.b64encode(nonce).decode("ascii"),
                        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                    },
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
        description="Local chat with an RSA handshake and AES-GCM messages (workshop steps 3-5)"
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
