import socket
import threading
import hashlib
import base64
import json
import struct

chat_subscriptions: dict[str, set[socket.socket]] = {}
client_meta: dict[socket.socket, dict] = {}
subscriptions_lock = threading.Lock()

def parse_handshake(data: bytes) -> dict:
    """
    Extrai headers HTTP do handshake e os query params da URL.
    O cliente conecta em: ws://host/ws?user_id=42&chats=room1,room2,room3
    """
    lines = data.decode("utf-8").split("\r\n")
    headers = {}
    request_line = lines[0]

    for line in lines[1:]:
        if ": " in line:
            key, val = line.split(": ", 1)
            headers[key.lower()] = val

    # Extrai query string da URL
    path = request_line.split(" ")[1]  # "/ws?user_id=42&chats=room1,room2"
    query_params = {}
    if "?" in path:
        qs = path.split("?", 1)[1]
        for param in qs.split("&"):
            if "=" in param:
                k, v = param.split("=", 1)
                query_params[k] = v

    return {"headers": headers, "params": query_params}

def perform_handshake(conn: socket.socket, data: bytes) -> dict | None:
    """
    Completa o handshake WebSocket (RFC 6455) e retorna os metadados do cliente.
    Retorna None se o handshake falhar.
    """
    parsed = parse_handshake(data)
    headers = parsed["headers"]
    params = parsed["params"]

    if "sec-websocket-key" not in headers:
        conn.send(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        return None

    user_id = params.get("user_id")
    if not user_id:
        conn.send(b"HTTP/1.1 400 Bad Request\r\n\r\nMissing user_id\n")
        return None

    chat_ids_raw = params.get("chats", "")
    chat_ids = [c.strip() for c in chat_ids_raw.split(",") if c.strip()]

    magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    key = headers["sec-websocket-key"] + magic
    accept = base64.b64encode(hashlib.sha1(key.encode()).digest()).decode()

    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n"
        "\r\n"
    )
    conn.send(response.encode())

    return {"user_id": user_id, "chat_ids": chat_ids}

def decode_frame(data: bytes) -> dict | None:
    """Decodifica um frame WebSocket recebido do cliente. Retorna None se o frame for inválido."""
    if len(data) < 2:
        return None

    fin = (data[0] >> 7) & 1
    opcode = data[0] & 0x0F
    masked = (data[1] >> 7) & 1
    payload_len = data[1] & 0x7F

    offset = 2
    if payload_len == 126:
        payload_len = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2
    elif payload_len == 127:
        payload_len = struct.unpack(">Q", data[offset:offset+8])[0]
        offset += 8

    mask_key = b""
    if masked:
        mask_key = data[offset:offset+4]
        offset += 4

    payload = bytearray(data[offset:offset+payload_len])
    if masked:
        payload = bytearray(b ^ mask_key[i % 4] for i, b in enumerate(payload))

    return {"opcode": opcode, "payload": bytes(payload), "fin": fin}


def encode_frame(message: str | bytes) -> bytes:
    """Encoda um frame WebSocket texto."""
    if isinstance(message, str):
        message = message.encode("utf-8")

    length = len(message)
    if length <= 125:
        header = bytes([0x81, length])
    elif length <= 65535:
        header = bytes([0x81, 126]) + struct.pack(">H", length)
    else:
        header = bytes([0x81, 127]) + struct.pack(">Q", length)

    return header + message

def subscribe(conn: socket.socket, chat_ids: list[str]):
    """
    Registra a conexão nos chats desejados.
    Usa lock para garantir exclusão mútua (thread-safety).
    """
    with subscriptions_lock:
        for chat_id in chat_ids:
            if chat_id not in chat_subscriptions:
                chat_subscriptions[chat_id] = set()
            chat_subscriptions[chat_id].add(conn)
    print(f"[subscriptions] {conn.getpeername()} -> chats: {chat_ids}")


def unsubscribe(conn: socket.socket):
    """Remove a conexão de todos os chats ao desconectar."""
    with subscriptions_lock:
        for chat_id in list(chat_subscriptions.keys()):
            chat_subscriptions[chat_id].discard(conn)
            if not chat_subscriptions[chat_id]:
                del chat_subscriptions[chat_id]
        client_meta.pop(conn, None)
    print(f"[subscriptions] conexão removida: {conn.getpeername()}")

def publish(chat_id: str, payload: dict, sender_conn: socket.socket):
    """
    Envia a mensagem para todos os subscribers do chat,
    exceto o remetente (comportamento típico de chat).
    """
    with subscriptions_lock:
        subscribers = set(chat_subscriptions.get(chat_id, set()))

    frame = encode_frame(json.dumps(payload, ensure_ascii=False))

    dead_conns = []
    for conn in subscribers:
        if conn is sender_conn:
            continue  # não envia de volta ao remetente
        try:
            conn.sendall(frame)
        except (BrokenPipeError, OSError):
            dead_conns.append(conn)

    # Limpeza lazy de conexões mortas
    for conn in dead_conns:
        unsubscribe(conn)

def handle_client(conn: socket.socket, addr):
    print(f"[+] Nova conexão: {addr}")
    try:
        # 1. Receber handshake HTTP
        raw = conn.recv(4096)
        if not raw:
            return

        meta = perform_handshake(conn, raw)
        if not meta:
            return

        user_id = meta["user_id"]
        chat_ids = meta["chat_ids"]

        # 2. Registrar subscrições
        with subscriptions_lock:
            client_meta[conn] = meta
        subscribe(conn, chat_ids)

        print(f"[handshake] user={user_id} subscribed to {chat_ids}")

        # 3. Loop de leitura de mensagens
        while True:
            data = conn.recv(4096)
            if not data:
                break

            frame = decode_frame(data)
            if frame is None:
                continue

            # Opcode 8 = close frame
            if frame["opcode"] == 8:
                break

            # Opcode 1 = text frame
            if frame["opcode"] == 1:
                try:
                    msg = json.loads(frame["payload"].decode("utf-8"))
                except json.JSONDecodeError:
                    continue

                chat_id = msg.get("chat_id")
                text = msg.get("text")

                if not chat_id or not text:
                    continue

                envelope = {
                    "type": "message",
                    "chat_id": chat_id,
                    "user_id": user_id,
                    "text": text,
                }

                print(f"[msg] user={user_id} chat={chat_id}: {text}")
                publish(chat_id, envelope, sender_conn=conn)

    except Exception as e:
        print(f"[erro] {addr}: {e}")
    finally:
        unsubscribe(conn)
        conn.close()
        print(f"[-] Desconectado: {addr}")

def start_server(host="0.0.0.0", port=8765):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(50)
    print(f"[server] Escutando em {host}:{port}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        thread.start()


if __name__ == "__main__":
    start_server()