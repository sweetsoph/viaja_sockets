import socket
import threading
import hashlib
import base64
import json
import struct
import time
from pyngrok import ngrok
from dotenv import load_dotenv
import os

load_dotenv()

NGROK_AUTH_TOKEN = os.getenv('NGROK_WS_TOKEN')
ngrok.set_auth_token(NGROK_AUTH_TOKEN)

chat_subscriptions: dict[str, set[socket.socket]] = {}
client_meta: dict[socket.socket, dict] = {}

# Novo: status por (chat_id, user_id) -> {"status": "online"|"typing"|"offline", "since": timestamp}
user_status: dict[tuple[str, str], dict] = {}
typing_timers: dict[tuple[str, str], threading.Timer] = {}
subscriptions_lock = threading.Lock()

TYPING_TIMEOUT = 4.0

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

def publish(chat_id: str, payload: dict, sender_conn: socket.socket | None = None):
    """
    Envia para todos os subscribers do chat.
    sender_conn=None para broadcasts de sistema (presença), assim o
    próprio usuário também recebe a confirmação do seu status.
    """
    with subscriptions_lock:
        subscribers = set(chat_subscriptions.get(chat_id, set()))

    frame = encode_frame(json.dumps(payload, ensure_ascii=False))

    dead_conns = []
    for conn in subscribers:
        if conn is sender_conn:
            continue
        try:
            conn.sendall(frame)
        except (BrokenPipeError, OSError):
            dead_conns.append(conn)

    for conn in dead_conns:
        unsubscribe(conn)

def _set_status(chat_id: str, user_id: str, status: str):
    """Atualiza o dicionário de status (deve ser chamado com o lock já adquirido)."""
    key = (chat_id, user_id)
    user_status[key] = {"status": status, "since": time.time()}


def broadcast_status(chat_id: str, user_id: str, status: str, sender_conn: socket.socket | None = None):
    """
    Grava o status e avisa todos os participantes do chat.
    status: "online" | "typing" | "offline"
    """
    with subscriptions_lock:
        _set_status(chat_id, user_id, status)

    envelope = {
        "type": "presence",
        "chat_id": chat_id,
        "user_id": user_id,
        "status": status,
        "ts": time.time(),
    }
    publish(chat_id, envelope, sender_conn=sender_conn)
    print(f"[presence] user={user_id} chat={chat_id} -> {status}")


def handle_typing(chat_id: str, user_id: str, conn: socket.socket):
    """
    Chamado sempre que o cliente envia um evento {"type":"typing","chat_id":"..."}.
    - Muda status para "typing" imediatamente.
    - Reinicia o timer: se não vier novo evento em TYPING_TIMEOUT segundos,
      volta automaticamente para "online".
    """
    key = (chat_id, user_id)
    
    with subscriptions_lock:
        old_timer = typing_timers.pop(key, None)
    if old_timer:
        old_timer.cancel()

    with subscriptions_lock:
        current = user_status.get(key, {}).get("status")

    if current != "typing":
        broadcast_status(chat_id, user_id, "typing", sender_conn=conn)

    # Agenda retorno automático para "online"
    def _revert_to_online():
        with subscriptions_lock:
            typing_timers.pop(key, None)
        broadcast_status(chat_id, user_id, "online", sender_conn=conn)

    timer = threading.Timer(TYPING_TIMEOUT, _revert_to_online)
    timer.daemon = True

    with subscriptions_lock:
        typing_timers[key] = timer

    timer.start()


def broadcast_online_all_chats(user_id: str, chat_ids: list[str], conn: socket.socket):
    """Anuncia 'online' em todos os chats do usuário ao conectar."""
    for chat_id in chat_ids:
        broadcast_status(chat_id, user_id, "online", sender_conn=conn)


def broadcast_offline_all_chats(user_id: str, chat_ids: list[str]):
    """
    Anuncia 'offline' em todos os chats e cancela timers de typing pendentes.
    Chamado no finally do handle_client.
    """
    for chat_id in chat_ids:
        key = (chat_id, user_id)

        # Cancela timer de typing se existir
        with subscriptions_lock:
            timer = typing_timers.pop(key, None)
            user_status.pop(key, None)
        if timer:
            timer.cancel()

        broadcast_status(chat_id, user_id, "offline", sender_conn=None)

def handle_client(conn: socket.socket, addr):
    print(f"[+] Nova conexão: {addr}")
    user_id  = None
    chat_ids = []

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

        # 3. Anuncia "online" em todos os chats ao conectar
        broadcast_online_all_chats(user_id, chat_ids, conn)
        print(f"[handshake] user={user_id} subscribed to {chat_ids}")

        # 4. Loop de leitura de mensagens
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
                msg_type = msg.get("type", "message")

                if not chat_id:
                    continue

                if msg_type == "typing":
                    handle_typing(chat_id, user_id, conn)
                    continue

                if msg_type == "stop_typing":
                    key = (chat_id, user_id)
                    with subscriptions_lock:
                        timer = typing_timers.pop(key, None)
                    if timer:
                        timer.cancel()
                    broadcast_status(chat_id, user_id, "online", sender_conn=conn)
                    continue
                
                if msg_type == "message":
                    text = msg.get("text")
                    if not text:
                        continue

                    # Enviar uma mensagem cancela o estado "typing"
                    key = (chat_id, user_id)
                    with subscriptions_lock:
                        timer = typing_timers.pop(key, None)
                    if timer:
                        timer.cancel()
                    broadcast_status(chat_id, user_id, "online", sender_conn=conn)

                    envelope = {
                        "type": "message",
                        "chat_id": chat_id,
                        "user_id": user_id,
                        "text": text,
                        "ts": time.time(),
                    }

                    print(f"[msg] user={user_id} chat={chat_id}: {text}")
                    publish(chat_id, envelope, sender_conn=conn)

    except Exception as e:
        print(f"[erro] {addr}: {e}")
    finally:
        if user_id:
            # Anuncia "offline" em todos os chats ao desconectar
            broadcast_offline_all_chats(user_id, chat_ids)
        unsubscribe(conn)
        conn.close()
        print(f"[-] Desconectado: {addr}")

def start_server(host="0.0.0.0", port=8765):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(50)
    print(f"[server] Servidor rodando localmente em {host}:{port}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        thread.start()

public_url = ngrok.connect(8765, "tcp")
print(f"[server] Túnel ngrok aberto: {public_url}")

start_server()