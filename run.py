import asyncio
import hashlib
import base64
import json
import struct

# Estruturas de dados (Não precisam mais de Lock no asyncio)
chat_subscriptions: dict[str, set[asyncio.StreamWriter]] = {}
client_meta: dict[asyncio.StreamWriter, dict] = {}

def parse_handshake(data: bytes) -> dict:
    lines = data.decode("utf-8").split("\r\n")
    headers = {}
    request_line = lines[0]

    for line in lines[1:]:
        if ": " in line:
            key, val = line.split(": ", 1)
            headers[key.lower()] = val

    path = request_line.split(" ")[1]
    query_params = {}
    if "?" in path:
        qs = path.split("?", 1)[1]
        for param in qs.split("&"):
            if "=" in param:
                k, v = param.split("=", 1)
                query_params[k] = v

    return {"headers": headers, "params": query_params}

async def perform_handshake(writer: asyncio.StreamWriter, data: bytes) -> dict | None:
    parsed = parse_handshake(data)
    headers = parsed["headers"]
    params = parsed["params"]

    if "sec-websocket-key" not in headers:
        writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        await writer.drain()
        return None

    user_id = params.get("user_id")
    chat_ids = [c.strip() for c in params.get("chats", "").split(",") if c.strip()]

    magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    key = headers["sec-websocket-key"] + magic
    accept = base64.b64encode(hashlib.sha1(key.encode()).digest()).decode()

    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
    )
    writer.write(response.encode())
    await writer.drain()

    return {"user_id": user_id, "chat_ids": chat_ids}

def decode_frame(data: bytes) -> dict | None:
    if len(data) < 2: return None
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

    if masked:
        mask_key = data[offset:offset+4]
        offset += 4
        payload = bytearray(data[offset:offset+payload_len])
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    else:
        payload = data[offset:offset+payload_len]

    return {"opcode": opcode, "payload": payload, "fin": fin}

def encode_frame(message: str | bytes) -> bytes:
    if isinstance(message, str): message = message.encode("utf-8")
    length = len(message)
    if length <= 125:
        header = bytes([0x81, length])
    elif length <= 65535:
        header = bytes([0x81, 126]) + struct.pack(">H", length)
    else:
        header = bytes([0x81, 127]) + struct.pack(">Q", length)
    return header + message

async def subscribe(writer: asyncio.StreamWriter, chat_ids: list[str]):
    for chat_id in chat_ids:
        if chat_id not in chat_subscriptions:
            chat_subscriptions[chat_id] = set()
        chat_subscriptions[chat_id].add(writer)

async def unsubscribe(writer: asyncio.StreamWriter):
    for chat_id in list(chat_subscriptions.keys()):
        chat_subscriptions[chat_id].discard(writer)
        if not chat_subscriptions[chat_id]:
            del chat_subscriptions[chat_id]
    client_meta.pop(writer, None)

async def publish(chat_id: str, payload: dict, sender_writer: asyncio.StreamWriter):
    subscribers = chat_subscriptions.get(chat_id, set())
    frame = encode_frame(json.dumps(payload, ensure_ascii=False))
    
    # Criamos uma lista de tarefas de escrita para enviar em paralelo
    tasks = []
    for writer in subscribers:
        if writer is sender_writer:
            continue
        try:
            writer.write(frame)
            tasks.append(writer.drain()) # Aguarda o buffer de rede
        except Exception:
            continue
    
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info('peername')
    print(f"[+] Nova conexão: {addr}")
    
    try:
        # 1. Handshake
        raw = await reader.read(4096)
        if not raw: return

        meta = await perform_handshake(writer, raw)
        if not meta: return

        client_meta[writer] = meta
        await subscribe(writer, meta["chat_ids"])

        # 2. Loop de Mensagens
        while True:
            data = await reader.read(4096)
            if not data: break

            frame = decode_frame(data)
            if not frame or frame["opcode"] == 8: break # Close

            if frame["opcode"] == 1:
                try:
                    msg = json.loads(frame["payload"].decode("utf-8"))
                    chat_id = msg.get("chat_id")
                    text = msg.get("text")

                    if chat_id and text:
                        envelope = {
                            "type": "message",
                            "chat_id": chat_id,
                            "user_id": meta["user_id"],
                            "text": text,
                        }
                        await publish(chat_id, envelope, sender_writer=writer)
                except Exception as e:
                    print(f"[msg erro] {e}")

    except Exception as e:
        print(f"[erro] {addr}: {e}")
    finally:
        await unsubscribe(writer)
        writer.close()
        await writer.wait_closed()
        print(f"[-] Desconectado: {addr}")

async def main():
    server = await asyncio.start_server(handle_client, '0.0.0.0', 8765)
    addr = server.sockets[0].getsockname()
    print(f"[server] Escutando em {addr}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass