# -*- coding: utf-8 -*-
"""端口转发: 5000/8000 -> 5001

旧预览链接指向5000或8000端口(不同时期的部署端口), 服务现运行在5001。
此转发器让三个端口同时可用, 避免旧预览卡片失效。
用法: python3 port_forward.py (后台常驻)
"""
import socket
import threading

LISTEN_PORTS = [5000, 8000]
TARGET = ("127.0.0.1", 5001)


def pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            src.close()
            dst.close()
        except OSError:
            pass


def serve(port):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("0.0.0.0", port))
    ls.listen(128)
    print(f"forwarding 0.0.0.0:{port} -> {TARGET[0]}:{TARGET[1]}", flush=True)
    while True:
        client, _ = ls.accept()
        try:
            upstream = socket.socket()
            upstream.connect(TARGET)
        except OSError:
            client.close()
            continue
        threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
        threading.Thread(target=pipe, args=(upstream, client), daemon=True).start()


def main():
    for p in LISTEN_PORTS:
        threading.Thread(target=serve, args=(p,), daemon=True).start()
    # keep main thread alive
    import time
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
