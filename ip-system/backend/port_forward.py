# -*- coding: utf-8 -*-
"""端口转发: 8000 -> 5001

旧预览链接指向8000端口(系统最初部署端口), 服务现运行在5001。
此转发器让两个端口同时可用, 避免旧预览卡片失效。
用法: python3 port_forward.py (后台常驻)
"""
import socket
import threading

LISTEN_PORT = 8000
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


def main():
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("0.0.0.0", LISTEN_PORT))
    ls.listen(128)
    print(f"forwarding 0.0.0.0:{LISTEN_PORT} -> {TARGET[0]}:{TARGET[1]}", flush=True)
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


if __name__ == "__main__":
    main()
