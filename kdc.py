import socket
import threading
import random
import string
import aes

state = {
    "ka": "",
    "kb": "",
    "custom_ks": None,
    "running": True
}


def generate_session_key():
    if state["custom_ks"]:
        return state["custom_ks"]
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(16))

def handle_client(conn, addr):
    try:
        data = conn.recv(4096).decode('utf-8').strip()
        if not data:
            return
        print(f"\n[STEP 1 DITERIMA dari {addr[0]}:{addr[1]}]")
        print(f"  Payload (ASCII) : {data}")

        parts = data.split("||")
        if len(parts) != 3:
            print("  [!] Format Step 1 tidak valid.")
            return

        id_a, id_b, n1 = parts[0], parts[1], parts[2]
        ks = generate_session_key()

        plain_for_a = f"{ks}||{id_a}||{id_b}||{n1}"
        cipher_for_a_hex = aes.encrypt(plain_for_a, state["ka"])

        plain_ticket_b = f"{ks}||{id_a}"
        cipher_ticket_b_hex = aes.encrypt(plain_ticket_b, state["kb"])

        step2_payload = f"{cipher_for_a_hex}||{cipher_ticket_b_hex}"
        conn.sendall((step2_payload + "\n").encode('utf-8'))

        print(f"[STEP 2 DIKIRIM ke {addr[0]}:{addr[1]}]")
        print(f"  Session Key (Ks): {ks}")
        print(f"  Plain Blok Alice: {plain_for_a}")
        print(f"  Hex Blok Alice  : {cipher_for_a_hex}")
        print(f"  Plain Tiket Bob : {plain_ticket_b}")
        print(f"  Hex Tiket Bob   : {cipher_ticket_b_hex}")
        print(f"  Paket Step 2    : {step2_payload}")
        print("\nKDC> ", end="", flush=True)
    except Exception as e:
        print(f"\n[!] Error saat memproses request KDC: {e}")
    finally:
        conn.close()

def server_loop(host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    print(f"[*] KDC Server aktif mendengarkan di {host}:{port}")
    while state["running"]:
        try:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except Exception:
            break

def main():
    print("=== KEY DISTRIBUTION CENTER (KDC) ===")
    host = input("Masukkan IP Bind KDC (kosongkan untuk 0.0.0.0): ").strip() or "0.0.0.0"
    port_in = input("Masukkan Port KDC (default 5000): ").strip()
    port = int(port_in) if port_in else 5000

    while not state["ka"]:
        state["ka"] = input("Masukkan Master Key Alice (Ka) [ASCII]: ").strip()
    while not state["kb"]:
        state["kb"] = input("Masukkan Master Key Bob   (Kb) [ASCII]: ").strip()

    ks_in = input("Masukkan Session Key (Ks) [ASCII] (kosongkan untuk Auto-Random): ").strip()
    state["custom_ks"] = ks_in if ks_in else None

    threading.Thread(target=server_loop, args=(host, port), daemon=True).start()

    print("\nPerintah Interaktif KDC:")
    print("  /info          -> Lihat Ka, Kb, dan mode Ks saat ini")
    print("  /setka <key>   -> Ubah Master Key Alice (Ka) dalam ASCII")
    print("  /setkb <key>   -> Ubah Master Key Bob (Kb) dalam ASCII")
    print("  /setks <key>   -> Tetapkan Session Key (Ks) manual (ketik 'auto' untuk acak)")
    print("  /exit          -> Keluar dari program\n")

    while True:
        try:
            cmd = input("KDC> ").strip()
            if not cmd:
                continue
            if cmd == "/info":
                ks_mode = state["custom_ks"] if state["custom_ks"] else "AUTO-RANDOM (16 chars)"
                print(f"  Master Key Alice (Ka) : {state['ka']}")
                print(f"  Master Key Bob   (Kb) : {state['kb']}")
                print(f"  Session Key Mode (Ks) : {ks_mode}")
            elif cmd.startswith("/setka "):
                state["ka"] = cmd[7:].strip()
                print(f"  [+] Ka berhasil diubah menjadi: {state['ka']}")
            elif cmd.startswith("/setkb "):
                state["kb"] = cmd[7:].strip()
                print(f"  [+] Kb berhasil diubah menjadi: {state['kb']}")
            elif cmd.startswith("/setks "):
                val = cmd[7:].strip()
                state["custom_ks"] = None if val.lower() == "auto" else val
                print(f"  [+] Ks berhasil diatur ke: {state['custom_ks'] or 'AUTO-RANDOM'}")
            elif cmd == "/exit":
                state["running"] = False
                break
            else:
                print("Perintah tidak dikenal. Gunakan /info, /setka, /setkb, /setks, atau /exit")
        except (KeyboardInterrupt, EOFError):
            break

if __name__ == "__main__":
    main()
