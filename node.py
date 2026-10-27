
import socket
import threading
import random
import aes

session = {
    "role": "",
    "my_id": "",
    "peer_id": "",
    "master_key": "",
    "session_key": "",
    "kdc_ip": "",
    "kdc_port": 5000,
    "bob_ip": "",
    "bob_port": 6000,
    "chat_sock": None,
    "authenticated": False,
    "lock": threading.Lock()
}


def compute_f(nonce_int):
    return nonce_int - 1


def close_active_socket():
    with session["lock"]:
        if session["chat_sock"]:
            try:
                session["chat_sock"].close()
            except Exception:
                pass
            session["chat_sock"] = None
        session["authenticated"] = False


def chat_receiver_loop(sock):
    while True:
        try:
            data = sock.recv(8192)
            if not data:
                print("\n[!] Koneksi dengan lawan bicara terputus.")
                close_active_socket()
                print(f"{session['my_id']}> ", end="", flush=True)
                break

            cipher_hex = data.decode('utf-8').strip()
            if not cipher_hex:
                continue

            print(f"\n[PESAN MASUK DARI {session['peer_id']}]")
            print(f"  Ciphertext (Hex) : {cipher_hex}")
            try:
                plaintext = aes.decrypt(cipher_hex, session["session_key"])
                print(f"  Plaintext (ASCII): {plaintext}")
            except Exception as e:
                print(f"  [!] Gagal Dekripsi (Key tidak cocok / data rusak): {e}")
            print(f"{session['my_id']}> ", end="", flush=True)
        except Exception:
            break


def bob_handle_incoming(conn, addr):
    close_active_socket()
    try:
        step3_hex = conn.recv(4096).decode('utf-8').strip()
        if not step3_hex:
            conn.close()
            return

        print(f"\n[STEP 3 DITERIMA dari {addr[0]}:{addr[1]}]")
        print(f"  Tiket Terenkripsi (Hex): {step3_hex}")

        try:
            ticket_plain = aes.decrypt(step3_hex, session["master_key"])
        except Exception as e:
            print(f"  [!] Gagal mendekripsi Tiket Step 3 dengan Kb ({session['master_key']}): {e}")
            conn.close()
            print(f"{session['my_id']}> ", end="", flush=True)
            return

        print(f"  Hasil Dekripsi Tiket   : {ticket_plain}")
        parts = ticket_plain.split("||")
        if len(parts) != 2:
            print("  [!] Format isi tiket tidak valid.")
            conn.close()
            return

        ks, id_a = parts[0], parts[1]
        session["session_key"] = ks
        session["peer_id"] = id_a
        print(f"  [+] Session Key (Ks) diperoleh: {ks} (dari {id_a})")

        n2 = random.randint(100000, 999999)
        step4_hex = aes.encrypt(str(n2), ks)
        conn.sendall((step4_hex + "\n").encode('utf-8'))

        print(f"[STEP 4 DIKIRIM ke {id_a}]")
        print(f"  Nonce N2 (ASCII)       : {n2}")
        print(f"  E(Ks, N2) (Hex)        : {step4_hex}")

        step5_hex = conn.recv(4096).decode('utf-8').strip()
        print(f"[STEP 5 DITERIMA dari {id_a}]")
        print(f"  E(Ks, f(N2)) (Hex)     : {step5_hex}")

        try:
            step5_plain = aes.decrypt(step5_hex, ks)
            print(f"  Hasil Dekripsi f(N2)   : {step5_plain}")
            expected = str(compute_f(n2))
            if step5_plain != expected:
                print(f"  [!] Autentikasi Gagal! Diharapkan {expected}, diterima {step5_plain}")
                conn.close()
                return
        except Exception as e:
            print(f"  [!] Gagal mendekripsi Step 5: {e}")
            conn.close()
            return

        with session["lock"]:
            session["chat_sock"] = conn
            session["authenticated"] = True

        print(f"[+] AUTENTIKASI BERHASIL! Sesi komunikasi AES dengan {id_a} aktif.")
        print(f"{session['my_id']}> ", end="", flush=True)
        chat_receiver_loop(conn)

    except Exception as e:
        print(f"\n[!] Error pada handshake Bob: {e}")
        conn.close()


def bob_server_listener(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    print(f"[*] Bob mendengarkan koneksi Alice di port {port}...")
    while True:
        try:
            conn, addr = server.accept()
            threading.Thread(target=bob_handle_incoming, args=(conn, addr), daemon=True).start()
        except Exception:
            break


def alice_run_handshake():
    close_active_socket()
    n1 = str(random.randint(100000, 999999))
    step1_payload = f"{session['my_id']}||{session['peer_id']}||{n1}"

    print(f"\n[STEP 1 DIKIRIM ke KDC ({session['kdc_ip']}:{session['kdc_port']})]")
    print(f"  Payload (ASCII) : {step1_payload}")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as kdc_sock:
            kdc_sock.settimeout(10)
            kdc_sock.connect((session["kdc_ip"], session["kdc_port"]))
            kdc_sock.sendall((step1_payload + "\n").encode('utf-8'))
            step2_data = kdc_sock.recv(8192).decode('utf-8').strip()
    except Exception as e:
        print(f"  [!] Gagal menghubungi KDC: {e}")
        return

    print(f"[STEP 2 DITERIMA dari KDC]")
    print(f"  Payload (Hex)   : {step2_data}")

    parts = step2_data.split("||")
    if len(parts) != 2:
        print("  [!] Format paket Step 2 dari KDC tidak valid.")
        return

    cipher_alice_hex, ticket_bob_hex = parts[0], parts[1]

    try:
        plain_alice = aes.decrypt(cipher_alice_hex, session["master_key"])
    except Exception as e:
        print(f"  [!] Gagal mendekripsi paket KDC dengan Ka ({session['master_key']}): {e}")
        return

    print(f"  Dekripsi Blok A : {plain_alice}")
    a_parts = plain_alice.split("||")
    if len(a_parts) != 4:
        print("  [!] Isi blok Alice tidak sesuai format.")
        return

    ks, recv_ida, recv_idb, recv_n1 = a_parts
    if recv_n1 != n1 or recv_idb != session["peer_id"]:
        print(f"  [!] Verifikasi Nonce N1 / ID_B gagal! (Diterima N1={recv_n1}, diharapkan={n1})")
        return

    session["session_key"] = ks
    print(f"  [+] Verifikasi N1 cocok! Session Key (Ks) = {ks}")

    try:
        bob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bob_sock.connect((session["bob_ip"], session["bob_port"]))

        print(f"[STEP 3 DIKIRIM ke Bob ({session['bob_ip']}:{session['bob_port']})]")
        print(f"  Tiket Bob (Hex) : {ticket_bob_hex}")
        bob_sock.sendall((ticket_bob_hex + "\n").encode('utf-8'))

        step4_hex = bob_sock.recv(4096).decode('utf-8').strip()
        if not step4_hex:
            print("  [!] Bob menutup koneksi (kemungkinan Kb Bob tidak cocok dengan KDC).")
            bob_sock.close()
            return

        print(f"[STEP 4 DITERIMA dari Bob]")
        print(f"  E(Ks, N2) (Hex) : {step4_hex}")

        n2_str = aes.decrypt(step4_hex, ks)
        print(f"  Dekripsi N2     : {n2_str}")

        f_n2_str = str(compute_f(int(n2_str)))
        step5_hex = aes.encrypt(f_n2_str, ks)

        print(f"[STEP 5 DIKIRIM ke Bob]")
        print(f"  f(N2) (ASCII)   : {f_n2_str}")
        print(f"  E(Ks,f(N2))(Hex): {step5_hex}")
        bob_sock.sendall((step5_hex + "\n").encode('utf-8'))

        with session["lock"]:
            session["chat_sock"] = bob_sock
            session["authenticated"] = True

        print(f"[+] AUTENTIKASI 5 LANGKAH SELESAI! Sesi komunikasi dua arah dengan Bob aktif.\n")
        threading.Thread(target=chat_receiver_loop, args=(bob_sock,), daemon=True).start()

    except Exception as e:
        print(f"  [!] Gagal menyelesaikan autentikasi dengan Bob: {e}")


def print_help():
    print("\n Daftar Perintah Interaktif:")
    print("  <ketik pesan langsung> -> Kirim pesan terenkripsi AES ke lawan bicara")
    print("  /info                  -> Tampilkan status ID, Master Key, dan Session Key (Ks)")
    print("  /setmaster <key>       -> Ubah Master Key (Ka/Kb) secara interaktif")
    print("  /setks <key>           -> Ubah Session Key (Ks) secara manual untuk uji test-case")
    if session["role"] == "ALICE":
        print("  /handshake             -> Jalankan ulang skenario Langkah 1 s.d. 5 (Re-Key)")
    print("  /enc <teks_ascii>      -> Uji enkripsi mandiri dengan Ks saat ini")
    print("  /dec <teks_hex>        -> Uji dekripsi mandiri dengan Ks saat ini")
    print("  /exit                  -> Keluar dari program\n")


def main():
    print("=== NODE ENTITAS (ALICE / BOB) ===")
    print("Pilih Role:")
    print("  [1] Alice (Initiator A)")
    print("  [2] Bob   (Responder B)")
    choice = ""
    while choice not in ("1", "2"):
        choice = input("Pilihan (1/2): ").strip()

    if choice == "1":
        session["role"] = "ALICE"
        session["my_id"] = input("Masukkan ID Alice (default ALICE): ").strip() or "ALICE"
        session["peer_id"] = input("Masukkan ID Tujuan (default BOB): ").strip() or "BOB"
        while not session["master_key"]:
            session["master_key"] = input("Masukkan Master Key Alice (Ka) [ASCII]: ").strip()
        session["kdc_ip"] = input("Masukkan IP KDC: ").strip() or "127.0.0.1"
        kdc_p = input("Masukkan Port KDC (default 5000): ").strip()
        session["kdc_port"] = int(kdc_p) if kdc_p else 5000
        session["bob_ip"] = input("Masukkan IP Bob: ").strip() or "127.0.0.1"
        bob_p = input("Masukkan Port Bob (default 6000): ").strip()
        session["bob_port"] = int(bob_p) if bob_p else 6000

        print_help()
        alice_run_handshake()
    else:
        session["role"] = "BOB"
        session["my_id"] = input("Masukkan ID Bob (default BOB): ").strip() or "BOB"
        session["peer_id"] = "ALICE"
        while not session["master_key"]:
            session["master_key"] = input("Masukkan Master Key Bob (Kb) [ASCII]: ").strip()
        bob_p = input("Masukkan Port Listen Bob (default 6000): ").strip()
        session["bob_port"] = int(bob_p) if bob_p else 6000

        print_help()
        threading.Thread(target=bob_server_listener, args=(session["bob_port"],), daemon=True).start()

    while True:
        try:
            user_in = input(f"{session['my_id']}> ").strip()
            if not user_in:
                continue

            if user_in == "/info":
                key_label = "Ka" if session["role"] == "ALICE" else "Kb"
                print(f"  Role               : {session['role']} (ID: {session['my_id']})")
                print(f"  Master Key ({key_label})    : {session['master_key']}")
                print(f"  Session Key (Ks)   : {session['session_key'] or '[Belum ada]'}")
                print(f"  Status Autentikasi : {'Aktif (Terhubung)' if session['authenticated'] else 'Belum Terhubung'}")

            elif user_in.startswith("/setmaster "):
                session["master_key"] = user_in[11:].strip()
                print(f"  [+] Master Key berhasil diubah menjadi: {session['master_key']}")

            elif user_in.startswith("/setks "):
                session["session_key"] = user_in[7:].strip()
                print(f"  [+] Session Key (Ks) berhasil diubah menjadi: {session['session_key']}")

            elif user_in == "/handshake" and session["role"] == "ALICE":
                alice_run_handshake()

            elif user_in.startswith("/enc "):
                if not session["session_key"]:
                    print("  [!] Session Key (Ks) masih kosong. Set dengan /setks atau lakukan /handshake.")
                    continue
                pt = user_in[5:]
                ct = aes.encrypt(pt, session["session_key"])
                print(f"  Plaintext (ASCII) : {pt}")
                print(f"  Key (ASCII)       : {session['session_key']}")
                print(f"  Ciphertext (Hex)  : {ct}")

            elif user_in.startswith("/dec "):
                if not session["session_key"]:
                    print("  [!] Session Key (Ks) masih kosong.")
                    continue
                ct = user_in[5:].strip()
                try:
                    pt = aes.decrypt(ct, session["session_key"])
                    print(f"  Ciphertext (Hex)  : {ct}")
                    print(f"  Key (ASCII)       : {session['session_key']}")
                    print(f"  Plaintext (ASCII) : {pt}")
                except Exception as e:
                    print(f"  [!] Gagal mendekripsi: {e}")

            elif user_in == "/help":
                print_help()

            elif user_in == "/exit":
                close_active_socket()
                break

            else:
                if not session["authenticated"] or not session["chat_sock"]:
                    print("  [!] Sesi belum terhubung. Jika Anda Alice, ketik /handshake.")
                    continue
                cipher_hex = aes.encrypt(user_in, session["session_key"])
                session["chat_sock"].sendall((cipher_hex + "\n").encode('utf-8'))
                print(f"  [TERKIRIM ke {session['peer_id']}]")
                print(f"  Plaintext (ASCII): {user_in}")
                print(f"  Ciphertext (Hex) : {cipher_hex}")

        except (KeyboardInterrupt, EOFError):
            close_active_socket()
            break


if __name__ == "__main__":
    main()
