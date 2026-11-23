import os
import platform
import secrets
import subprocess

# STEP 1: LOAD INPUT IMAGE (load_rgb)
def load_rgb(path, tk_root=None):
    from PIL import Image
    im = Image.open(path).convert("RGB")
    w, h, px = im.width, im.height, list(im.getdata())
    return [px[y * w:(y + 1) * w] for y in range(h)]

def bin_to_gray(b): return [[0 if v else 255 for v in row] for row in b]

def save_bin_png(b, path):
    from PIL import Image
    im = Image.new("L", (len(b[0]), len(b)))
    im.putdata([0 if v else 255 for row in b for v in row])
    im.save(path)

def fit_grid(grid, max_w, max_h, gray=False, area_avg=False):
    sh, sw = len(grid), len(grid[0])
    scale = min(max_w / sw, max_h / sh)
    if 0.85 <= scale <= 1.15:
        return grid
    nw, nh = max(2, int(round(sw * scale))), max(2, int(round(sh * scale)))
    if area_avg and scale < 1.0 and gray:
        out = []
        for y in range(nh):
            y0, y1 = int(y * sh / nh), max(int(y * sh / nh) + 1, int((y + 1) * sh / nh))
            row = []
            for x in range(nw):
                x0, x1 = int(x * sw / nw), max(int(x * sw / nw) + 1, int((x + 1) * sw / nw))
                s = sum(grid[yy][xx] for yy in range(y0, min(y1, sh)) for xx in range(x0, min(x1, sw)))
                c = (min(y1, sh) - y0) * (min(x1, sw) - x0)
                row.append(s // c)
            out.append(row)
        return out
    return [[grid[int(y * sh / nh)][int(x * sw / nw)] for x in range(nw)] for y in range(nh)]

def to_ppm(grid, gray=False):
    h, w = len(grid), len(grid[0])
    body = bytearray(w * h * 3)
    i = 0
    for row in grid:
        for px in row:
            r, g, b = (px, px, px) if gray else px
            body[i], body[i + 1], body[i + 2] = r, g, b
            i += 3
    return f"P6\n{w} {h}\n255\n".encode() + bytes(body)



S0_BASIS = ((1, 1, 0, 0), (1, 1, 0, 0))  # White (0) -> H(r1 OR r2) = 2/4 (50% gray)
S1_BASIS = ((1, 1, 0, 0), (0, 0, 1, 1))  # Black (1) -> H(r1 OR r2) = 4/4 (100% black)

# STEP 2: BINARIZATION
def to_binary(rgb, thr=128):
    return [[1 if (r + g + b) // 3 < thr else 0 for (r, g, b) in row] for row in rgb]

# STEP 3: NAOR-SHAMIR (2, 2) SPLIT
def csprng_perm(m=4):
    cols = list(range(m))
    for i in range(m - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        cols[i], cols[j] = cols[j], cols[i]
    return cols

def ns_split(secret):
    h, w = len(secret), len(secret[0])
    s1 = [[0] * (2 * w) for _ in range(2 * h)]
    s2 = [[0] * (2 * w) for _ in range(2 * h)]
    for y in range(h):
        for x in range(w):
            basis = S0_BASIS if secret[y][x] == 0 else S1_BASIS
            pi = csprng_perm(4)
            r1 = tuple(basis[0][c] for c in pi)
            r2 = tuple(basis[1][c] for c in pi)
            s1[2*y][2*x], s1[2*y][2*x+1], s1[2*y+1][2*x], s1[2*y+1][2*x+1] = r1
            s2[2*y][2*x], s2[2*y][2*x+1], s2[2*y+1][2*x], s2[2*y+1][2*x+1] = r2
    return s1, s2

# STEP 4: DIGITAL STACKING — BOOLEAN OR
def ns_stack(s1, s2):
    return [[a | b for a, b in zip(r1, r2)] for r1, r2 in zip(s1, s2)]

# STEP 5: Demonstration
def _norm_bin(b, size=64):
    sh, sw = len(b), len(b[0])
    return [[b[int(y * sh / size)][int(x * sw / size)] for x in range(size)] for y in range(size)]

def verify_vault(secret_bin, cand_rgb, thr=0.90):
    cb = to_binary(cand_rgb)
    ch, cw = len(cb), len(cb[0])
    if ch >= 4 and cw >= 4 and ch % 2 == 0 and cw % 2 == 0:
        bh, bw = ch // 2, cw // 2
        cnt = [0, 0, 0, 0, 0]
        dec = []
        for y in range(bh):
            row = []
            for x in range(bw):
                hw = cb[2*y][2*x] + cb[2*y][2*x+1] + cb[2*y+1][2*x] + cb[2*y+1][2*x+1]
                cnt[hw] += 1
                row.append(1 if hw == 4 else 0)
            dec.append(row)
        tb = bh * bw
        if cnt[2] / tb >= 0.95 and cnt[4] == 0:
            return False, "SINGLE_SHARE_NOISE", 0.0, "SINGLE_SHARE_NOISE: VÂN TAY KHÔNG TRÙNG KHỚP -> TRUY CẬP THẤT BẠI"
        if (cnt[2] + cnt[4]) / tb >= 0.95 and cnt[4] > 0 and cnt[0] / tb < 0.02:
            kind, cand_p = "STACKED_RECOVERED", dec
        else:
            kind, cand_p = "ORIGINAL_FINGERPRINT", cb
    else:
        kind, cand_p = "ORIGINAL_FINGERPRINT", cb

    if len(cand_p) == len(secret_bin) and len(cand_p[0]) == len(secret_bin[0]):
        pa, pb = secret_bin, cand_p
    else:
        pa, pb = _norm_bin(secret_bin, 64), _norm_bin(cand_p, 64)

    ratio = sum(a == b for ra, rb in zip(pa, pb) for a, b in zip(ra, rb)) / (len(pa) * len(pa[0]))
    ok = ratio >= thr
    return ok, kind, ratio, f"{kind}: {'VÂN TAY TRÙNG KHỚP -> TRUY CẬP THÀNH CÔNG' if ok else 'VÂN TAY KHÔNG TRÙNG KHỚP -> TRUY CẬP THẤT BẠI'}"

def open_target(path):
    sys_name = platform.system()
    if sys_name == "Windows": os.startfile(path)
    elif sys_name == "Darwin": subprocess.Popen(["open", path])
    else: subprocess.Popen(["xdg-open", path])

# GUI
STEPS = ["1. Input", "2. Binarization", "3. Split", "4. Stack (OR)", "5. Demonstration"]

def launch_gui():
    import tkinter as tk
    from tkinter import filedialog

    root = tk.Tk()
    root.title("demo")
    root.geometry("1200x760")

    st = {
        "idx": 0, "rgb": None, "P": None, "s1": None, "s2": None, "stk": None, "refs": [],
        "target_path": "", "pwd_path": "", "pwd_P": None, "unlock_path": "",
    }

    ribbon = tk.Frame(root, bg="#1B365D", pady=8)
    ribbon.pack(fill=tk.X)
    pills = [tk.Label(ribbon, text=name, font=("Segoe UI", 9, "bold"), bg="#CBD5E1", fg="#1E293B", padx=14, pady=4) for name in STEPS]
    for p in pills: p.pack(side=tk.LEFT, padx=5)

    bar = tk.Frame(root, pady=6, padx=10); bar.pack(fill=tk.X)
    def run_all(rgb, src_label="(Generated Sample)"):
        st["rgb"] = rgb
        st["P"] = to_binary(rgb)
        st["s1"], st["s2"] = ns_split(st["P"])
        st["stk"] = ns_stack(st["s1"], st["s2"])
        st["pwd_P"] = st["P"]
        st["pwd_path"] = src_label
        st["idx"] = 0
        render()

    tk.Button(bar, text="Load Image", bg="#2563EB", fg="white", command=lambda: (p := filedialog.askopenfilename()) and run_all(load_rgb(p, root), p)).pack(side=tk.LEFT, padx=4)
    btn_prev = tk.Button(bar, text="◀ Prev", command=lambda: (st.__setitem__("idx", max(0, st["idx"] - 1)), render()), state=tk.DISABLED)
    btn_next = tk.Button(bar, text="Next ▶", bg="#16A34A", fg="white", command=lambda: (st.__setitem__("idx", min(4, st["idx"] + 1)), render()), state=tk.DISABLED)
    btn_prev.pack(side=tk.LEFT, padx=8); btn_next.pack(side=tk.LEFT, padx=4)

    # Full-width main display area
    main = tk.Frame(root, padx=12, pady=4); main.pack(fill=tk.BOTH, expand=True)
    lbl_stat = tk.Label(main, text="", font=("Consolas", 10, "bold"), pady=6, padx=8, anchor="w")
    stage = tk.Frame(main, bg="#E2E8F0", bd=1, relief=tk.SUNKEN); stage.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

    def photo_fit(grid, max_w, max_h, gray=False, area_avg=False):
        scaled = fit_grid(grid, max_w, max_h, gray=gray, area_avg=area_avg)
        im = tk.PhotoImage(data=to_ppm(scaled, gray))
        st["refs"].append(im)
        return im

    def show_imgs(items):
        root.update_idletasks()
        avail_w = max(1060, stage.winfo_width() - 40)
        avail_h = max(520, stage.winfo_height() - 60)
        n = len(items)
        slot_w = max(300, (avail_w - 24 * n) // n)
        slot_h = min(560, avail_h)

        f = tk.Frame(stage, bg="#E2E8F0"); f.pack(expand=True)
        for ttl, g, is_g, use_avg in items:
            c = tk.Frame(f, bg="#E2E8F0", padx=10); c.pack(side=tk.LEFT)
            tk.Label(c, text=ttl, font=("Segoe UI", 10, "bold"), bg="#E2E8F0", fg="#0F172A").pack(pady=(0, 4))
            tk.Label(c, image=photo_fit(g, slot_w, slot_h, gray=is_g, area_avg=use_avg), bg="#E2E8F0").pack()

    def render():
        for w in stage.winfo_children(): w.destroy()
        st["refs"].clear()
        i = st["idx"]
        for k, p in enumerate(pills):
            p.config(bg="#16A34A" if k < i else ("#2563EB" if k == i else "#CBD5E1"), fg="white" if k <= i else "#1E293B")
        btn_prev.config(state=tk.NORMAL if i > 0 else tk.DISABLED)
        btn_next.config(state=tk.NORMAL if i < 4 else tk.DISABLED)
        lbl_stat.pack_forget()

        if i == 0:    # STEP 1: Input Image
            show_imgs([("Input Image", st["rgb"], False, False)])
        elif i == 1:  # STEP 2: Binary Matrix
            show_imgs([("Before: Input", st["rgb"], False, False), ("After: Binarization", bin_to_gray(st["P"]), True, False)])
        elif i == 2:  # STEP 3: Split -> Share 1 & Share 2
            show_imgs([("Share 1", bin_to_gray(st["s1"]), True, False), ("Share 2", bin_to_gray(st["s2"]), True, False)])
        elif i == 3:  # STEP 4: Stack (Share 1 OR Share 2)
            show_imgs([
                ("Share 1", bin_to_gray(st["s1"]), True, False),
                ("Share 2", bin_to_gray(st["s2"]), True, False),
                ("Stacked (OR)", bin_to_gray(st["stk"]), True, True),
            ])
        elif i == 4:  # STEP 5: Demonstration
            render_vault_step()

    def render_vault_step():
        shares_dir = os.path.abspath("./shares")
        os.makedirs(shares_dir, exist_ok=True)
        save_bin_png(st["s1"], os.path.join(shares_dir, "share1.png"))
        save_bin_png(st["s2"], os.path.join(shares_dir, "share2.png"))
        save_bin_png(st["stk"], os.path.join(shares_dir, "stacked.png"))
        wrap = tk.Frame(stage, bg="#F8FAFC", padx=16, pady=12); wrap.pack(fill=tk.BOTH, expand=True)

        top_box = tk.LabelFrame(wrap, text=" 1. Chọn mục cần bảo vệ & Đặt mật khẩu bằng ảnh vân tay ", font=("Segoe UI", 10, "bold"), bg="white", fg="#1B365D", padx=12, pady=10)
        top_box.pack(fill=tk.X, pady=(0, 10))

        var_target = tk.StringVar(value=st["target_path"])
        var_pwd = tk.StringVar(value=st["pwd_path"])

        r_t = tk.Frame(top_box, bg="white"); r_t.pack(fill=tk.X, pady=4)
        tk.Label(r_t, text="Tệp / Thư mục bảo vệ:", width=20, anchor="w", bg="white", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)
        tk.Entry(r_t, textvariable=var_target).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        tk.Button(r_t, text="Chọn Tệp...", bg="#2563EB", fg="white", command=lambda: (p := filedialog.askopenfilename(title="Chọn tệp cần bảo vệ")) and (st.__setitem__("target_path", p), var_target.set(p))).pack(side=tk.LEFT, padx=2)
        tk.Button(r_t, text="Chọn Thư mục...", bg="#0D9488", fg="white", command=lambda: (d := filedialog.askdirectory(title="Chọn thư mục cần bảo vệ")) and (st.__setitem__("target_path", d), var_target.set(d))).pack(side=tk.LEFT, padx=2)

        r_p = tk.Frame(top_box, bg="white"); r_p.pack(fill=tk.X, pady=4)
        tk.Label(r_p, text="Ảnh vân tay mật khẩu:", width=20, anchor="w", bg="white", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)
        tk.Entry(r_p, textvariable=var_pwd).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        def pick_pwd_img():
            p = filedialog.askopenfilename(title="Chọn ảnh vân tay làm mật khẩu")
            if p:
                st["pwd_P"] = to_binary(load_rgb(p, root))
                st["pwd_path"] = p
                var_pwd.set(p)
                log.insert(tk.END, f"[SETUP] Đã đặt ảnh mật khẩu mới: {os.path.basename(p)}\n"); log.see(tk.END)
        tk.Button(r_p, text="Chọn ảnh vân tay...", bg="#1B365D", fg="white", command=pick_pwd_img).pack(side=tk.LEFT, padx=2)

        bot_box = tk.LabelFrame(wrap, text=" 2. Mở khóa tệp/thư mục ", font=("Segoe UI", 10, "bold"), bg="white", fg="#0F766E", padx=12, pady=10)
        bot_box.pack(fill=tk.BOTH, expand=True)

        var_unlock = tk.StringVar(value=st["unlock_path"])
        r_u = tk.Frame(bot_box, bg="white"); r_u.pack(fill=tk.X, pady=(4, 8))
        tk.Label(r_u, text="Ảnh nhập mở khóa:", width=20, anchor="w", bg="white", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)
        tk.Entry(r_u, textvariable=var_unlock).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)

        def pick_unlock_img():
            p = filedialog.askopenfilename(title="Chọn ảnh đầu vào để mở khóa", initialdir=shares_dir)
            if p:
                st["unlock_path"] = p
                var_unlock.set(p)
                run_verify(os.path.basename(p), load_rgb(p, root))

        tk.Button(r_u, text="Chọn ảnh & Mở khóa ▶", bg="#16A34A", fg="white", font=("Segoe UI", 9, "bold"), padx=12, command=pick_unlock_img).pack(side=tk.LEFT, padx=3)

        log = tk.Text(bot_box, height=12, font=("Consolas", 10), bg="#0F172A", fg="#E2E8F0", padx=8, pady=6)
        log.pack(fill=tk.BOTH, expand=True)
        log.insert(tk.END, f"[READY] Mật khẩu vân tay: {st['pwd_path']}\n")

        def run_verify(label, img_rgb):
            ok, kind, ratio, msg = verify_vault(st["pwd_P"], img_rgb)
            log.insert(tk.END, f"[{label}] {msg}\n"); log.see(tk.END)
            lbl_stat.pack(before=stage, fill=tk.X, pady=(0, 6))
            if ok:
                lbl_stat.config(bg="#DCFCE7", fg="#166534", text="TRUY CẬP THÀNH CÔNG - VÂN TAY TRÙNG KHỚP")
                open_target(st["target_path"])
            else:
                lbl_stat.config(bg="#FEF2F2", fg="#991B1B", text="TRUY CẬP THẤT BẠI - VÂN TAY KHÔNG TRÙNG KHỚP")

    root.mainloop()

if __name__ == "__main__":
    launch_gui()