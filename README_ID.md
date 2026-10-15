# 🛡️ Safe Repo Guard (Bahasa Indonesia)

> **Review keamanan zero-execution untuk codebase asing, bagi manusia dan AI coding agent.**
> Menemukan hal-hal yang berjalan *sendiri* saat kamu membuka folder, menjalankan
> `git status`, `npm install`, atau menyerahkan repo ke AI agent: git hook jahat, pembajakan
> git config, skrip install, task yang jalan saat folder dibuka, file config agent, loader
> tersamar, dan prompt injection.

[🇬🇧 English documentation (README.md)](README.md)

---

## 🚨 Ancamannya

Penyerang menargetkan developer secara langsung: lowongan freelance palsu (Upwork, Fiverr),
"tugas take-home" saat interview kerja, laporan bug, dan repo tak dikenal yang dikirim lewat
`.zip`, link Google Drive, atau URL `git clone`. Payload berjalan sebelum aplikasinya dijalankan:

| Vektor | Pemicunya |
|---|---|
| **Git hook** (`.git/hooks/post-checkout`, `pre-commit`...) yang ikut di dalam `.zip` | `git checkout`, `git commit`, `git pull` |
| **Pembajakan git config** di `.git/config`: `core.fsmonitor`, `core.hooksPath`, `core.pager`, `core.editor`, `core.sshCommand`, `filter.*.smudge/clean`, `diff.*.textconv`, `alias.x = !cmd`, `credential.helper`, `include.path`, URL `ext::` | **`git status`** (fsmonitor), `git log`/`diff` (pager), checkout (filter), fetch (sshCommand) |
| **Repo bersarang / bare repo** dengan hook dan config sendiri | perintah git apa pun di folder itu |
| **Skrip install** di `package.json` (`preinstall`, `postinstall`, `prepare`...) | `npm`/`yarn`/`pnpm install` |
| **Auto-run IDE**: `.vscode/tasks.json` dengan `"runOn": "folderOpen"`, `initializeCommand` di `devcontainer.json` | membuka folder |
| **Loader tersamar**: kode disembunyikan setelah ratusan spasi, `eval(atob(...))`, `child_process` di `*.config.js` | `npm run dev` / build |
| **Peracunan AI agent**: instruksi di README/komentar, teks Unicode tersembunyi, `CLAUDE.md`/`AGENTS.md`/`.cursorrules`, hook di `.claude/settings.json`, server di `.mcp.json` | menjalankan AI agent di folder itu |

Agent dalam mode auto-approve bisa digiring untuk menjalankan payload, atau membaca lalu
mengirim `.env`, SSH key, dan kredensial cloud kamu.

---

## 💡 Isi paket

1. **`safe-repo-scan`**: scanner Python 3.8+ tanpa dependensi. Hanya membaca file, tidak
   pernah menjalankan git atau apa pun dari repo, tidak mengikuti symlink, tidak bisa dibuat
   hang oleh FIFO, dan membuang escape sequence terminal dari semua yang dicetak.
2. **`safe-repo-scan-sh`**: versi Bash untuk mesin tanpa Python (Linux, macOS, Git Bash).
3. **`--disarm`**: menetralkan pemicu otomatis, dengan backup bertimestamp.
4. **Rules untuk AI agent**: Claude Code, Codex/OpenCode (`AGENTS.md`), Gemini CLI/Antigravity,
   Cursor, Windsurf.
5. **Skill `safe-repo-review`**: protokol review langkah demi langkah untuk agent yang
   mendukung skill.

Tidak butuh AI, API key, atau koneksi internet.

---

## ⚡ Instalasi

```bash
git clone https://github.com/harundev0/safe-repo-guard.git
cd safe-repo-guard
less install.sh        # pendek: baca dulu apa yang akan kamu jalankan
./install.sh
```

Installer hanya menyalin file dari repo ini:

- scanner ke `~/.local/bin/` (`safe-repo-scan`, `safe-repo-scan-sh`);
- skill ke `~/.agents/skills/`, serta `~/.claude/skills/` dan `~/.config/opencode/skills/`
  jika tool tersebut terpasang;
- rules global ke `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`, `~/.config/opencode/AGENTS.md`,
  `~/.gemini/GEMINI.md`, dan `~/.codeium/windsurf/memories/global_rules.md`, masing-masing
  hanya jika folder tool itu ada.

Blok rules dibungkus penanda `<!-- safe-repo-guard:start -->` / `<!-- safe-repo-guard:end -->`,
jadi menjalankan installer lagi akan memperbarui, bukan menduplikasi.
`./install.sh --uninstall` menghapus semua yang dipasang.

Rules Cursor bersifat per proyek: salin `rules/cursor-rule.mdc` ke `.cursor/rules/` proyek itu.

---

## 🛠️ Cara pakai

```bash
safe-repo-scan /path/ke/repo-asing           # laporan untuk dibaca manusia
safe-repo-scan /path/ke/repo-asing --json    # JSON untuk skrip/CI
safe-repo-scan-sh /path/ke/repo-asing        # versi Bash
```

| Exit code | Arti |
|---|---|
| `0` | tidak ada temuan HIGH/CRITICAL |
| `1` | ada temuan HIGH/CRITICAL (CI sebaiknya gagal) |
| `2` | path tidak ada / argumen salah |

### Disarm (`--disarm`)

```bash
safe-repo-scan /path/ke/repo-asing --disarm
```

| Vektor | Yang dilakukan disarm |
|---|---|
| Git hook aktif | dipindah ke `.git/hooks_quarantine/<nama>.disabled-<waktu>`, izin eksekusi dicabut |
| Setting git berbahaya | hanya baris itu yang dihapus; asli disimpan sebagai `config.backup-<waktu>` |
| Skrip install npm | diganti nama menjadi `disarmed_<nama>`; asli disimpan sebagai `package.json.backup-<waktu>` |
| Task VS Code `folderOpen` | `tasks.json` diganti nama menjadi `tasks.json.disabled-<waktu>` |

Backup tidak pernah ditimpa, dan tidak ada yang diubah di luar folder yang dipindai. Disarm
**tidak** mengubah kode aplikasi, dev container, file agent, atau dokumen: temuan itu harus
direview manual. Jalankan scan lagi setelahnya.

### Bersama AI agent

> *"Pakai safe-repo-review untuk memeriksa repo ini sebelum melakukan apa pun. Jangan jalankan git atau npm di dalamnya."*

Rules dan skill membuat agent hanya memakai tool baca, memperlakukan teks repo sebagai data
(bukan instruksi), berhenti dan melapor jika ada ancaman, dan bertanya dulu sebelum `--disarm`.

---

## 🔍 Cakupan & batasan

Versi Python memeriksa semuanya. Versi Bash tidak mengikuti `include.path`, tidak mendeteksi
Unicode tersembunyi, symlink keluar repo, dan pola `eval`/base64, serta hanya memindai prompt
injection di file dokumen. Detail ada di tabel "Coverage" pada [README.md](README.md).

- Analisis statis dan heuristik: menemukan pola yang dikenal dan pemicu otomatis, bukan
  antivirus. **Hasil bersih tidak berarti aplikasinya aman dijalankan**: build, test, dan jalankan
  kode asing di container/VM sekali pakai tanpa kredensial kamu.
- Melewati `node_modules`, `vendor`, virtualenv, dan folder hasil generate (`dist`, `build`, `target`,
  `.next`, `.nuxt`, `.svelte-kit`, `.output`, `.turbo`, `coverage`); membaca file
  hingga 2 MB dan maksimal 20.000 file (laporan memberi tahu jika terpotong).
- Memindai repo ini sendiri menghasilkan temuan HIGH: dokumen dan tesnya memang berisi contoh
  serangan.

---

## 🆘 Sudah terlanjur terpapar?

Jika git, install, build, atau agent sudah sempat berjalan di repo mencurigakan:

1. **Putuskan internet** (matikan Wi-Fi / cabut kabel) untuk menghentikan unduhan dan pencurian data.
2. **Cari dan hentikan proses**:
   ```bash
   ps aux | grep -E 'curl|wget|nc |ncat|socat|bash -i|python -c|node -e'
   lsof -i -P -n            # koneksi jaringan aktif
   kill -9 <PID>
   ```
3. **Periksa persistensi** (jalur penyerang untuk kembali):
   ```bash
   crontab -l
   ls -la ~/.config/systemd/user/ ~/.config/autostart/ 2>/dev/null
   tail -n 20 ~/.bashrc ~/.zshrc ~/.profile 2>/dev/null
   cat ~/.ssh/authorized_keys
   ls -la ~/Library/LaunchAgents 2>/dev/null     # macOS
   ```
   Hapus apa pun yang bukan kamu tambahkan.
4. **Netralkan atau hapus repo**: `safe-repo-scan <path> --disarm`, atau `rm -rf <path>`.
5. **Ganti semua rahasia dari perangkat lain yang bersih**: token GitHub/GitLab dan SSH key,
   key cloud (AWS, GCP, Azure), API key di file `.env` (OpenAI, Anthropic, Stripe, database),
   password yang tersimpan di browser dan dompet kripto; logout sesi lain.
6. **Pindai** dengan antivirus, misalnya `clamscan -r -i ~/`. Jika ragu, instal ulang OS.

---

## 📋 Checklist manual (tanpa tool)

Perintah read-only, dijalankan dari root repo:

```bash
ls -la .git                                     # jika FILE atau symlink, git diarahkan ke tempat lain
ls -la .git/hooks/ | grep -v '\.sample$'        # hook aktif; baca dengan: cat -v .git/hooks/<nama>
cat -v .git/config                              # clone baru hanya berisi [core], [remote], [branch]
grep -n -i -E '^[[:space:]]*(hookspath|fsmonitor|pager|editor|sshcommand|askpass|gitproxy|external|textconv|command|smudge|clean|process|driver|helper|program|cmd|path|worktree)[[:space:]]*=' .git/config
grep -n -E '=[[:space:]]*"?!|ext::' .git/config
grep -rn -E '"(preinstall|install|postinstall|prepare|prepack)"[[:space:]]*:' --include=package.json --exclude-dir=node_modules .
grep -rn -i 'folderOpen' --include=tasks.json .
```

**Aturan emas:** jangan jalankan perintah `git` apa pun di repo asing sebelum semua ini bersih.

---

## 🧪 Pengembangan

```bash
python3 -m unittest discover -s tests -v
```

## 📄 Lisensi

MIT. Lihat [LICENSE](LICENSE).
