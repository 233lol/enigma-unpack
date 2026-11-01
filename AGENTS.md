# AGENTS.md

Windows-only, stdlib-only Python reverse-engineering/build pipeline for an
Enigma Protector 5.x target. It is not a normal app/library: most commands
launch the target, write crash dumps, or patch binaries.

This is the **public, sanitized** branch. Do not reintroduce target/game
branding into code, docs, filenames, or commit messages. The target window
keyword lives only as the data value `launcher.json` → `window_title`; code
must read it, never hardcode a title.

## Read first

- `README.md` — pipeline, quick start, FAQ.
- `run_all.py` — the orchestrator; start here for any build change.
- `extract/paths.py` — the source/target/temp rules. Do not hardcode paths elsewhere.
- `docs/05-脱壳与重建.md` — PE/OEP/import/DPM/XOR details and addresses.
- `docs/08-自动进入序章.md` — exact new-game key sequence and the scene temp-file issue.

## Hard rules

- Stay inside the repo. Never use system `%TEMP%` or parent directories from
  project scripts; `paths.use_local_temp()` redirects `TEMP/TMP` to
  `<repo>\tmp`. (The built exe itself writes its scene files to the *current*
  user's `%TEMP%` via `GetTempPathA`; that is intended.)
- `bk/` is the pristine original backup. **Never run games from it**; running
  there writes `config.txt`, `user/`, `data/license.s2`. Run from `test/` only.
- `test/` is the runnable game dir; `out/` is final products; `tmp/` holds all
  intermediates and crash dumps (`paths.WORK = tmp/work`).
- Preserve `test/save/sav_test1` — it is a verified working original save.
- `build/` is source/recipe, not disposable. Do not delete
  `build/app_iat_ok.tsv`, `build/unixtime/`, or `tools/`.
- OEP extraction needs admin-configured WER LocalDumps. Run
  `启用错误转储.bat` as administrator once (sets `crackme.exe` and
  `target_extract.exe` to `<repo>\tmp\crashdumps`, restarts `WerSvc`).
  `target_extract.exe` is a temporary hardlink of `crackme.exe`; WER keys by
  image name, so the distinct name isolates this project's HKCU config.
- `bk/`, `test/`, `out/`, `tmp/` are git-ignored. They are required at runtime
  but never committed.

## Commands

```bat
:: full from zero (preferred for verification)
python run_all.py --from-scratch --verify --with-scene
:: same as double-clicking 一键脱壳重建.bat

:: rebuild from existing tmp\work
python run_all.py --skip-extract

:: restore test\ from bk\ first, then rebuild
python run_all.py --restore-test --from-scratch --verify

:: focused single steps
python extract\extract_scene.py
python extract\extract_oep.py
python extract\extract_script.py
python selfcheck.py
python enigma_launch.py --check
```

Verification is `run_all.py --verify` (launches `test\unenigma_single.exe` and
waits for the configured `hspwnd0` window). There is no unit-test suite.

## Non-obvious pipeline facts

- `extract_oep.py` uses WER full dumps + hardware breakpoint `DR0` at
  `0x4209E9`/`0x420F3C`. It runs a temporary hardlink
  `test\target_extract.exe` because WER keys by image name; it is deleted
  after extraction.
- `extract_scene.py` reads Enigma virtual files through the target's own HSP
  functions (`0x401280`, `0x4018F0`) while the target is running. It writes
  stripped `scene1.hsp` (145,508 B) / `scene2.hsp` (2,661 B). The original DPM
  also stores stripped scenes, so the `;###` header is **not** required.
- `build_exe.py` rebuilds PE + imports from `tmp\work\app_img_oep.bin` and
  `build\app_iat_ok.tsv`; then `restore_winmain.py` writes native WinMain at
  `0x41AFF0`, `add_entry.py` adds the entry stub, `add_tls.py` adds TLS,
  `add_scene_boot.py` adds the `.scn` scene bootstrap (see below).
- DPM storage: `start.ax` is pre-XORed with the fixed 0x47-byte pad; scene files
  are plaintext. `build_singlefile.py` appends the DPM and patches `optmes`.
- binutils is needed only for `unixTime.dll`; if missing, the build copies
  `build\unixtime\unixTime.dll` as a fallback.

## Scene temp-file bootstrap (solved — don't re-debug)

Symptom inside the prologue: `HspError 12 WinError 2` (FILE_IO / file not
found), with a misleading `* invalid chara position ...` line. The target's
`Scene:Init` opens the absolute path `GetTempPathA()\scene1.hsp`. The original
Enigma VFS materializes the scene files in `%TEMP%`; an unpacked exe has no
VFS, so the open failed. DPM contents, encoding, arrays, and DLL replacement
were red herrings.

Fix: `build/add_scene_boot.py` appends a `.scn` section with both validated
scene files plus a startup stub, and repoints `AddressOfEntryPoint` at the
stub. The stub writes `%TEMP%\scene1.hsp` and `%TEMP%\scene2.hsp` (via
`GetTempPathA` + `MultiByteToWideChar` + `CreateFileW` + `WriteFile`) and
tails into the old entry (`0x454670`, i.e. the `add_entry.py` cave). It runs
after `add_tls.py` and before `build_singlefile.py`; `.scn` must be added
before the DPM is appended, or the HSPHED `mode` offset breaks.

Verification: with `tmp\scene1.hsp` and `tmp\scene2.hsp` deleted, run
`python tools/auto_seq.py test unenigma_single.exe 1.0`; the target must reach
the prologue with no `test\error.txt`, and the exe must recreate both temp
scene files itself.

## GUI automation gotchas

- `tools\auto_seq.py` sends the correct new-game sequence:
  `b×9, a, b, a, b, Enter, a, Esc, a, name, Enter`.
- Keys need 0.8–1.2 s spacing and real foreground focus; the script uses
  `AttachThreadInput`. Without it the target stalls at the talent screen.
- Window matching is `hspwnd0` + `launcher.json`'s `window_title` (empty means
  class-only). Use `enigma_launch.is_game_window()`; do not hardcode titles.
- `tools\auto_orig.py` runs the same sequence on the original via the launcher;
  `tools\load_save_test.py` loads the save. Set `KEEP=1` to leave the target
  running for screenshots, and kill target processes after tests.
