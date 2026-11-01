# Enigma Protector 脱壳与重建学习项目

把「运行时绕过 Enigma Protector 5.x 的注册校验」和「从壳里还原出可独立运行的
程序」合并成一个自包含的 Python 工程。适合用来学习：

- Enigma 虚拟机里的注册判定，以及「等完整性校验跑完后再改描述符」的运行时补丁；
- 用 WER LocalDumps + 硬件断点（DR0）在 OEP 抓取已解密、CRT 未运行的原程序映像；
- 重建 PE、导入表、入口桩、TLS 与脚本库；
- 处理壳的虚拟文件系统与脱壳后运行环境之间的差异（序章文件、临时目录等）。

> 仅用于**个人已授权副本**的安全研究与兼容性测试。仓库不包含目标程序、
> 游戏资源或任何密钥；请自备一份合法副本，放进 `bk\`。

---

## 0. 两条路

| 我想…… | 用哪个 | 需要 | 结果 |
|---|---|---|---|
| 直接运行加壳程序（每次绕过注册） | `一键启动游戏.bat` | `test\crackme.exe`（缺失时从 `bk\` 恢复） | 运行时内存补丁，不修改磁盘 |
| 得到无壳、可反复运行的 exe | `一键脱壳重建.bat` | `bk\crackme.exe` + 一次管理员配置 | 从零重建，产物装进 `test\` |

两条路互不冲突。

---

## 1. 快速开始

### A. 运行时启动

```bat
一键启动游戏.bat
```

或：

```bat
python enigma_launch.py
python enigma_launch.py --exe "D:\path\your.exe"
python enigma_launch.py --check
```

启动器默认从 `launcher.json` 读取路径、窗口标题关键字和等待时间。

### B. 脱壳重建

第一次需要让 Windows 能为提取用的临时映像写崩溃转储：

```bat
:: 右键「启用错误转储.bat」→ 以管理员身份运行（只需一次）
```

然后：

```bat
一键脱壳重建.bat
:: 等价于： python run_all.py --from-scratch --verify --with-scene
```

流水线：

1. 把 `test\` 恢复成一份可运行的原始副本（与 `bk\` 不一致时自动恢复）；
2. `extract\extract_oep.py` — DR0=OEP，命中后由 WER 写全量转储，拼出原程序映像；
3. `extract\extract_script.py` — 从运行中的进程取出脚本主体 `start.ax`；
4. `extract\extract_scene.py` — 读出壳虚拟文件系统里的场景脚本；
5. `build\*` — 重建 PE/导入表、WinMain、入口桩、TLS、场景启动桩、
   `data.dpm`、单文件版、`unixTime.dll`；
6. 安装到 `test\` 并试跑校验。

产物：

| 文件 | 说明 |
|---|---|
| `out\unenigma.exe` | 双文件版主程序（需同目录 `data.dpm` + `unixTime.dll`） |
| `out\data.dpm` | 脚本库（`start.ax` 预 XOR + 场景明文） |
| `out\unenigma_single.exe` | 单文件版（脚本库 + 场景启动桩内嵌） |
| `out\unixTime.dll` | 替代 DLL |

双击 `test\unenigma_single.exe` 即可运行。

---

## 2. 目录结构

```
enigma-lab/
├─ 一键启动游戏.bat          运行时绕过注册并启动
├─ 一键脱壳重建.bat          从 bk\crackme.exe 从零提取 + 重建 + 安装 + 试跑
├─ 启用错误转储.bat          配置 WER LocalDumps（管理员，一次）
├─ run_all.py                流水线（提取→重建→安装→校验）
├─ enigma_launch.py          启动器（纯 Python + ctypes）
├─ selfcheck.py              环境自检
├─ launcher.json             路径 / 窗口标题 / 等待时间
├─ bk/                       原始程序备份（自备，不提交）
├─ test/                     运行目录（不提交）
├─ tmp/                      所有临时文件（不提交）
├─ out/                      构建产物（不提交）
├─ extract/                  提取：OEP、脚本、场景、WER 配置
├─ build/                    重建：PE/导入、入口、TLS、DPM、单文件
├─ tools/                    自动化与诊断脚本
└─ docs/                     原理、验证记录、故障排查
```

`bk\`、`test\`、`out\`、`tmp\` 都在 `.gitignore` 里，不会被提交。

---

## 3. 关键实现

- **注册绕过**：注册判定由壳虚拟机的条件描述符决定。等启动完整性校验结束后，
  把两个描述符的标记改成 `0x03`（永不跳转），壳就走「注册成功 → 继续运行」。
  只改数据，不改执行位置。见 `docs/01-注册绕过原理.md`。
- **OEP 映像**：给每个线程设硬件执行断点 `DR0 = OEP`；命中产生未处理异常，
  WER 写全量转储，再从转储拼出 `0x400000..0x453000`。见
  `docs/05-脱壳与重建.md`。
- **PE 重建**：OEP 映像 + `build\app_iat_ok.tsv` 重建导入表；写回原生 WinMain；
  入口桩负责 `.data` 可写、CRT 堆、`__security_init_cookie`；补 TLS 目录。
- **场景启动桩**：目标程序会打开 `GetTempPathA()\scene1.hsp`。原版由壳的虚拟
  文件系统在运行时提供；脱壳版没有 VFS，所以 `build\add_scene_boot.py` 把场景
  文件放进 exe 新增的 `.scn` 段，入口桩启动时写入 `%TEMP%`，再跳回原入口。
  这样单文件版可以直接双击运行。
- **DPM**：`start.ax` 用固定 pad 预 XOR；场景文件明文；单文件版把 DPM 追加到
  exe 末尾并改写 HSPHED 的偏移字段。

---

## 4. 配置

`launcher.json`：

```json
{
  "game_dir": "test",
  "source_exe": "bk/crackme.exe",
  "exe": "test/crackme.exe",
  "window_title": "Elona",
  "player": "enigma",
  "wait": 1.2
}
```

- `window_title`：目标窗口标题里需要包含的关键字（配合窗口类 `hspwnd0`）。
  这是**配置值**而不是代码常量；换目标时改这里即可，代码里不要写死标题。
- `player`：注册对话框里填入的玩家名，内容无关紧要。
- 路径也可以被 `--exe` / `--game-dir` / `ENIGMA_SOURCE` / `ENIGMA_GAME` 覆盖。

---

## 5. 命令行速查

```bat
:: 只提取
python extract\extract_all.py
python extract\extract_oep.py --oep 0x4209E9
python extract\extract_script.py
python extract\extract_scene.py

:: 只重建（tmp\work 已有原料）
python run_all.py --skip-extract

:: 从零
python run_all.py --from-scratch --verify --with-scene

:: 从 bk\ 覆盖 test\ 的原始文件再重建（保留 save/user）
python run_all.py --restore-test --from-scratch --verify

:: 指定脚本库 / 构建无剧情版
python run_all.py --scene-dpm "test\data.dpm"
python run_all.py --no-scene
```

环境变量 `ENIGMA_SOURCE`、`ENIGMA_GAME` 可覆盖默认路径；所有路径都限制在项目内。

---

## 6. 环境要求

| 项目 | 要求 |
|---|---|
| Windows | 32/64 位均可（目标程序是 32 位；OEP 提取用到 WOW64 调试寄存器） |
| Python | 3.8+ |
| 权限 | OEP 提取需要 WER LocalDumps（`启用错误转储.bat` 管理员运行一次） |
| binutils | 只有重建 `unixTime.dll` 时需要（`as`/`dlltool`/`ld`）；缺失时用 `build\unixtime\unixTime.dll` 兜底 |
| 目录 | `bk\` 原始副本 + `test\` 运行副本；临时文件都在 `tmp\` |

---

## 7. 常见问题

- **OEP 提取报「没有抓到转储」**：先管理员运行 `启用错误转储.bat`，确认
  `HKLM\Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\crackme.exe`
  与 `target_extract.exe` 的 `DumpType=2`、`DumpFolder` 指向项目内的
  `tmp\crashdumps`，再重试。如果暂时无法增加 `target_extract.exe` 的配置，
  可以设置 `ENIGMA_EXTRACT_NAME=crackme.exe` 直接用主程序提取；删除该变量后，
  流水线也会在 `target_extract.exe` 未配置时自动回退到已配置的 `crackme.exe`。
- **重建后没有窗口**：先 `python selfcheck.py`；再
  `python run_all.py --restore-test --from-scratch --verify`。
- **新建角色后崩溃 / 没有序章**：确认 `tmp\work\scene1.hsp` 含 `{0}` 序章；
  场景启动桩会自动把它写进 `%TEMP%`。仍失败时用
  `python extract\extract_scene.py` 重新取，再 `python run_all.py --skip-extract`。
- **换了一个目标程序**：改 `launcher.json` 的 `exe` / `source_exe` / `window_title`。
  注意 PE 重建部分（OEP、导入表、入口、DPM）与具体程序相关，不是通用脱壳器。

更多见 `docs\04-故障排查.md`。

---

## 8. 说明

- 不修改原始备份 `bk\`；不提交游戏资源与构建产物。
- 仅用于个人已授权副本或安全研究。
