"""Generate the TokenHunt landing-page demo GIF + poster PNG.

EVERYTHING the tool "prints" in the GIF is verbatim captured output from real
runs of the token-hunt CLI on this machine (Windows, Python 3.13, PYTHONUTF8=1):

  $ cd /c/tmp/th4
  $ printf 'export ANTHROPIC_API_KEY=%s\\n' "$KEY" > sessions/transcript.jsonl
  $ token-hunt watch sessions            # -> lines captured to watch-out.txt
  $ token-hunt scan sessions/transcript.jsonl --context PreToolUse:Bash --no-log

The only cosmetic deviations from raw bytes:
  - "sessions\\transcript.jsonl" rendered with a forward slash (path separator)
  - U+FE0F variation selector dropped from the warning sign (the mono font has
    only the monochrome glyph)

Usage:
    python docs/make-demo-gif.py

Outputs:
    E:/dev/projects/tokenhunt-site/public/demo.gif        (1000x560, 12 fps)
    E:/dev/projects/tokenhunt-site/public/demo-poster.png (2000x1120, final frame @2x)
"""
from __future__ import annotations

import os

from PIL import Image, ImageDraw, ImageFont

OUT_GIF = "E:/dev/projects/tokenhunt-site/public/demo.gif"
OUT_POSTER = "E:/dev/projects/tokenhunt-site/public/demo-poster.png"

FONT_DIR = os.path.join(
    os.path.expanduser("~"), "AppData", "Local", "Microsoft", "Windows", "Fonts"
)
FONT_REG = os.path.join(FONT_DIR, "JetBrainsMono-Regular.ttf")
FONT_MED = os.path.join(FONT_DIR, "JetBrainsMono-Medium.ttf")

INK = (12, 13, 16)        # #0C0D10 background
PAPER = (244, 243, 239)   # #F4F3EF default text
ORANGE = (255, 90, 31)    # #FF5A1F leak highlight / prompt
RED = (229, 72, 77)       # #E5484D critical alert only
MUTED = (138, 143, 152)   # #8A8F98
BORDER = (31, 33, 38)     # #1F2126
HL_BG = (36, 21, 9)       # flat dark-orange tint behind the match line

SCALE = 2                 # render at 2x, ship the GIF at 1x
W, H = 1000, 560
TITLE_H = 34
MARGIN_X = 28
TOP_PAD = 20
LINE_H = 26
FPS = 12
FRAME_MS = 1000 // FPS
COLS = 104                # display columns

KEY = (
    "sk-ant-api03-WBy4JhEAhWFl8MYgCSlFU0POqQW9bBx8C8xf2jttqxoFLd70UiwuU69m2"
    "KyeOrxSP1vEBpfOK75PtBqpPyQi4sQ3w"
)

CMD_WATCH = "token-hunt watch sessions"
CMD_WRITE = f"printf 'export ANTHROPIC_API_KEY={KEY}' > sessions/transcript.jsonl"
CMD_SCAN = (
    "token-hunt scan sessions/transcript.jsonl --context PreToolUse:Bash --no-log"
)

# Verbatim captured outputs (see module docstring for capture commands).
OUT_WATCHING = "watching sessions for new files..."
OUT_WATCH_ALERT = "⚠  sessions/transcript.jsonl: 2 leak(s) detected"
OUT_SCAN_HEAD = "⚠  1 potential leak(s) detected:"
OUT_SCAN_MATCH = "  - anthropic-key (fp=bffec25e) @ line 1"
OUT_SCAN_ROTATE = "    rotate: https://console.anthropic.com/settings/keys"

TITLE = "token-hunt watch sessions/"

# row role -> (fg color, font key, highlight bg)
ROLE = {
    "cmd": (PAPER, "reg", None),
    "out": (MUTED, "reg", None),
    "warn": (ORANGE, "med", None),
    "crit": (RED, "med", None),
    "find": (ORANGE, "med", HL_BG),
}

font_cache: dict[tuple[str, int], ImageFont.FreeTypeFont] = {}


def get_font(which: str, size: int) -> ImageFont.FreeTypeFont:
    key = (which, size)
    if key not in font_cache:
        font_cache[key] = ImageFont.truetype(
            FONT_REG if which == "reg" else FONT_MED, size
        )
    return font_cache[key]


def wrap(text: str, cols: int, first_cols: int | None = None) -> list[str]:
    """Hard-wrap like a terminal (no indent on continuation lines)."""
    limit = first_cols if first_cols is not None else cols
    lines = []
    while len(text) > limit:
        lines.append(text[:limit])
        text = text[limit:]
        limit = cols
    lines.append(text)
    return lines


class Terminal:
    """Accumulates committed display rows; each row is (text, role)."""

    def __init__(self, cols: int):
        self.cols = cols
        self.rows: list[tuple[str, str]] = []

    def push(self, text: str, role: str) -> None:
        self.rows.append((text, role))

    def rows_for_typing(self, typed: str) -> list[tuple[str, str]]:
        rows = list(self.rows)
        first = self.cols - 2  # "$ " eats two columns on the first row
        for i, chunk in enumerate(wrap(typed, self.cols, first)):
            rows.append((("$ " if i == 0 else "") + chunk, "cmd"))
        return rows


def render(rows: list[tuple[str, str]], cursor: tuple[int, int] | None,
           cursor_on: bool, scale: int = SCALE,
           downscale: bool = True) -> Image.Image:
    """Render one frame. cursor = (row_index, col_index) into `rows`."""
    img = Image.new("RGB", (W * scale, H * scale), INK)
    d = ImageDraw.Draw(img)

    # window border, rounded 8px
    d.rounded_rectangle(
        [scale, scale, (W - 2) * scale, (H - 2) * scale],
        radius=8 * scale, outline=BORDER, width=scale,
    )
    # title bar divider
    d.line([scale, TITLE_H * scale, (W - 1) * scale, TITLE_H * scale],
           fill=BORDER, width=scale)
    # three muted dots
    r = 4 * scale
    for i in range(3):
        cx = (24 + i * 16) * scale
        cy = (TITLE_H // 2) * scale
        d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=MUTED)
    # title text
    d.text((72 * scale, (TITLE_H // 2) * scale), TITLE,
           font=get_font("reg", 12 * scale), fill=MUTED, anchor="lm")

    body_font = get_font("reg", 15 * scale)
    med_font = get_font("med", 15 * scale)
    x0 = MARGIN_X * scale
    max_rows = (H - TITLE_H - TOP_PAD - 20) // LINE_H
    visible = rows[-max_rows:]
    cursor_row, cursor_col = cursor if cursor else (None, None)

    y = (TITLE_H + TOP_PAD) * scale
    for idx, (text, role) in enumerate(visible):
        fg, fkey, hl = ROLE[role]
        fnt = body_font if fkey == "reg" else med_font
        row_h = LINE_H * scale
        if hl:
            d.rectangle([x0 - 6 * scale, y,
                         (W - MARGIN_X) * scale + 6 * scale, y + row_h],
                        fill=hl)
        d.text((x0, y + row_h // 2), text, font=fnt, fill=fg, anchor="lm")

        if cursor_on and idx == cursor_row:
            cw = body_font.getlength("M")
            cx = x0 + cursor_col * cw
            d.rectangle([cx, y + 5 * scale, cx + cw, y + row_h - 5 * scale],
                        fill=ORANGE)
        y += row_h

    if scale == 1 or not downscale:
        return img
    return img.resize((W, H), Image.LANCZOS)


def build_seq() -> list[tuple[list, tuple[int, int] | None, bool, int]]:
    """Return [(rows, cursor, cursor_on, repeat_frames)]."""
    term = Terminal(COLS)
    seq: list[tuple[list, tuple[int, int] | None, bool, int]] = []

    def type_cmd(cmd: str, per_frame: int, blink_hold: int) -> None:
        n = 0
        while n <= len(cmd):
            rows = term.rows_for_typing(cmd[:n])
            last = rows[-1]
            cursor = (len(rows) - 1, len(last[0]))
            seq.append((rows, cursor, True, 1))
            n += per_frame
        term.rows = term.rows_for_typing(cmd)  # commit (keeps hard wrap)
        for k in range(blink_hold):
            seq.append((list(term.rows), None, k % 2 == 0, 1))

    # initial prompt
    term.push("$ ", "cmd")
    for k in range(3):
        seq.append((list(term.rows), (0, 2), k % 2 == 0, 1))
    term.rows.pop()  # typing re-renders the prompt itself

    # 1. watch command
    type_cmd(CMD_WATCH, 2, 3)

    # watching output
    term.push(OUT_WATCHING, "out")
    seq.append((list(term.rows), None, False, 5))

    # 2. file-write command
    term.push("", "cmd")  # blank separator
    type_cmd(CMD_WRITE, 6, 3)

    # watch fires (real captured output)
    term.push(OUT_WATCH_ALERT, "warn")
    seq.append((list(term.rows), None, False, 6))

    # 3. scan command
    term.push("", "cmd")
    type_cmd(CMD_SCAN, 7, 2)

    # scan output, line by line (real captured output)
    for text, role in [
        (OUT_SCAN_HEAD, "crit"),
        (OUT_SCAN_MATCH, "find"),
        (OUT_SCAN_ROTATE, "warn"),
    ]:
        term.push(text, role)
        seq.append((list(term.rows), None, False, 3))

    # fresh prompt + blinking cursor, hold ~1.7s before loop
    term.push("$ ", "cmd")
    for k in range(20):
        seq.append((list(term.rows), (len(term.rows) - 1, 2), k % 2 == 0, 1))

    return seq


def main() -> None:
    seq = build_seq()

    # render + merge identical consecutive frames
    frames: list[tuple[Image.Image, int]] = []
    prev_bytes = None
    total_ms = 0
    for rows, cursor, con, reps in seq:
        frame = render(rows, cursor, con)
        total_ms += reps * FRAME_MS
        b = frame.tobytes()
        if prev_bytes is not None and b == prev_bytes:
            f, d = frames[-1]
            frames[-1] = (f, d + reps * FRAME_MS)
        else:
            frames.append((frame, reps * FRAME_MS))
            prev_bytes = b
    print(f"frames: {len(frames)}  duration: {total_ms / 1000:.2f}s")

    # poster: final state at full 2x (before downscale)
    last_rows, _, _, _ = seq[-1]
    poster = render(last_rows, (len(last_rows) - 1, 2), True, scale=2,
                    downscale=False)
    poster.save(OUT_POSTER, optimize=True)
    print(f"wrote {OUT_POSTER} ({os.path.getsize(OUT_POSTER)} bytes)")

    os.makedirs(os.path.dirname(OUT_GIF), exist_ok=True)
    frames_q = [
        (f.quantize(colors=256, method=Image.MEDIANCUT, dither=Image.NONE), d)
        for f, d in frames
    ]
    first, _ = frames_q[0]
    first.save(
        OUT_GIF, save_all=True, append_images=[f for f, _ in frames_q[1:]],
        duration=[d for _, d in frames_q], loop=0, optimize=True,
    )
    print(f"wrote {OUT_GIF} ({os.path.getsize(OUT_GIF)} bytes)")


if __name__ == "__main__":
    main()
