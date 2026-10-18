"""Frame raw captures in a browser window for the README, and build the tour and clip GIFs.

    python frame.py stills  RAW_DIR OUT_DIR    # RAW_DIR/shots.json -> OUT_DIR/<name>.png
    python frame.py tour    REC_DIR OUT_DIR    # REC_DIR/frames.json -> OUT_DIR/<REC_DIR name>.gif (+ .mp4 for the tour)

Stills: a macOS-style window (traffic lights, URL pill with the page's real path, 1 px
border, rounded corners) on a transparent canvas with a soft drop shadow, 1600 px wide and
under 480 KB (the page posterised to 256 colours when full colour does not fit; the shadow
keeps its alpha). Recordings (capture.mjs --tour / --record): every frame in the same dark
chrome on a solid background, then ffmpeg's two-pass palette GIF and, for the tour, an
H.264 MP4.

Needs Pillow; recordings need ffmpeg on PATH.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from functools import lru_cache
from pathlib import Path

from PIL import Image
from PIL import ImageDraw
from PIL import ImageFilter
from PIL import ImageFont

THEMES = {
    "dark": {"bar": "#1D1F25", "pill": "#26282D", "border": "#43444C", "text": "#8E9099", "lock": "#6F727C"},
    "light": {"bar": "#F0F2F4", "pill": "#FFFFFF", "border": "#E2E6E9", "text": "#6B7079", "lock": "#9A9EA6"},
}
DOTS = ("#FF5F57", "#FEBC2E", "#28C840")
TOUR_BACKGROUND = "#14161A"
FONT_CANDIDATES = (
    "/usr/share/fonts/opentype/inter/Inter-Regular.otf",
    "/usr/share/fonts/truetype/inter/Inter-Regular.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
)

# Geometry at 1x (CSS pixels); everything is multiplied by the capture's scale.
BAR_HEIGHT = 44
RADIUS = 14
BORDER = 1
DOT_RADIUS = 6
DOT_GAP = 20
DOT_LEFT = 20
PILL_HEIGHT = 28
PILL_WIDTH_SHARE = 0.46
FONT_SIZE = 13
SUPERSAMPLE = 4


@lru_cache(maxsize=None)
def _font(size: int) -> ImageFont.FreeTypeFont:
    for path in FONT_CANDIDATES:
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default(size)


def _rounded_mask(size: tuple, radius: int) -> Image.Image:
    """An anti-aliased rounded-rectangle mask, drawn large and scaled down."""
    w, h = size
    big = Image.new("L", (w * SUPERSAMPLE, h * SUPERSAMPLE), 0)
    ImageDraw.Draw(big).rounded_rectangle((0, 0, w * SUPERSAMPLE - 1, h * SUPERSAMPLE - 1), radius * SUPERSAMPLE, fill=255)
    return big.resize(size, Image.LANCZOS)


def _top_rounded_mask(size: tuple, radius: int) -> Image.Image:
    """Rounded top corners only, for the bar."""
    w, h = size
    big = Image.new("L", (w * SUPERSAMPLE, h * SUPERSAMPLE), 0)
    d = ImageDraw.Draw(big)
    d.rounded_rectangle((0, 0, w * SUPERSAMPLE - 1, h * SUPERSAMPLE - 1 + radius * SUPERSAMPLE), radius * SUPERSAMPLE, fill=255)
    return big.resize(size, Image.LANCZOS)


def _draw_bar(width: int, scale: float, url: str, theme: str) -> Image.Image:
    """The window's top bar: traffic lights and the URL pill, drawn supersampled."""
    colors = THEMES[theme]
    s = scale * SUPERSAMPLE
    w, h = width * SUPERSAMPLE, round(BAR_HEIGHT * s)
    bar = Image.new("RGBA", (w, h), colors["bar"])
    d = ImageDraw.Draw(bar)
    cy = h / 2
    for i, color in enumerate(DOTS):
        cx = (DOT_LEFT + i * DOT_GAP) * s
        r = DOT_RADIUS * s
        d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=color)

    pill_w = w * PILL_WIDTH_SHARE
    pill_h = PILL_HEIGHT * s
    x0, y0 = (w - pill_w) / 2, cy - pill_h / 2
    d.rounded_rectangle((x0, y0, x0 + pill_w, y0 + pill_h), pill_h / 2, fill=colors["pill"])

    font = _font(round(FONT_SIZE * s))
    text_w = d.textlength(url, font=font)
    lock_w = 9 * s
    gap = 7 * s
    total = lock_w + gap + text_w
    tx = (w - total) / 2
    # A small padlock: shackle arc over a rounded body.
    lx, ly = tx, cy - 1.5 * s
    body_h = 6.5 * s
    d.rounded_rectangle((lx, ly - 0.5 * s, lx + lock_w, ly + body_h), 1.6 * s, fill=colors["lock"])
    sh = 3.2 * s
    d.arc(
        (lx + 1.6 * s, ly - sh * 1.55, lx + lock_w - 1.6 * s, ly + sh * 0.45),
        180,
        360,
        fill=colors["lock"],
        width=max(1, round(1.4 * s)),
    )
    d.text((tx + lock_w + gap, cy), url, font=font, fill=colors["text"], anchor="lm")
    return bar.resize((width, round(BAR_HEIGHT * scale)), Image.LANCZOS)


def window(shot: Image.Image, url: str, theme: str, scale: float) -> Image.Image:
    """The capture inside the browser window, rounded and bordered, as RGBA."""
    shot = shot.convert("RGBA")
    w = shot.width
    bar = _draw_bar(w, scale, url, theme)
    inner = Image.new("RGBA", (w, bar.height + shot.height), THEMES[theme]["bar"])
    inner.paste(bar, (0, 0))
    inner.paste(shot, (0, bar.height))
    # Hairline between the bar and the page.
    ImageDraw.Draw(inner).rectangle((0, bar.height - max(1, round(BORDER * scale)), w, bar.height - 1), fill=THEMES[theme]["border"])

    bw = max(1, round(BORDER * scale))
    radius = round(RADIUS * scale)
    outer_size = (inner.width + 2 * bw, inner.height + 2 * bw)
    out = Image.new("RGBA", outer_size, (0, 0, 0, 0))
    border_layer = Image.new("RGBA", outer_size, THEMES[theme]["border"])
    out.paste(border_layer, (0, 0), _rounded_mask(outer_size, radius))
    out.paste(inner, (bw, bw), _rounded_mask(inner.size, radius - bw))
    return out


def with_shadow(win: Image.Image, scale: float, padding: int, background=None) -> Image.Image:
    """The window on a canvas with a soft drop shadow (CSS-like blur 40, y 16 at 2x)."""
    pad = round(padding)
    canvas_size = (win.width + 2 * pad, win.height + 2 * pad)
    canvas = Image.new("RGBA", canvas_size, background or (0, 0, 0, 0))
    alpha = win.getchannel("A")
    shadow = Image.new("RGBA", canvas_size, (0, 0, 0, 0))
    shadow_alpha = Image.new("L", canvas_size, 0)
    offset_y = round(8 * scale)
    shadow_alpha.paste(alpha.point(lambda a: int(a * 0.35)), (pad, pad + offset_y))
    shadow_alpha = shadow_alpha.filter(ImageFilter.GaussianBlur(10 * scale))
    shadow.putalpha(shadow_alpha)
    canvas = Image.alpha_composite(canvas, shadow)
    canvas.alpha_composite(win, (pad, pad))
    return canvas


def _posterise_window(img: Image.Image) -> Image.Image:
    """The opaque window reduced to 256 colours; the shadow and the anti-aliased edges keep theirs.

    A paletted PNG would band the soft shadow, so the image stays RGBA: fewer distinct colours
    in the page is what lets deflate do better.
    """
    alpha = img.getchannel("A")
    content = img.convert("RGB").quantize(256, method=Image.Quantize.FASTOCTREE, dither=Image.Dither.NONE).convert("RGB")
    out = img.copy()
    out.paste(content, (0, 0), alpha.point(lambda a: 255 if a == 255 else 0))
    return out


def save_optimised(img: Image.Image, path: Path, budget_kb: int = 480) -> dict:
    """Save as PNG within ``budget_kb``: full colour when it fits, else the posterised window."""
    img.save(path, optimize=True)
    mode = "full"
    if path.stat().st_size > budget_kb * 1024:
        _posterise_window(img).save(path, optimize=True)
        mode = "posterised"
    size = path.stat().st_size
    if size > budget_kb * 1024:
        print(f"warning: {path.name} is {size // 1024} KB, over the {budget_kb} KB budget", file=sys.stderr)
    return {"file": str(path), "bytes": size, "mode": mode, "size": img.size}


def frame_still(raw: Path, url: str, theme: str, out: Path, width: int = 1600, padding: int = 40) -> dict:
    """One capture in its window, ``padding`` px of transparent margin around it at ``width``."""
    shot = Image.open(raw)
    scale = shot.width / 1440
    win = window(shot, url, theme, scale)
    pad = padding * win.width / (width - 2 * padding)
    canvas = with_shadow(win, scale, pad)
    canvas = canvas.resize((width, round(canvas.height * width / canvas.width)), Image.LANCZOS)
    return save_optimised(canvas, out)


def stills(raw_dir: Path, out_dir: Path, host: dict) -> None:
    manifest = json.loads((raw_dir / "shots.json").read_text())
    out_dir.mkdir(parents=True, exist_ok=True)
    for shot in manifest:
        url = host.get(shot.get("app", "app"), host["app"]) + shot["path"]
        info = frame_still(raw_dir / shot["file"], url, shot["theme"], out_dir / f"{shot['name']}.png")
        print(f"{info['file']}: {info['size'][0]}x{info['size'][1]} {info['bytes'] // 1024} KB ({info['mode']})")


VIDEO_FPS = 15


def _render_tour_frames(tour_dir: Path, frames: list, work: Path, host: dict, fps: int) -> tuple:
    """Every tick of a constant-rate sequence: the latest recorded frame, framed in the dark chrome."""
    duration = frames[-1]["t"] + 1.5
    cache: dict = {}
    n = int(duration * fps)
    j = 0
    for i in range(n):
        t = i / fps
        while j + 1 < len(frames) and frames[j + 1]["t"] <= t:
            j += 1
        f = frames[j]
        if f["file"] not in cache:
            cache.clear()
            shot = Image.open(tour_dir / f["file"]).convert("RGB")
            scale = shot.width / 1440
            url = host.get(f.get("app", "app"), host["app"]) + f["path"]
            win = window(shot, url, "dark", scale)
            cache[f["file"]] = with_shadow(win, scale, 32 * scale, background=TOUR_BACKGROUND).convert("RGB")
        cache[f["file"]].save(work / f"t{i:05d}.png", compress_level=1)
    return n, cache[f["file"]].size


def tour(tour_dir: Path, out_dir: Path, host: dict, fps: int, gif_width: int, speed: float, gif_budget_mb: float, mp4: bool) -> None:
    """frames.json: [{"file": "f00001.jpg", "t": seconds, "path": "/...", "app": "app"|"portal"}, ...].

    Writes ``<dir name>.gif`` (and ``.mp4``) to ``out_dir``: ``tour``, ``gif-soc``, ...
    """
    name = tour_dir.resolve().name
    frames = json.loads((tour_dir / "frames.json").read_text())
    frames.sort(key=lambda f: f["t"])
    for f in frames:
        f["t"] /= speed
    work = Path(tempfile.mkdtemp(prefix="tour-frames-"))
    out_dir.mkdir(parents=True, exist_ok=True)
    ffmpeg = ["ffmpeg", "-y", "-loglevel", "error", "-framerate", str(VIDEO_FPS), "-i", str(work / "t%05d.png")]
    try:
        n, size = _render_tour_frames(tour_dir, frames, work, host, VIDEO_FPS)
        print(f"{n} frames at {VIDEO_FPS} fps ({n / VIDEO_FPS:.1f} s), {size[0]}x{size[1]}")
        video = out_dir / f"{name}.mp4"
        if mp4:
            mp4_args = ["-vf", "scale=1600:-2:flags=lanczos", "-c:v", "libx264", "-preset", "slow", "-crf", "24", "-pix_fmt", "yuv420p"]
            subprocess.run([*ffmpeg, *mp4_args, "-movflags", "+faststart", str(video)], check=True)
        palette = work / "palette.png"
        gif = out_dir / f"{name}.gif"
        # Two-pass palette. Over budget: a slightly narrower GIF first, then fewer frames per second.
        narrower = round(gif_width * 0.93 / 2) * 2
        attempts = [(fps, gif_width), (fps, narrower), (max(8, fps - 2), narrower), (8, narrower)]
        for gif_fps, width in attempts:
            filters = f"fps={gif_fps},scale={width}:-1:flags=lanczos"
            subprocess.run([*ffmpeg, "-vf", f"{filters},palettegen=stats_mode=diff:max_colors=128", str(palette)], check=True)
            use = f"{filters} [x]; [x][1:v] paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle"
            subprocess.run([*ffmpeg, "-i", str(palette), "-lavfi", use, "-loop", "0", str(gif)], check=True)
            megabytes = gif.stat().st_size / 1024 / 1024
            print(f"{gif}: {megabytes:.2f} MB at {gif_fps} fps, {width} px")
            if megabytes <= gif_budget_mb:
                break
        if mp4:
            print(f"{video}: {video.stat().st_size / 1024 / 1024:.2f} MB")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(argv=None) -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("command", choices=["stills", "tour"])
    p.add_argument("source", type=Path)
    p.add_argument("out", type=Path)
    p.add_argument("--app-host", default="copilot.example.com")
    p.add_argument("--portal-host", default="portal.example.com")
    p.add_argument("--fps", type=int, default=12, help="GIF frame rate to try first")
    p.add_argument("--gif-width", type=int, default=1200)
    p.add_argument("--speed", type=float, default=None, help="playback speed (1 = as recorded; default 1.1 for the tour, 1.4 for a clip)")
    p.add_argument("--gif-budget", type=float, default=None, help="largest acceptable GIF in MB (5 for the tour, 3 for a clip)")
    p.add_argument("--mp4", action=argparse.BooleanOptionalAction, default=None, help="also an MP4 (default: the tour only)")
    args = p.parse_args(argv)
    host = {"app": args.app_host, "portal": args.portal_host}
    if args.command == "stills":
        stills(args.source, args.out, host)
    else:
        is_tour = args.source.resolve().name == "tour"
        budget = args.gif_budget if args.gif_budget is not None else (5.0 if is_tour else 3.0)
        mp4 = args.mp4 if args.mp4 is not None else is_tour
        speed = args.speed if args.speed is not None else (1.1 if is_tour else 1.4)
        tour(args.source, args.out, host, args.fps, args.gif_width, speed, budget, mp4)


if __name__ == "__main__":
    sys.exit(main())
