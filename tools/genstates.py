#!/usr/bin/env python3
"""Generates the teapot state images (UI + tray) from assets/logo.png. Run from the project root."""
from PIL import Image, ImageDraw, ImageFont, ImageEnhance, ImageChops

logo = Image.open("assets/logo.png").convert("RGBA")
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

def tint(im, rgb, amount):
    a = im.split()[3]
    gray = ImageEnhance.Color(im).enhance(0.0).convert("RGB")
    over = Image.new("RGB", im.size, rgb)
    out = Image.blend(gray, over, amount).convert("RGBA")
    out.putalpha(a)
    return out

def circle_mask(size):
    m = Image.new("L", (size, size), 0)
    ImageDraw.Draw(m).ellipse((0, 0, size - 1, size - 1), fill=255)
    return m

# ---- UI variants (220x220)
off = ImageEnhance.Color(logo).enhance(0.0)
off = ImageEnhance.Brightness(off).enhance(0.72)
d = ImageDraw.Draw(off)
f1, f2, f3 = (ImageFont.truetype(FONT, s) for s in (34, 26, 20))
for (x, y, f) in ((126, 58, f1), (150, 42, f2), (168, 30, f3)):  # kept inside the circle the UI crops to
    d.text((x, y), "z", font=f, fill=(210, 220, 230, 255), stroke_width=2, stroke_fill=(20, 28, 34, 255))
off.save("assets/logo_off.png")

bad = tint(logo, (255, 70, 70), 0.0)
bad = Image.blend(ImageEnhance.Color(logo).enhance(0.55), Image.new("RGBA", logo.size, (255, 60, 60, 255)), 0.28)
bad.putalpha(logo.split()[3])
d = ImageDraw.Draw(bad)
d.ellipse((140, 26, 190, 76), fill=(235, 55, 55, 255), outline=(255, 255, 255, 255), width=4)
d.text((165, 52), "!", font=ImageFont.truetype(FONT, 38), fill=(255, 255, 255, 255), anchor="mm")
bad.save("assets/logo_bad.png")

# ---- tray icons (32x32): teapot close-up + status dot
S = 4 * 32  # draw large, then shrink
def tray(state, dot):
    crop = logo.crop((52, 8, 182, 138)).resize((S, S), Image.LANCZOS)
    if state == "off":
        crop = ImageEnhance.Brightness(ImageEnhance.Color(crop).enhance(0.0)).enhance(0.8)
    elif state == "bad":
        crop = Image.blend(ImageEnhance.Color(crop).enhance(0.6), Image.new("RGBA", crop.size, (255, 60, 60, 255)), 0.25)
    bg = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    bg.paste(crop, (0, 0), circle_mask(S))
    d = ImageDraw.Draw(bg)
    r = int(S * 0.20)
    cx, cy = S - r - 2, S - r - 2
    d.ellipse((cx - r - 7, cy - r - 7, cx + r + 7, cy + r + 7), fill=(12, 16, 20, 255))
    d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=dot)
    if state == "bad":
        d.text((cx, cy - 2), "!", font=ImageFont.truetype(FONT, int(r * 1.7)), fill=(255, 255, 255, 255), anchor="mm")
    return bg.resize((32, 32), Image.LANCZOS)

tray("on", (45, 212, 167, 255)).save("assets/tray_on.png")
tray("off", (140, 150, 160, 255)).save("assets/tray_off.png")
tray("bad", (240, 80, 80, 255)).save("assets/tray_bad.png")
tray("starting", (245, 184, 74, 255)).save("assets/tray_start.png")
