"""
generate_icons.py - Generates red, black, and white PhishXcape extension icons
Creates:
- extension/icons/icon16.png
- extension/icons/icon48.png
- extension/icons/icon128.png
"""

import os
from PIL import Image, ImageDraw

ICONS_DIR = os.path.dirname(__file__)

def create_shield_icon(size):
    # Create image with transparent background (RGBA)
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    pad = max(1, int(size * 0.08))
    w = size - 2 * pad
    h = size - 2 * pad

    # Outer Shield boundary polygon
    # Points normalized to [0, 1]
    raw_pts = [
        (0.5, 0.05), # top tip
        (0.92, 0.22), # top right
        (0.92, 0.55), # right mid
        (0.5, 0.95), # bottom point
        (0.08, 0.55), # left mid
        (0.08, 0.22), # top left
    ]

    shield_pts = [(pad + pt[0] * w, pad + pt[1] * h) for pt in raw_pts]

    # Draw dark background shield
    draw.polygon(shield_pts, fill=(11, 11, 15, 255), outline=(229, 9, 20, 255), width=max(1, int(size * 0.06)))

    # Draw inner red accent
    inner_pad = max(2, int(size * 0.18))
    iw = size - 2 * inner_pad
    ih = size - 2 * inner_pad
    inner_pts = [(inner_pad + pt[0] * iw, inner_pad + pt[1] * ih) for pt in raw_pts]
    draw.polygon(inner_pts, fill=(229, 9, 20, 230), outline=(255, 255, 255, 255), width=max(1, int(size * 0.03)))

    # Draw exclamation mark or security cross in white
    cx = size / 2.0
    cy = size * 0.45
    r = max(1.5, size * 0.06)
    
    # Exclamation top bar
    bar_w = max(1.5, size * 0.06)
    top_y = size * 0.30
    bot_y = size * 0.54
    draw.line([(cx, top_y), (cx, bot_y)], fill=(255, 255, 255, 255), width=int(bar_w))
    
    # Exclamation dot
    dot_y = size * 0.65
    draw.ellipse([(cx - r, dot_y - r), (cx + r, dot_y + r)], fill=(255, 255, 255, 255))

    out_path = os.path.join(ICONS_DIR, f"icon{size}.png")
    img.save(out_path, "PNG")
    print(f"[+] Created {out_path}")

if __name__ == "__main__":
    for s in [16, 48, 128]:
        create_shield_icon(s)
