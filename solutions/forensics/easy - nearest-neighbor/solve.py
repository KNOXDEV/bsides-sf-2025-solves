#!/usr/bin/env python3

from wand.image import Image

with Image(filename="./src/distfiles/flag.webp") as img:
    # this doesn't work, no idea why
    # img.sample(img.width // 16, img.height // 16)

    img.resize(img.width // 16, img.height // 16, filter='point')

    img.save(filename="./flag_small.png")