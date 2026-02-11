#!/usr/bin/env python3

from wand.image import Image
import numpy

with open("./src/distfiles/flags.r16", mode="rb") as file:
    filebytes = file.read()

# first 18 bytes seems to be a header rather than image data
header = filebytes[:18]
filebytes = filebytes[18:]

data = numpy.frombuffer(filebytes, numpy.uint16)

# guessed this via trial and error, but its probably in the header
width = 600
height = len(data) // width
data = numpy.reshape(data, (width, height))

with Image.from_array(data) as img:
    img.save(filename="./result.png")