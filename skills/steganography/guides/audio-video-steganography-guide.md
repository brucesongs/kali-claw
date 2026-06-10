# Audio and Video Steganography Techniques Guide

## Introduction

Audio and video steganography hides secret data within multimedia files by exploiting human perceptual limitations and media codec characteristics. Unlike image steganography, audio and video provide larger embedding capacities and additional hiding mechanisms through temporal, spectral, and compression domain manipulation. This guide covers LSB audio encoding, spectrogram embedding, video frame manipulation, and codec-specific techniques used in modern steganographic workflows.

Audio steganography leverages the psychoacoustic model — humans cannot perceive subtle changes in audio amplitude or frequency below certain thresholds. Video steganography extends this by providing temporal dimension (hiding data across frames) and spatial dimension (hiding data within individual frames). Understanding these techniques is essential for both embedding hidden data and detecting steganographic content in forensic investigations.

## Practical Steps

### 1. LSB Audio Steganography with WAV Files

```bash
# Embed secret message in WAV audio using LSB encoding
python3 -c "
import wave
import struct

def encode_audio_lsb(carrier_wav, message, output_wav):
    with wave.open(carrier_wav, 'rb') as w:
        params = w.getparams()
        frames = bytearray(w.readframes(params.nframes))

    # Convert message to binary
    binary_msg = ''.join(format(b, '08b') for b in message.encode() + b'\x00')

    if len(binary_msg) > len(frames):
        print('ERROR: Message too long for carrier')
        return

    # Embed bits in LSB of each audio sample
    for i, bit in enumerate(binary_msg):
        frames[i] = (frames[i] & 0xFE) | int(bit)

    with wave.open(output_wav, 'wb') as w:
        w.setparams(params)
        w.writeframes(bytes(frames))
    print(f'Encoded {len(message)} bytes into {output_wav}')

encode_audio_lsb('carrier.wav', 'Secret message hidden in audio', 'stego_audio.wav')
```

### 2. Audio LSB Decoding

```bash
# Extract hidden message from LSB-encoded WAV
python3 -c "
import wave

def decode_audio_lsb(stego_wav):
    with wave.open(stego_wav, 'rb') as w:
        frames = w.readframes(w.getnframes())

    bits = []
    for byte in frames:
        bits.append(str(byte & 1))

    # Group into bytes and decode
    message = []
    for i in range(0, len(bits) - 7, 8):
        byte_val = int(''.join(bits[i:i+8]), 2)
        if byte_val == 0:  # null terminator
            break
        message.append(chr(byte_val))

    decoded = ''.join(message)
    print(f'Decoded message: {decoded}')
    return decoded

decode_audio_lsb('stego_audio.wav')
"
```

### 3. Spectrogram Image Embedding

```bash
# Hide an image in audio spectrogram (visual steganography)
ffmpeg -i input_audio.wav -lavfi "showspectrumpic=s=1920x1080:mode=separate" spectrogram_before.png 2>/dev/null

# Create a spectrogram with hidden image using Python
python3 -c "
import numpy as np
from PIL import Image

# Load secret image to embed in spectrogram
secret = Image.open('secret_image.png').convert('L')
secret_array = np.array(secret)

# Create synthetic audio that produces the image as spectrogram
# Map pixel intensity to frequency amplitude
sample_rate = 44100
duration = len(secret_array)  # each row = one time slice
freqs = np.linspace(100, 8000, secret_array.shape[1])

audio = np.zeros(duration * sample_rate // duration)
for t in range(duration):
    for f_idx, freq in enumerate(freqs):
        amplitude = secret_array[t, f_idx] / 255.0
        phase = np.random.random() * 2 * np.pi
        t_samples = np.arange(sample_rate // duration)
        audio_segment = amplitude * np.sin(2 * np.pi * freq * t_samples / sample_rate + phase)
        start = t * (sample_rate // duration)
        end = start + len(audio_segment)
        if end <= len(audio):
            audio[start:end] += audio_segment

# Normalize and save
audio = (audio / np.max(np.abs(audio)) * 32767).astype(np.int16)
print(f'Generated spectrogram audio: {len(audio)} samples')
print('When viewed as spectrogram, the secret image is revealed')
"
```

### 4. Video Frame Steganography

```bash
# Embed data across video frames using frame-level LSB
python3 -c "
import struct

def calculate_capacity(video_path, frame_count=300, width=1920, height=1080):
    '''Calculate how much data can be hidden in a video.'''
    pixels_per_frame = width * height * 3  # RGB
    bits_per_frame = pixels_per_frame  # 1 bit per channel LSB
    total_bits = bits_per_frame * frame_count
    total_bytes = total_bits // 8
    print(f'Video capacity ({frame_count} frames at {width}x{height}):')
    print(f'  Pixels per frame: {pixels_per_frame:,}')
    print(f'  Bits per frame:   {bits_per_frame:,}')
    print(f'  Total capacity:   {total_bytes:,} bytes ({total_bytes/1024/1024:.1f} MB)')

calculate_capacity('video.mp4')
"
```

### 5. MP3/Steganographic Encoding with MP3Stego

```bash
# Hide data in MP3 compression artifacts using MP3Stego
# Encode secret message into MP3 file
encode -E secret_message.txt -P password cover_audio.wav stego_audio.mp3

# Decode hidden message from MP3
decode -X -P password stego_audio.mp3

# Verify file sizes are similar (detection avoidance)
ls -la cover_audio.wav stego_audio.mp3
```

### 6. Video Codec Manipulation

```bash
# Extract and manipulate video frames for steganographic embedding
ffmpeg -i input_video.mp4 -vf "select=eq(n\,0)" -frames:v 1 frame_000.png 2>/dev/null

# Batch extract keyframes
mkdir -p frames/
ffmpeg -i input_video.mp4 -vf "select=eq(pict_type\,I)" -vsync vfr frames/frame_%03d.png 2>/dev/null

# Embed data in specific frames and reassemble
python3 -c "
# Strategy: modify every Nth I-frame to avoid detection
import os

frames_dir = 'frames/'
frames = sorted([f for f in os.listdir(frames_dir) if f.endswith('.png')])
print(f'Extracted {len(frames)} I-frames')
print(f'Embedding in every 10th frame for stealth:')

for i, frame in enumerate(frames):
    if i % 10 == 0:
        print(f'  Embedding in {frame}')
    else:
        print(f'  Skipping {frame}')

print(f'Total frames for embedding: {len(frames) // 10}')
print(f'Reassemble: ffmpeg -framerate 30 -i frames/frame_%03d.png -c:v libx264 output.mp4')
"
```

### 7. Echo Hiding in Audio

```bash
# Echo hiding technique for audio steganography
python3 -c "
import numpy as np

def echo_hide(audio signal, message_bits, d0=100, d1=200, decay=0.5):
    '''Hide data using echo delays. Bit 0 = delay d0, Bit 1 = delay d1.'''
    samples_per_bit = len(audio_signal) // max(len(message_bits), 1)
    result = np.copy(audio_signal).astype(float)

    for i, bit in enumerate(message_bits):
        delay = d1 if bit == '1' else d0
        start = i * samples_per_bit
        end = min(start + samples_per_bit, len(result))

        # Add echo with appropriate delay
        echo_start = min(start + delay, len(result))
        if echo_start < end:
            segment_len = end - echo_start
            result[echo_start:end] += decay * result[start:start + segment_len]

    return result

# Generate test signal
sample_rate = 44100
duration = 5
t = np.linspace(0, duration, sample_rate * duration)
test_signal = 0.5 * np.sin(2 * np.pi * 440 * t)

# Embed binary message
message = '10110'
stego_signal = echo_hide(test_signal, message)
print(f'Embedded {len(message)} bits using echo hiding')
print(f'Signal length: {len(stego_signal)} samples')
"
```

## Hands-on Exercises

### Exercise 1: Audio LSB Encoding and Decoding

Create a WAV file with a hidden message using LSB encoding. Have a partner attempt to extract the message without knowing the encoding method or message length. Document the signal-to-noise ratio and detectability.

### Exercise 2: Spectrogram Image Challenge

Embed a small image into an audio file's spectrogram. Verify the image is visible when viewed with a spectrogram tool. Experiment with different frequency ranges to optimize visibility while maintaining audio quality.

## References

- MP3Stego Tool — https://www.petitcolas.net/steganography/mp3stego/
- FFmpeg Documentation — https://ffmpeg.org/documentation.html
- Steganography in Digital Media — Fridrich, J. (2009)
- Audio Steganography Survey — IEEE Signal Processing Magazine
