# imghdr.py – Compatibilidad para Python 3.13+
# Fuente simplificada basada en el módulo original

def what(file, h=None):
    if h is None:
        if hasattr(file, 'read'):
            pos = file.tell()
            h = file.read(32)
            file.seek(pos)
        else:
            with open(file, 'rb') as f:
                h = f.read(32)

    if h.startswith(b'\xff\xd8'):
        return 'jpeg'
    if h[:8] == b'\x89PNG\r\n\x1a\n':
        return 'png'
    if h[:6] in (b'GIF87a', b'GIF89a'):
        return 'gif'
    if h[:2] == b'BM':
        return 'bmp'
    if h[:4] == b'\x00\x00\x01\x00':
        return 'ico'
    if h[:4] == b'RIFF' and h[8:12] == b'WEBP':
        return 'webp'

    return None
