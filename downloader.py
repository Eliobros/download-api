import sys
import json
import os
import yt_dlp

url = sys.argv[1]
download_type = sys.argv[2]

if not os.path.exists('downloads'):
    os.makedirs('downloads')

if "soundcloud.com" in url and download_type != "audio":
    print(json.dumps({"error": "SoundCloud só suporta áudio."}))
    sys.exit()

class MyLogger(object):
    def debug(self, msg):
        pass
    def warning(self, msg):
        pass
    def error(self, msg):
        print(msg, file=sys.stderr)

ydl_opts = {
    'quiet': True,
    'no_warnings': True,
    'logger': MyLogger(),
    'outtmpl': 'downloads/%(title)s.%(ext)s',
}

if download_type == "audio":
    ydl_opts['format'] = 'bestaudio/best'
    ydl_opts['postprocessors'] = [{
        'key': 'FFmpegExtractAudio',
        'preferredcodec': 'mp3',
        'preferredquality': '192',
    }]
else:
    ydl_opts['format'] = 'best'

try:
    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        info = ydl.extract_info(url, download=True)
        filename = ydl.prepare_filename(info)
        result = {
            "title": info.get("title"),
            "uploader": info.get("uploader"),
            "duration": info.get("duration"),
            "webpage_url": info.get("webpage_url"),
            "filename": filename
        }
        print(json.dumps(result))
except Exception as e:
    print(json.dumps({"error": str(e)}))
