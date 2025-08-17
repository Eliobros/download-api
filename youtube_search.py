import sys
import json
import yt_dlp

query = sys.argv[1]

opts = {
    'quiet': True,
    'extract_flat': True,
    'skip_download': True,
}

with yt_dlp.YoutubeDL(opts) as ydl:
    try:
        search_query = f"ytsearch5:{query}"
        info = ydl.extract_info(search_query, download=False)
        results = info.get('entries', [])
        if not results:
            print(json.dumps({"error": "Nenhum resultado encontrado"}))
            sys.exit(0)
        videos = []
        for v in results:
            videos.append({
                "title": v.get("title"),
                "channel": v.get("uploader"),
                "id": v.get("id"),
                "url": v.get("url"),
                "views": v.get("view_count"),
                "thumbnail": v.get("thumbnail"),
                "description": v.get("description")
            })
        print(json.dumps(videos))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
