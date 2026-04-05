import os
import datetime
import filetype

def extract_metadata(file_path):
    """Extract basic metadata from a file."""
    if not os.path.exists(file_path):
        return {"error": "File not found"}
        
    stat_info = os.stat(file_path)
    
    # Try to guess file type
    kind = filetype.guess(file_path)
    mime = kind.mime if kind else "unknown"
    ext = kind.extension if kind else os.path.splitext(file_path)[1].lstrip('.')
    
    try:
        ctime = datetime.datetime.fromtimestamp(stat_info.st_ctime).isoformat()
        mtime = datetime.datetime.fromtimestamp(stat_info.st_mtime).isoformat()
    except OSError:
        ctime = "Unknown"
        mtime = "Unknown"
    
    return {
        "filename": os.path.basename(file_path),
        "size_bytes": stat_info.st_size,
        "created": ctime,
        "modified": mtime,
        "mime_type": mime,
        "extension": ext
    }
