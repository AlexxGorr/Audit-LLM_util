def format_size(size_bytes):
    if size_bytes < 1024:
        return f'{size_bytes} B'

    units = ["KB", "MB", "GB", "TB", "PB"]
    size = size_bytes / 1024
    unit_index = 0

    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1

    return f'{size:.1f} {units[unit_index]}'














