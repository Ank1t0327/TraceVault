import datetime

def webkit_to_datetime(webkit_timestamp):
    """Convert WebKit/Chrome timestamp (microseconds since Jan 1, 1601) to datetime."""
    if not webkit_timestamp:
        return None
    try:
        # 11644473600 is seconds between 1601-01-01 and 1970-01-01
        epoch_start = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        return epoch_start + datetime.timedelta(microseconds=int(webkit_timestamp))
    except (ValueError, OverflowError, TypeError):
        return None

def format_time_short(dt):
    """Format datetime object as HH:MM string."""
    if isinstance(dt, datetime.datetime):
        return dt.strftime("%H:%M")
    return "00:00"
