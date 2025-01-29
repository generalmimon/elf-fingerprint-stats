map(to_entries | map(select(.key != "elfs").value |= length) | from_entries)
