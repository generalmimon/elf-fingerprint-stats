to_entries | map((.value.common_features.[]?, .value.elfs.[].[]) |= length)
