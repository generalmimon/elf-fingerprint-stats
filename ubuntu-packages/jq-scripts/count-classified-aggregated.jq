del(.["$comment"])
| .[].[] |= length
| {total: (reduce (.[] | to_entries[]) as {$key, $value} ({}; .[$key] += $value)), absolute: .}
| .total as $total
| .["relative"] = (.absolute | .[] |= with_entries(.value /= $total[.key]))
