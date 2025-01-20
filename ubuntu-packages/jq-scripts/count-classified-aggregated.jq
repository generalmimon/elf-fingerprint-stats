del(.["$comment"])
| .[].[] |= length
| map_values(.total = (. | add))
| {absolute: ., relative: map_values(.total as $total | map_values(. / $total))}
