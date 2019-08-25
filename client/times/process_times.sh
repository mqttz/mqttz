#!/bin/bash
paste -d' ' mqttz-sub.dat mqttz-pub.dat | awk '{$3 = $2 - $1} 1' | awk '{print $3}' > mqttz-times.dat
