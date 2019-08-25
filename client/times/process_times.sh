#!/bin/bash
paste -d' ' mqttz-sub.dat mqttz-pub.dat | awk '{$3 = $1 - $2} 1' | awk '{print $3}' > mqttz-times.dat
