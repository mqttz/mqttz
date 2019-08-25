#!/usr/bin/python3
from multiprocessing import Process, Pool, Array
#from threading import Thread
import subprocess
import signal
import sys
import time

port = 1889
topic = 'jeje'
msg = 'mama'
MAGIC_MSG = "MQT-TZ: Done!\n"
NUM_EXPERIMENTS = 100

def publish_mqttz(times):
    for i in range(NUM_EXPERIMENTS):
        command = "./mosquitto_pub -p {} -t {} -m {}".format(port, topic, msg)
        times.append(time.time())
        proc = subprocess.Popen(command.split(' '))
        proc.wait()
        proc.kill()
        print("Finished publishing!")
        time.sleep(3)

def subscribe_mqttz(times):
    # print("Do I still know what I am doing?")
    command = "./mosquitto_sub -p {} -t {}".format(port, topic)
    proc = subprocess.Popen(command.split(' '), stdout=subprocess.PIPE)
    count = 0
    try:
        for line in iter(proc.stdout.readline,''):
            try:
                if (line.decode('utf-8') == MAGIC_MSG):
                    print("Yeah!")
                    #print(line.decode('utf-8'))
                    count += 1
                    times.append(time.time())
                    print(count)
                if (count == NUM_EXPERIMENTS):
                    print("We done!")
                    proc.kill()
                    break
            except UnicodeDecodeError:
                continue
            except FileNotFoundError:
                print("{} file does not exist!")
                sys.exit(0)
    except KeyboardInterrupt:
        proc.kill()
        print("Bye!")
        return

def process_times(mode, times):
    file_name = "times/{}.dat".format(mode)
    with open(file_name, "w") as f:
        for t in times:
            f.write("{}\n".format(str(t)))


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)
    times = []
    try:
        mode = sys.argv[1]
    except IndexError:
        print("Haven't provided enough arguments!")
        sys.exit(0)
    if (mode == "mqttz-sub"):
        subscribe_mqttz(times)
    elif (mode == "mqttz-pub"):
        publish_mqttz(times)
    else:
        print("{} mode has not been implemented yet!")
        sys.exit(0)
    process_times(mode, times)

