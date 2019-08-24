#!/usr/bin/python3
from multiprocessing import Process, Pool, Array
#from threading import Thread
import subprocess
import signal
import sys
import time

port = 1887
topic = 'jeje'
msg = 'mama'
MAGIC_MSG = "MQT-TZ: Done!\n"
NUM_EXPERIMENTS = 2

def publish_mqttz():
    times = [0,0]
    for i in range(NUM_EXPERIMENTS):
        command = "./mosquitto_pub -p {} -t {} -m {}".format(port, topic, msg)
        proc = subprocess.Popen(command.split(' '))
        proc.wait()
        times[i] = time.time()
        proc.kill()
        print("Finished publishing!")
        time.sleep(3)

def subscribe_mqttz():
    # print("Do I still know what I am doing?")
    times = [0,0]
    command = "./mosquitto_sub -p {} -t {}".format(port, topic)
    proc = subprocess.Popen(command.split(' '), stdout=subprocess.PIPE)
    count = 0
    try:
        for line in iter(proc.stdout.readline,''):
            try:
                if (line.decode('utf-8') == MAGIC_MSG):
                    print("Yeah!")
                    count += 1
                    times[i] = time.time()
                    print(count)
                if (count == NUM_EXPERIMENTS):
                    print("We done!")
                    proc.kill()
                    break
            except UnicodeDecodeError:
                continue
    except KeyboardInterrupt:
        proc.kill()
        print("Bye!")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)
#    Thread(target = publish_mqttz).start()
#    Thread(target = subscribe_mqttz).start()
#    pub_times = [] #Array('i', NUM_EXPERIMENTS)
#    sub_times = [] #Array('i', NUM_EXPERIMENTS)
    subscriber = Process(target = subscribe_mqttz)
    subscriber.start()
    time.sleep(1)
    publisher = Process(target = publish_mqttz)
    publisher.start()
    subscriber.join()
    publisher.join()
#    print(pub_times[:])
#    print(sub_times[:])
#    with Pool(processes = 2) as pool:
#        pool.apply_async(subscribe_mqttz)
#        pool.apply_async(publish_mqttz)
