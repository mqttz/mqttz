#!/usr/bin/python3
from multiprocessing import Process, Pool, Array
#from threading import Thread
import subprocess
import signal
import sys
import time

host = 127.0.0.1
port = 1889

def subscribe_mqtt(num = 50):
    # print("Do I still know what I am doing?")
    command = "./mosquitto_sub -h {} -p {} -t {}".format(host, port, topic)
    proc = [subprocess.Popen(command.split(' ')) for _ in range(num)]
    while True:
        try:
            time.sleep(3)
        except KeyboardInterrupt:
            proc.kill()
            print("Bye!")
            return

if __name__ == "__main__":
    subscribe_mqtt()
