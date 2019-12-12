import pathlib
import click
import json
import collections
import numpy as np
import h5py
import time
import scipy.interpolate
import subprocess
from random import randint

class MQTTZPublisherPool():
    #def __init__(self, host='127.0.0.1', port=1889):
    def __init__(self, host='192.168.1.57', port=1883):
        self.port = port
        self.host = host
        self.command = "./mosquitto_pub -h {} -p {} -t {} -m"
        self.id = ''.join(["%s" % randint(0, 9) for num in range(0, 3)])
        self.topic = "mqttz/ecg/{}".format(self.id)

    def publish_results(self, topic, time, value):
        payload = self._mqttz_encode_payload(time, value)
        num_pub = 50
        if topic == 'mqttz/ecg':
            for i in range(num_pub):
                n_topic = 'mqttz/ecg/{}'.format(i)
                cmd = self.command.format(self.host, self.port,
                                          n_topic).split(' ')
                cmd.append("'{}'".format(payload))
                proc = subprocess.Popen(cmd)
                proc.wait()
                proc.kill()
                #print(cmd)

    @staticmethod
    def _mqttz_encode_payload(time, value):
        if isinstance(value, np.ndarray):
            values = np.array(value).astype(float).tolist()
        else:
            values = [float(value)]
        return json.dumps([[int(time), values]])
        #return json.dumps([[int(time), values]]).encode('utf8')
        

@click.group()
def cli():
    """Utility to replay HRV features."""
    pass


def hdfsigs2dict(hdfsigs):
    data = dict()
    for k in hdfsigs.keys():
        if str(type(hdfsigs[k])).__contains__('Group'):
            tmp = hdfsigs2dict(hdfsigs[k])
            for kk in tmp.keys():
                data[k + '/' + kk] = tmp[kk]
        else:
            data[k] = collections.deque(hdfsigs[k][()])
            data[k].popleft()
    return data

def create_fake_hrv_signals(ramp_length = 1E3, fs = 1.0):
    values = np.linspace(0, 1, ramp_length)
    values = np.concatenate((values, np.flip(values)))
    time = np.arange(0, len(values)) / fs * 1E3
    keys = ['hf', 'lf', 'lf_hf', 'hr', 'rmssd', 'sdnn']

    data = dict()
    for k in keys:
        data['computed/' + k] = collections.deque([(time[i], values[i])
                                             for i, v in enumerate(time)])

    return data


@cli.command()
# @click.option('-v', '--verbose', count=True, help='Increase verbosity level.')
@click.argument('source_file', type=click.Path(exists=True))
                # help='HDF5 file containing the recorded data to replay.')
@click.option('--speedup', default=1.0, help='Replay speedup factor.')
@click.option('--mode', required=False, default='sense+hrv',
              type=click.Choice(['sense', 'hrv', 'fakehrv', 'sense+hrv']))
@click.option('--loops', default=1, help='Number of loops (inf is endless).')
# @click.option('--date', help='Date/recording to replay.') # todo add this
@click.option('--tstart2skip', default=0.0, help='Time (in seconds) of '
                                                 'beginning to skip.')
def replay(source_file, speedup, mode, loops, tstart2skip):

    if mode is not 'fakehrv':
        fhdf = h5py.File(source_file, 'r')

        ks = sorted(fhdf.keys())
        k1 = ks[0]  # TODO: verify that we're taking the newest here!
        ks = sorted(fhdf[k1].keys())
        k2 = ks[0]  # TODO: verify that we're taking the newest here!

        # sense signals (not HRV)
        data = hdfsigs2dict(fhdf[k1][k2]['sense'])
        # data.pop('computed')
        # # HRV signals only
        # data = data['computed'])

        # related adapter-sense time (cpu-time) to sense r-time to align HRV
        # to rest of signals
        t_stream = [x[0] for x in data['rtime']]
        t_rtime = [x[1] for x in data['rtime']]
        f_int = scipy.interpolate.interp1d(t_rtime, t_stream)
        for k in data.keys():
            if 'computed' in k:
                for i, v in enumerate(data[k]):
                    data[k][i][0] = f_int(data[k][i][0])

    if mode == 'sense+hrv':
        pass
    if mode == 'sense':
        data = {k: v for k, v in data.items() if 'computed' not in k}
    elif mode == 'hrv':
        data = {k: v for k, v in data.items() if 'computed' in k}
    elif mode == 'fakehrv':
        data = create_fake_hrv_signals()

    t_start_cpu = time.time()
    if 'ecg' in data.keys():
        t_start_sense = data['ecg'][0][0]
    else:
        t_start_sense = np.min([v[0][0] for k, v in data.items()])
    t_start_sense += tstart2skip*1E3
    for k in data.keys():
        while data[k][0][0] < t_start_sense:
            data[k].popleft()
            if len(data[k]) <= 0:
                break
    data_original = data     # store backup to restore when looping

    mqttz_pub = MQTTZPublisherPool()

    while np.any([len(data[k]) >= 0 for k in data.keys()]):

        tdiff_cpu = time.time() - t_start_cpu

        for k in data.keys():
            if len(data[k]) > 0:
                tdiff_sense = (data[k][0][0] - t_start_sense)/1E3/speedup
                time2next = tdiff_sense - tdiff_cpu

                if time2next <= 0:
                    topic = 'mqttz/' + k
                    mqttz_pub.publish_results(topic, data[k][0][0],
                            data[k][0][1])
                    data[k].popleft()

        if np.all([len(data[k]) == 0 for k in data.keys()]) & (loops > 0):
            # start another replay loop
            data = data_original
            t_start_cpu = time.time()
            loops -= 1

        time.sleep(0.01)

    print('done replaying!')




if __name__ == '__main__':
    cli()
