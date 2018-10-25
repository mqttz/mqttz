#!/usr/bin/env python

# Test whether a client subscribed to a topic receives its own message sent to that topic.
# Does the Payload Format Indicator property get sent through?
# MQTT v5

import inspect, os, sys
# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"..")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import mosq_test
import mqtt5_props

rc = 1
mid = 53
keepalive = 60
connect_packet = mosq_test.gen_connect("subpub-qos0-test", keepalive=keepalive, proto_ver=5)
connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

subscribe_packet = mosq_test.gen_subscribe(mid, "subpub/qos0", 0, proto_ver=5)
suback_packet = mosq_test.gen_suback(mid, 0, proto_ver=5)

props = mqtt5_props.gen_byte_prop(mqtt5_props.PROP_PAYLOAD_FORMAT_INDICATOR, 0xed)
props = props+mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_TOPIC_ALIAS, 1)
props = mqtt5_props.prop_finalise(props)
publish_packet_out = mosq_test.gen_publish("subpub/qos0", qos=0, payload="message", proto_ver=5, properties=props)

props = mqtt5_props.gen_byte_prop(mqtt5_props.PROP_PAYLOAD_FORMAT_INDICATOR, 0xed)
props = mqtt5_props.prop_finalise(props)
publish_packet_expected = mosq_test.gen_publish("subpub/qos0", qos=0, payload="message", proto_ver=5, properties=props)

port = mosq_test.get_port()
broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

try:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)

    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
    mosq_test.do_send_receive(sock, publish_packet_out, publish_packet_expected, "publish")

    rc = 0

    sock.close()
finally:
    broker.terminate()
    broker.wait()
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde)

exit(rc)

