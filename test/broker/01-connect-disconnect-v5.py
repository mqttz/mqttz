#!/usr/bin/env python3

# loop through the different v5 DISCONNECT reason_code/properties options.

from mosq_test_helper import *

def disco_test(test, disconnect_packet):
    global rc

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    sock.send(disconnect_packet)
    sock.close()
    rc -= 1


rc = 4
keepalive = 10
connect_packet = mosq_test.gen_connect("connect-disconnect-test", proto_ver=5, keepalive=keepalive)
connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

port = mosq_test.get_port()
broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)


try:
    # No reason code, no properties, len=0
    disconnect_packet = mosq_test.gen_disconnect(proto_ver=5)
    disco_test("disco len=0", disconnect_packet)

    # Reason code, no properties, len=1
    disconnect_packet = mosq_test.gen_disconnect(proto_ver=5, reason_code=0)
    disco_test("disco len=1", disconnect_packet)

    # Reason code, empty properties, len=2
    disconnect_packet = mosq_test.gen_disconnect(proto_ver=5, reason_code=0, properties="")
    disco_test("disco len=2", disconnect_packet)

    # Reason code, one property, len>2
    props = mqtt5_props.gen_string_pair_prop(mqtt5_props.PROP_USER_PROPERTY, "key", "value")
    disconnect_packet = mosq_test.gen_disconnect(proto_ver=5, reason_code=0, properties=props)
    disco_test("disco len>2", disconnect_packet)
finally:
    broker.terminate()
    broker.wait()
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde.decode('utf-8'))

if rc != 0:
    print(test)
    exit(rc)
