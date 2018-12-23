#!/usr/bin/env python

# Do subscription identifiers work as expected?
# MQTT v5

from mosq_test_helper import *

rc = 1
keepalive = 60
connect_packet = mosq_test.gen_connect("subpub-test", keepalive=keepalive, proto_ver=5)
connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

mid = 1
props = mqtt5_props.gen_varint_prop(mqtt5_props.PROP_SUBSCRIPTION_IDENTIFIER, 1)
props = mqtt5_props.prop_finalise(props)
subscribe1_packet = mosq_test.gen_subscribe(mid, "subpub/id1", 0, proto_ver=5, properties=props)
suback1_packet = mosq_test.gen_suback(mid, 0, proto_ver=5)

mid = 2
props = mqtt5_props.gen_varint_prop(mqtt5_props.PROP_SUBSCRIPTION_IDENTIFIER, 14)
props = mqtt5_props.prop_finalise(props)
subscribe2_packet = mosq_test.gen_subscribe(mid, "subpub/+/id2", 0, proto_ver=5, properties=props)
suback2_packet = mosq_test.gen_suback(mid, 0, proto_ver=5)

mid = 3
subscribe3_packet = mosq_test.gen_subscribe(mid, "subpub/noid", 0, proto_ver=5)
suback3_packet = mosq_test.gen_suback(mid, 0, proto_ver=5)

publish1_packet = mosq_test.gen_publish("subpub/id1", qos=0, payload="message1", proto_ver=5)

props = mqtt5_props.gen_varint_prop(mqtt5_props.PROP_SUBSCRIPTION_IDENTIFIER, 1)
props = mqtt5_props.prop_finalise(props)
publish1r_packet = mosq_test.gen_publish("subpub/id1", qos=0, payload="message1", proto_ver=5, properties=props)

publish2_packet = mosq_test.gen_publish("subpub/test/id2", qos=0, payload="message2", proto_ver=5)
props = mqtt5_props.gen_varint_prop(mqtt5_props.PROP_SUBSCRIPTION_IDENTIFIER, 14)
props = mqtt5_props.prop_finalise(props)
publish2r_packet = mosq_test.gen_publish("subpub/test/id2", qos=0, payload="message2", proto_ver=5, properties=props)

publish3_packet = mosq_test.gen_publish("subpub/noid", qos=0, payload="message3", proto_ver=5)


port = mosq_test.get_port()
broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

try:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)

    mosq_test.do_send_receive(sock, subscribe1_packet, suback1_packet, "suback1")
    mosq_test.do_send_receive(sock, subscribe2_packet, suback2_packet, "suback2")
    mosq_test.do_send_receive(sock, subscribe3_packet, suback3_packet, "suback3")

    mosq_test.do_send_receive(sock, publish3_packet, publish3_packet, "publish3")
    mosq_test.do_send_receive(sock, publish2_packet, publish2r_packet, "publish2")
    mosq_test.do_send_receive(sock, publish1_packet, publish1r_packet, "publish1")

    rc = 0

    sock.close()
finally:
    broker.terminate()
    broker.wait()
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde)

exit(rc)

