## MQT-TZ: TrustZone Enabled MQTT Broker

MQT-TZ is a project aimed at hardening IoT gateways using TrustZone.
A detailed project description can be read from the different publications where it appears:
+ [MQT-TZ: Secure MQTT Broker for Biomedical Signal Processing on the Edge](https://arxiv.org/abs/2007.01555).
+ [MQT-TZ: Hardening IoT Brokers Using ARM TrustZone](broken)

Navigating the [GitHub organization](https://github.com/mqttz) you will see the different building blocks of the project.
+ [Fork of the `mosquitto` MQTT client and broker](https://github.com/mqttz/mqttz)
+ [Trusted Applications for TrustZone and Op-TEE: MQT-TZ specific and Benchmarking Oriented](https://github.com/mqttz/optee-apps)
+ [Running a TLS-enabled MQTT Broker](https://github.com/mqttz/mqttz-conf)

-----

This repository is a fork of Eclipse's `mosquitto` MQTT broker: https://github.com/eclipse/mosquitto
It includes some additional callbacks to integrate within the MQT-TZ system.

To build it, we refer to the instructions in the original repo, as we don't include any additional dependencies.
