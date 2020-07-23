## MQT-TZ: TrustZone Enabled MQTT Broker

MQT-TZ is a project aimed at hardening IoT gateways using TrustZone.
A detailed project description can be read from the different publications where it appears:
+ [MQT-TZ: Secure MQTT Broker for Biomedical Signal Processing on the Edge](https://arxiv.org/abs/2007.01555), as it appeared in the 2020 Medical Informatics Europe
Conference (MIE2020). You can cite it using the bibtex below:
```
@article{Segarra2020MQTTZ-MIE,
  author = {Segarra, Carlos and Delgado-Gonzalo, Ricard and Schiavoni, Valerio},
  year = {2020},
  month = {06},
  pages = {332-336},
  title = {MQT-TZ: Secure MQTT Broker for Biomedical Signal Processing on the Edge},
  volume = {270},
  journal = {Studies in health technology and informatics},
  doi = {10.3233/SHTI200177}
}
```
+ [MQT-TZ: Hardening IoT Brokers Using ARM TrustZone](broken), as it appeared in the proceedings of the 2020 39th International Symposium on Reliable Distributed Systems (SRDS 2020). You can cite it using the bibtex below:
```
@inproceedings{Segarra2020MQTTZ-SRDS,
  author={C. {Segarra}, and R. {Delgado-Gonzalo}, and V. {Schiavoni}},
  booktitle={2020 39th Symposium on Reliable Distributed Systems (SRDS)}, 
  title={MQT-TZ: Hardening IoT Brokers Using ARM TrustZone}, 
  year={2020},
  volume={},
  number={},
  pages={}
}
```

Navigating the [GitHub organization](https://github.com/mqttz) you will see the different building blocks of the project.
+ [Fork of the `mosquitto` MQTT client and broker](https://github.com/mqttz/mqttz)
+ [Trusted Applications for TrustZone and Op-TEE: MQT-TZ specific and Benchmarking Oriented](https://github.com/mqttz/optee-apps)
+ [Running a TLS-enabled MQTT Broker](https://github.com/mqttz/mqttz-conf)

-----

This repository is a fork of Eclipse's `mosquitto` MQTT broker: https://github.com/eclipse/mosquitto
It includes some additional callbacks to integrate within the MQT-TZ system.

To build it, we refer to the instructions in the original repo, as we don't include any additional dependencies.
