# Docker Images 

This directory contains Docker files for Mosquitto.

The `1.4` and `1.5` directories contain the latest version of Mosquitto for
those releases, and provide the basis of the official images.

`1.4.12` is the version using Alpine packaged Mosquitto, which will be removed
at the next minor release.

The `generic` directory contains a generic Dockerfile that can be used to build
arbitrary versions of Mosquitto based on the released tarballs as follows:

```
cd generic
docker build -t eclipse-mosquitto:1.5.1 --build-arg VERSION="1.5.1" .
docker run --rm -it eclipse-mosquitto:1.5.1
```

