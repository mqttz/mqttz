<!--
.. title: Download
.. slug: download
.. date: 2018-01-07 20:15:04 UTC
.. tags: tag
.. category: category
.. link: link
.. description:
.. type: text
-->

# Source

* [mosquitto-1.5.2.tar.gz](http://mosquitto.org/files/source/mosquitto-1.5.2.tar.gz) (319kB) ([GPG signature](http://mosquitto.org/files/source/mosquitto-1.5.1.tar.gz.asc))
* [mosquitto-1.5.2.tar.gz](http://www.eclipse.org/downloads/download.php?file=/mosquitto/source/mosquitto-1.5.2.tar.gz) (via Eclipse)
* [Git source code repository](https://github.com/eclipse/mosquitto) (github.com)

Older downloads are available at [http://mosquitto.org/files/](../files/)

# Binary Installation

The binary packages listed below are supported by the Mosquitto project. In many
cases Mosquitto is also available directly from official Linux/BSD
distributions.

## Windows

* [mosquitto-1.5.2-install-windows-x64.exe](http://www.eclipse.org/downloads/download.php?file=/mosquitto/binary/win64/mosquitto-1.5.2-install-windows-x64.exe) (~360 kB) (64-bit build, Windows Vista and up, built with Visual Studio Community 2017)
* [mosquitto-1.5.2-install-windows-x32.exe](http://www.eclipse.org/downloads/download.php?file=/mosquitto/binary/win32/mosquitto-1.5.2-install-windows-x86.exe) (~360 kB) (32-bit build, Windows Vista and up, built with Visual Studio Community 2017)

You will also need to install Win64 OpenSSL v1.1.0 Light or Win32OpenSSL v1.1.0 Light from [slproweb.com](http://slproweb.com/products/Win32OpenSSL.html)

See also readme-windows.txt after installing.

## Mac
Mosquitto can be installed from the homebrew project. See
[brew.sh](http://brew.sh/) and then use `brew install mosquitto`

## Linux distributions with snap support

* `snap install mosquitto`

## CentOS
Download the repository config file for your CentOS version from below and copy it to /etc/yum.repos.d/ You'll now be able to install and keep mosquitto up to date using the normal package management tools.

The available packages are: mosquitto, mosquitto-clients, libmosquitto1, libmosquitto-devel, libmosquittopp1, libmosquittopp-devel, python-mosquitto.
* [CentOS 7](http://download.opensuse.org/repositories/home:/oojah:/mqtt/CentOS_CentOS-7/home:oojah:mqtt.repo)
* [CentOS 6](http://download.opensuse.org/repositories/home:/oojah:/mqtt/CentOS_CentOS-6/home:oojah:mqtt.repo)

## Debian
* Mosquitto is now in Debian proper. There will be a short delay between a new
  release and it appearing in Debian as part of the normal Debian procedures.
* There are also Debian repositories provided by the mosquitto project, as
  described at <http://mosquitto.org/2013/01/mosquitto-debian-repository>

## openSUSE
Download the repository config file for your openSUSE version from below and
copy it to /etc/zypp/repos.d/ You'll now be able to install and keep mosquitto
up to date using the normal package management tools.

The available packages are: mosquitto, mosquitto-clients, libmosquitto1, libmosquitto-devel, libmosquittopp1, libmosquittopp-devel, python-mosquitto.

* [openSUSE 13.2]http://download.opensuse.org/repositories/home:/oojah:/mqtt/openSUSE_13.2/home:oojah:mqtt.repo)
* [openSUSE 13.1]http://download.opensuse.org/repositories/home:/oojah:/mqtt/openSUSE_13.1/home:oojah:mqtt.repo)

## Raspberry Pi
Mosquitto is available through the main repository.

There are also Debian repositories provided by the mosquitto project, as
described at <http://mosquitto.org/2013/01/mosquitto-debian-repository/>

## Redhat Enterprise Linux
Download the repository config file for your RHEL version from below and copy
it to /etc/yum.repos.d/ You'll now be able to install and keep mosquitto up to
date using the normal package management tools.

The available packages are: mosquitto, mosquitto-clients, libmosquitto1, libmosquitto-devel, libmosquittopp1, libmosquittopp-devel, python-mosquitto.
* [RHEL 7](http://download.opensuse.org/repositories/home:/oojah:/mqtt/RedHat_RHEL-7/home:oojah:mqtt.repo)
* [RHEL 6](http://download.opensuse.org/repositories/home:/oojah:/mqtt/RedHat_RHEL-6/home:oojah:mqtt.repo)

## SUSE Linux Enterprise Server
Add the appropriate repository to your package config from the list below, then install mosquitto from your normal package management tools.

* [SLE 15](http://download.opensuse.org/repositories/home:/oojah:/mqtt/SLE_15/)
* [SLE 12 SP3](http://download.opensuse.org/repositories/home:/oojah:/mqtt/SLE_12_SP3/)
* [SLE 12 SP2](http://download.opensuse.org/repositories/home:/oojah:/mqtt/SLE_12_SP2/)
* [SLE 12 SP1](http://download.opensuse.org/repositories/home:/oojah:/mqtt/SLE_12_SP1/)
* [SLE 12](http://download.opensuse.org/repositories/home:/oojah:/mqtt/SLE_123/)

## Ubuntu
Mosquitto is available in the Ubuntu repositories so you can install as with
any other package. If you are on an earlier version of Ubuntu or want a more
recent version of mosquitto, add the [mosquitto-dev
PPA](http://launchpad.net/%7Emosquitto-dev/+archive/mosquitto-ppa/) to your
repositories list - see the link for details. mosquitto can then be installed
from your package manager.

* `sudo apt-add-repository ppa:mosquitto-dev/mosquitto-ppa`
* `sudo apt-get update`

# Other packages known to exist

## Arch Linux
* Mosquitto can be found in the community repository.

## Fedora
Mosquitto is now available from Fedora directly. Use `yum install mosquitto`,
or search for "mosquitto" to find the related packages.

## FreeBSD
Mosquitto is available for FreeBSD: http://www.freshports.org/net/mosquitto/

## Gentoo
Use `emerge mosquitto`

## OpenWrt
If you're using a trunk snapshot use `opkg update; opkg install mosquitto`

Karl Palsson maintains a set of feeds that may be more up to date than the
current OpenWrt version:

* https://github.com/remakeelectric/owrt_pub_feeds

