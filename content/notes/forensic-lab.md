---
layout: note
title: Forensic Lab setup 
date: 2023-03-27
---

This tutorial will guide you through the setup of a Forensic lab using:

- [VirtualBox 7](https://www.virtualbox.org/)
- [REMnux](https://docs.remnux.org/) + [Sift](https://www.sans.org/tools/sift-workstation/) on Ubuntu 20.04
- [FlareVM](https://github.com/mandiant/flare-vm) on Windows 10

It is mostly a summary of notes I took while building my own lab.

## Disclaimer

**Do not follow this guide blindly!**

Be very careful during the setup of your forensic lab, especially if you intend to manipulate and/or detonate malware. 
I am in no way responsible for any harm or damage you may cause and you should always make sure you are operating in a safe environment.

If you are not sure about what you're doing, please stop and seek advice from professionals.

## 0x00 - Get an hypervisor

Although his setup will be using [VirtualBox 7](https://www.virtualbox.org/wiki/Downloads), it can be adapted to use another hypervisor.

## 0x01 - Linux box setup

This guide will start from an Ubuntu image but you may also start from the REMnux of Sift VM appliance and install the other REMnux/Sift on top of it.

### Prepare Ubuntu 20.04

At the time of writing, REMnux does not support Ubuntu 22.04, so I will be using Ubuntu 20.04. Also, REMnux won't run on ARM processors.

1. Download the [Ubuntu 20.04 image](https://releases.ubuntu.com) and create the VM from it.
1. Proceed to the installation as you would for a bare metal installation.
1. When it's completed, click on "Device" in the VirtualBox menu and "Insert Guest Additions CD image..." and run it. It will fix the resolution and "optimize the guest operating system for better performance and usability". Check the [documentation](https://www.virtualbox.org/manual/ch04.html) for further details.
1. Once ready, spin up a terminal and add yourself to the sudoers.

You should now have a clean Ubuntu setup on which you will be able to install [REMnux](https://docs.remnux.org/) and [Sift](https://www.sans.org/tools/sift-workstation/).

:warning: It is possible that your terminal doesn't start. If that's the case, you may have to mess with languages to fix it (see this [related post](https://askubuntu.com/questions/1435918/terminal-not-opening-on-ubuntu-22-04-on-virtual-box-7-0-0)). If that isn't enough, Google your specific issue.

:bulb: At this point, I advise to take a snapshot, just in case things go sour during the next steps.

### Install REMnux

Let's proceed with the installation of [REMnux](https://docs.remnux.org/).
To do so, we will use [`cast`](https://github.com/ekristen/cast).

Download the latest [release](https://github.com/ekristen/cast/releases), install it, and run:

```sh
cast install remnux/salt-states
```

:warning: The installation may be quite slow, but it will eventually come through. If not, simply interrupt and relaunch the install. In case it's all broken, revert to the previous snapshot.

:bulb: When completed, take a snapshot.

### Install Sift

Same as REMnux:

```sh
cast install teamdfir/sift-saltstack
```

:bulb: Take another snapshot.

You should now have a Linux box loaded with forensics tools! :tada:

## 0x02 - Windows box setup

### Prepare Windows 10

1. Download the [Windows 10 image](https://www.microsoft.com/en-us/software-download/windows10ISO) and create the VM from it.
1. Proceed to the installation as you would for a bare metal installation.
1. When it's completed, click on "Device" in the VirtualBox menu and "Insert Guest Additions CD image..." and run it.

:bulb: Take a snapshot.

### Install FlareVM

Simply follow the [official detailed installation guide](https://github.com/mandiant/flare-vm#installation).

:bulb: Take another snapshot.

## 0x03 - Network setup

:heavy_exclamation_mark: This part is very important if you want to isolate your lab and avoid infecting your host.

1. Create a new network on VirtualBox
1. Enable DHCP server
1. Setup an IP range you can, in no way, confuse with your local network, e.g. `10.0.0.0/24` if your local network is `192.168.0.0/24`
1. Update the DHCP server address, mask, and lower/upper addresses accordingly
1. Change the network adapter of the VMs to the one you just created
1. Double check that there are no other active network adapters!

### INetSim configuration (Linux box)

Configuring [`INetSim`](https://www.inetsim.org/) will allow to simulate "common internet services in a lab environment, e.g. for analyzing the network behaviour of unknown malware samples".

Edit `/etc/inetsim/inetsim.conf`:

- uncomment `start_service dns`
- set `service_bind_address` to `0.0.0.0`
- set `dns_default_ip` to the IP of the box

### Update DNS server address (Windows box)

Set the "Preferred DNS server" to the IP of the Linux box.

:bulb: Snapshot both boxes.


:checkered_flag: The lab setup is now complete, go have fun! :checkered_flag:
