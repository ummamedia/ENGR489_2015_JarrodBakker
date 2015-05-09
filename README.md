# ENGR489_2015_JarrodBakker
This repository contains the implementation material for my 2015 ENGR489 project at Victoria University of Wellington.

My project builds upon the code contained with the Mininet VM image found on https://github.com/mininet/mininet/wiki/Mininet-VM-Images where my chosen Mininet release was the 'Mininet 2.2.1 on Ubuntu 14.04 - 64 bit'. This repository does not include the files provided by the image as that would bloat the repository itself. Therefore the files contained within are ones that I have developed.

Mininet and Ryu were updated to their respective latest versions. To update Mininet follow the instructions on http://mininet.org/download/, namely 'Option 4. Upgrading an existing Mininet Installation'. To upgrade Ryu follow the instructions on https://github.com/osrg/ryu/wiki/OpenFlow_Tutorial.

Open vSwitch was also updated. At time of downloading, the Mininet VM image contained version 1.11.0 of Open vSwitch. This only partially supports OpenFlow 1.3, meaning that one or more features are not supported. As a result Open vSwitch was updated to version 2.3.1. Instructions for updating the image can be found at https://github.com/mininet/mininet/wiki/Installing-new-version-of-Open-vSwitch where the correct file of the Open vSwitch version is inserted.
