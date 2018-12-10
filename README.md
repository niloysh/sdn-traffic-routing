### Sway: Traffic-Aware QoS Routing in Software-Defined IoT
===========================================================

This directory contains some starter code for the POX + Mininet setup used in Sway.

#### Installation/ Usage :
 - Step 1: Clone this repository to your home directory.
 - Step 2: You should have two directories, namely `pox` and `mininet`.
 - Step 3: The `pox/ext/sway` contains the code for a simple reactive forwarding module built on top of the POX SDN controller.
 - Step 4: To launch the reactive forwarding application, simply `cd` into the `pox` directory and run `$ ./pox.py sway.startup`
 - Step 5: The mininet directory contains a simple custom topology. To launch it, `cd` into the mininet directory and run `$ sudo python topology.py`

#### Adding Functionality :

From here on, you can add various functionality according to your requirements. I have intentionally kept the code simple so that it is easier to understand and modify. Some ideas for enhancements are:

 - The [fnss](https://fnss.github.io/) library can be utilized to read in various network topologies from  sources such as [CAIDA](http://www.caida.org/research/topology/#Datasets) and [Internet Topology Zoo](http://www.topology-zoo.org/).
 - Since `mininet/topology.py` and `sway/reactive_fwd` utilizes the [networkx](https://networkx.github.io/documentation/stable/index.html) library, you can utilize various algorithms present, such as Dijkstra, Bellman-Ford, K-shortest paths, etc.
 - The [OpenNetMon](https://github.com/TUDelftNAS/SDN-OpenNetMon) module can be utilized to measure link delay, bandwidth etc. for QoS applications.


#### Citation : 
If you use the code in this repository in your research work or project, please consider citing the following publication.

N. Saha, S. Bera, S. Misra, "[Sway: Traffic-Aware QoS Routing in Software-Defined IoT](https://niloysh.github.io/assets/Sway.pdf), in *IEEE Trans. on Emerging Topics in Computing*, 2018. Doi: 10.1109/TETC.2018.2847296

```
@ARTICLE{8385144, 
author={N. Saha and S. Bera and S. Misra}, 
journal={IEEE Transactions on Emerging Topics in Computing}, 
title={Sway: Traffic-Aware QoS Routing in Software-Defined IoT}, 
year={2018}, 
volume={}, 
number={}, 
pages={1-1}, 
keywords={Computer architecture;Delays;Internet of Things;Quality of service;Routing;Wireless communication;Internet of Things;Quality-of-Service;Routing;Software-Defined Networking}, 
doi={10.1109/TETC.2018.2847296}, 
ISSN={}, 
month={},}
```




