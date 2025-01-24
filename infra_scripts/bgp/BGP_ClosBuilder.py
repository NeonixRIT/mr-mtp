import fabrictestbed_extensions.utils
import xml.dom.minidom
from fabrictestbed_extensions.fablib.fablib import FablibManager as fablib_manager
from collections import Counter
from time import perf_counter

from FabUtils import FabOrchestrator
from ClosGenerator import BGPDCNConfig
from mako.template import Template
import asyncio
import os
import json
from ipaddress import ip_address, IPv4Address, IPv4Network
import re
from typing import Any

# FABRIC Configuration
SLICE_NAME = "bgp_sec_test_kam"
SITE_NAME = "STAR"
MEAS_ADD = False

# Folded-Clos Configuration
PORTS_PER_DEVICE = 4
NUMBER_OF_TIERS = 2
NETWORK_NODE_PREFIXES = "T,S,L"
COMPUTE_NODE_PREFIXES = "C"
SEC_NODE_PREFIX = "H"
SINGLE_COMPUTE_SUBNET = False
SOUTHBOUND_PORT_DENSITY = {1:1}
ADD_SEC_NODE = True
BGP_SCRIPTS_LOCATION = "./remote_scripts/bgp_scripts"
TEMPLATE_LOCATION = "./remote_scripts/frr_templates/frr_conf_bgp.mako"

# NETWORK_NODE_PREFIXES += f',{SEC_NODE_PREFIX}'


def setup_manager():
    fablib = fablib_manager(project_id='fec0d0d8-a7a8-4eac-b091-87f7914af796', fabric_rc='')
    fablib.show_config()
    fablib.probe_bastion_host()
    return fablib


def build_graph():
    topology = BGPDCNConfig(PORTS_PER_DEVICE,
                            NUMBER_OF_TIERS,
                            southboundPortsConfig=SOUTHBOUND_PORT_DENSITY,
                            singleComputeSubnet=SINGLE_COMPUTE_SUBNET,
                            addSecurityNode=ADD_SEC_NODE)
    logFile = topology.jsonGraphInfo()
    topology.buildGraph()
    print(f"Folded-Clos topology details (Not considering port density changes and security node additions):\n{topology.getClosStats()}")
    return topology, logFile


def build_bgp_template():
    bgpTemplate = Template(filename=TEMPLATE_LOCATION)
    print("FRR-BGP configuration template loaded.")
    return bgpTemplate


# CONFIGURATION FOR BGP-SPEAKING LEAF AND SPINE NODES
def addBGPConfiguration(node, nodeInfo, topology: BGPDCNConfig, bgpTemplate: Template):
    '''
    Prepare a node for the FRR BGP-4 implementation to be installed.
    '''

    # Store information about BGP-speaking neighbors to configure neighborship
    neighboringNodes = []

    # Find the node's BGP-speaking neighbors and determine their ASN as well as their IPv4 address used on the subnet shared by the nodes.
    for neighbor, addr in topology.getNodeAttribute(node, 'ipv4').items():
        if(topology.isNetworkNode(neighbor)):
            neighboringNodes.append({'asn':topology.getNodeAttribute(neighbor, 'ASN'), 'ip':topology.getNodeAttribute(neighbor, 'ipv4', node)})

    # In addition to storing neighbor information, store any compute subnets that the node must advertise to neighbors (leaf's only).
    nodeTemplate = {'neighbors':neighboringNodes, 'bgp_asn': topology.getNodeAttribute(node, 'ASN'), 'networks': topology.getNodeAttribute(node, 'advertise')}

    # Process the stored information and render a custom frr.conf.
    nodeBGPData = bgpTemplate.render(**nodeTemplate)

    # Add FABRIC post-boot tasks to get the node ready for FRR installation
    # print(dir(nodeInfo))
    # exit()
    nodeInfo.add_post_boot_upload_directory(BGP_SCRIPTS_LOCATION,'.')
    nodeInfo.add_post_boot_execute(f'sudo echo -e "{nodeBGPData}" > bgp_scripts/frr.conf')
    nodeInfo.add_post_boot_execute('sudo chmod +x /home/rocky/bgp_scripts/*.sh')

    return


# CONFIGURATION FOR NON-BGP-SPEAKING COMPUTE NODES
def addComputeConfiguration(nodeInfo):
    '''
    Prepare a node for traffic testing.
    '''
    nodeInfo.add_post_boot_upload_directory(BGP_SCRIPTS_LOCATION,'.')
    nodeInfo.add_post_boot_execute('sudo chmod +x /home/rocky/bgp_scripts/*.sh') # added sudo to the front of both of them and added all *.sh to execute

    return


def create_slice(manager: fablib_manager, logFile: dict[str, Any], topology: BGPDCNConfig, bgpTemplate: Template):
    # Create the slice
    slice = manager.new_slice(name=SLICE_NAME)

    addedNodes = {} # Visited nodes structure, format = name : nodeInfo

    # Add slice-specific information to the log file
    logFile.update({"name": SLICE_NAME, "site": SITE_NAME, "meas": MEAS_ADD})

    # Iterate over each network in the topology and configure each interface connected to the network, and the network itself.
    for networkInfo in topology.iterNetwork(fabricFormating=True):
        networkIntfs = [] # Interfaces to be added to the network.
        network = networkInfo[0] # A tuple containing the nodes on the network.
        networkName = networkInfo[1] # The FABRIC network name.

        print(f"Configuring network: {network}")

        # For each node in a given IPv4 subnet within the folded-Clos topology.
        for node in network:
            # If the node has not yet been visited, provide it with the appropriate configuration.
            if(node not in addedNodes):
                # Add the node to the FABRIC slice.
                if(node.startswith(SEC_NODE_PREFIX)):
                    nodeInfo = slice.add_node(name=node, cores=4, ram=4, disk=80, image='default_kali', site=SITE_NAME)
                else:
                    nodeInfo = slice.add_node(name=node, cores=1, ram=4, image='default_rocky_8', site=SITE_NAME)

                # If the node is a non-compute node, it needs FRR-BGP configuration instructions.
                if(topology.isNetworkNode(node)):
                    addBGPConfiguration(node, nodeInfo, topology, bgpTemplate)
                else:
                    addComputeConfiguration(nodeInfo)

                addedNodes[node] = nodeInfo
                print(f"\tAdded node {node} to the slice.")

            else:
                print(f"\tAlready added node {node} to the slice.")

            # Create a name for the node's interface connected to this network and add it to the FABRIC slice.
            intfName = topology.generateFabricIntfName(node, network)
            netIntf = addedNodes[node].add_component(model='NIC_Basic', name=intfName).get_interfaces()[0]
            networkIntfs.append(netIntf)

        # Add the network to the FABRIC slice.
        slice.add_l2network(name=networkName, interfaces=networkIntfs, type="L2Bridge")
        print(f"\tAdded network {network}")


    # Submit Slice Request
    print(f'Submitting the new slice, "{SLICE_NAME}"...')
    slice.submit()
    print(f'{SLICE_NAME} creation done.')


def configure_slice(logFile, topology):
    manager_orc = FabOrchestrator(SLICE_NAME)

    # Commands to execute the bash scripts configuring the nodes
    coreNodeConfig = "./bgp_scripts/init_bgp.sh"
    edgeNodeConfig = "./bgp_scripts/init_compute.sh"

    # Configure core (BGP-speaking) nodes
    manager_orc.executeCommandsParallel(coreNodeConfig, prefixList=NETWORK_NODE_PREFIXES)

    # Configure edge (non-BGP-speaking) nodes
    manager_orc.executeCommandsParallel(edgeNodeConfig, prefixList=COMPUTE_NODE_PREFIXES)

    # Add IPv4 Addressing to All Nodes
    # This system utilizes the addressing provided by the ClosGenerator module:

    # * 192.168.0.0/16 is the compute supernet. All compute subnets are given a /24 subnet. Compute devices are given lower addresses (ex: .1) and the leaf node is given a high address (ex: .254)

    # * 172.16.0.0/12 is the core supernet. All core subnets are given a /24 subnet. Both devices are given lower addresses.
    manager = fablib_manager()
    slice = manager.get_slice(name=SLICE_NAME)

    slice.show()
    slice.list_nodes()
    slice.list_networks()

    COMPUTE_SUPERNET = "192.168.0.0/16"

    # Iterate through every node in the topology
    for node in topology.iterNodes():
        print(f"Configuring IPv4 addressing on node: {node}")

        # Pull IPv4 attribute data to configure FABRIC interfaces
        for neighbor, currentAddress in topology.getNodeAttribute(node, 'ipv4').items():
            # Access the interface from FABRIC.
            intfName = f"{node}-intf-{neighbor}-p1" # Naming is a bit strange, but is formatted in FABRIC as such.
            intf = slice.get_interface(intfName)

            # Convert the address and subnet into ipaddress objects for FABRIC processing.
            fabAddress = IPv4Address(currentAddress)
            fabSubnet = IPv4Network(f"{currentAddress}/24", strict=False)

            # Assign the address to the interface.
            intf.ip_addr_add(addr=fabAddress, subnet=fabSubnet)

        # For compute nodes, also add a compute supernet route with its attached leaf node as the next-hop.
        if(not topology.isNetworkNode(node)):
            IPGroup = re.search(r"192\.168\.([0-9]{1,3})\.[0-9]{1,3}", currentAddress) # Grab the third octet number.
            thirdOctet = IPGroup.group(1)
            nextHop = f"192.168.{thirdOctet}.254"

            # Add the route to the node
            intf.get_node().ip_route_add(subnet=IPv4Network(COMPUTE_SUPERNET), gateway=IPv4Address(nextHop))

            print(f"\tAdded route to {node}")

        print("\tConfiguration complete.")

    # Log Topology Information

    # Iterate through every node in the topology
    for nodeName in topology.iterNodes():
        print(f"Saving {nodeName} SSH information...")
        tierNumber = topology.getNodeAttribute(nodeName, 'tier')
        logFile[f"tier_{tierNumber}"][nodeName]["ssh"] = manager_orc.slice.get_node(nodeName).get_ssh_command()

    with open(f'{SLICE_NAME}_k{PORTS_PER_DEVICE}_t{NUMBER_OF_TIERS}_BGP.json', "w") as outfile:
        json.dump(logFile, outfile)


def main():
    # Initialize the FABRIC manager
    manager = setup_manager()

    # Build the topology
    topology, logFile = build_graph()

    # Load the BGP template
    bgpTemplate = build_bgp_template()

    # Create the slice
    create_slice(manager, logFile, topology, bgpTemplate)

    # Configure the slice
    configure_slice(logFile, topology)


if __name__ == "__main__":
    main()
