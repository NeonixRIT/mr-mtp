"""
Author: Peter Willis
Desc: Collection of scripts to aid in the testing of FABRIC experiments.

THE SLICE MUST ALREADY BE CREATED FOR THIS TO WORK
"""

from fabrictestbed_extensions.fablib.fablib import FablibManager as fablib_manager
from ipaddress import ip_address, IPv4Address, IPv4Network
import datetime
import ntpath


class FabOrchestrator:
    # Constructor, get access to the slice and nodes
    def __init__(self, sliceName):
        """ """

        try:
            # Slice
            self.slice = fablib_manager().get_slice(sliceName)

            # Nodes
            self.nodes = self.slice.get_nodes()

            print(f'Slice name: {sliceName}\nSlice and nodes were acquired successfully.')

        except Exception as e:
            print(f'Exception: {e}')

    def selectedNodes(self, prefixList=None):
        """
        Perform an action (execute a command, up/download a file, etc.) on a subset of nodes
        """

        if prefixList:
            prefixList = tuple(map(str.strip, prefixList.split(',')))

        for node in self.nodes:
            nodeName = node.get_name()

            if prefixList and not nodeName.startswith(prefixList):
                continue

            yield node

    def executeCommandsParallel(self, command, prefixList=None, addNodeName=False):
        """
        Execute a command, in parallel using threads, on all or a subset of remote FABRIC nodes
        """

        try:
            # Create execute threads
            execute_threads = {}
            for node in self.selectedNodes(prefixList):
                nodeName = node.get_name()
                if addNodeName is True:
                    finalCommand = command.format(name=nodeName)
                else:
                    finalCommand = command

                print(f'Starting command on node {nodeName}')
                print(f'Command to execute: {finalCommand}')

                execute_threads[node] = node.execute_thread(finalCommand)

            # Wait for results from threads
            for node, thread in execute_threads.items():
                print(f'Waiting for result from node {node.get_name()}')
                stdout, stderr = thread.result()
                print(f'stdout: {stdout}')
                print(f'stderr: {stderr}')

        except Exception as e:
            print(f'Exception: {e}')

        return

    def uploadDirectoryParallel(self, directory, remoteLocation=None, prefixList=None):
        """ """

        if remoteLocation is None:
            remoteLocation = '/home/rocky'

        print(f'Directory to upload: {directory}\nPlaced in: {remoteLocation}')

        try:
            # Create execute threads
            execute_threads = {}
            for node in self.selectedNodes(prefixList):
                print(f'Starting upload on node {node.get_name()}')
                execute_threads[node] = node.upload_directory_thread(directory, remoteLocation)

            # Wait for results from threads
            for node, thread in execute_threads.items():
                print(f'Waiting for result from node {node.get_name()}')
                output = thread.result()
                print(f'Output: {output}')

        except Exception as e:
            print(f'Exception: {e}')

        return

    def uploadFileParallel(self, file, remoteLocation=None, prefixList=None):
        """ """

        if remoteLocation is None:
            fileName = ntpath.basename(file)
            remoteLocation = f'/home/rocky/{fileName}'

        print(f'File to upload: {file}\nPlaced in: {remoteLocation}')

        try:
            # Create execute threads
            execute_threads = {}
            for node in self.selectedNodes(prefixList):
                print(f'Starting upload on node {node.get_name()}')
                execute_threads[node] = node.upload_file_thread(file, remoteLocation)

            # Wait for results from threads
            for node, thread in execute_threads.items():
                print(f'Waiting for result from node {node.get_name()}')
                output = thread.result()
                print(f'Output: {output}')

        except Exception as e:
            print(f'Exception: {e}')

        return

    def downloadFilesParallel(self, localLocation, remoteLocation, prefixList=None, addNodeName=False):
        """
        Download a file
        """

        try:
            # Create execute threads
            execute_threads = {}
            for node in self.selectedNodes(prefixList):
                nodeName = node.get_name()
                if addNodeName is True:
                    finalRemoteLocation = remoteLocation.format(name=nodeName)
                    finalLocalLocation = localLocation.format(name=nodeName)
                else:
                    finalRemoteLocation = remoteLocation
                    finalLocalLocation = localLocation

                print(f'Starting download on node {nodeName}')
                print(f'File to download: {finalRemoteLocation}')
                print(f'Location of download: {finalLocalLocation}')

                execute_threads[node] = node.download_file_thread(finalLocalLocation, finalRemoteLocation)

            # Wait for results from threads
            for node, thread in execute_threads.items():
                print(f'Waiting for result from node {node.get_name()}')
                output = thread.result()
                print(f'Output: {output}')

        except Exception as e:
            print(f'Exception: {e}')

        return

    def saveSSHCommands(self):
        """
        Grab the SSH command for each node in the topology and save it to a file in the local directory
        """

        with open(f'{self.slice.get_name()}_ssh_cmds.txt', 'w') as sshFile:
            for node in self.nodes:
                sshFile.write(f'{node.get_name()}:\n')
                sshFile.write(f'{node.get_ssh_command()}\n')

        return

    def renewSlice(self, daysToAdd):
        """
        Renew the slice for a set number of days
        """

        endDate = (datetime.datetime.now() + datetime.timedelta(days=daysToAdd)).strftime('%Y-%m-%d %H:%M:%S %z') + '+0000'
        self.slice.renew(endDate)

        return

    def getInterfaceSubnet(self, intfName):
        """
        Return the subnet of an interface in IPv4Network format
        """

        intf = self.slice.get_interface(intfName)

        subnet = IPv4Network(f'{intf.get_ip_addr()}/24', strict=False)

        return subnet
