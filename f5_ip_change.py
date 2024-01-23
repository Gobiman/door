#!/usr/bin/python

################################################################################
# Script to process IP address changes on F5 BIGIP v10 and v11 devices. You
# cannot change IP addresses, so you must delete and re-add nodes. This script
# does exactly that, in a limited way.
#
# Caveats and limitations:
# - Nodes will get recreated in the 'Common' partition even if they were in
#   other partitions. This is on purpose, because this is what I needed
# - No per-node settings will be remembered
# - Per-pool settings will not be kept, except ratio
# - If nodes are used in multiple partitions, the script will crash
#
# The needed WSDL files can be found on your F5 device.

import f5
import re
import suds

# workardound for suds hardcoded cache path of $TMPDIR/suds
import os
os.environ['TMPDIR'] = os.getcwd()

# This is needed because we want to cache the WSDL
def set_host(self, host):
    self.hostname = host 
    for c in self.clients:
        c.set_options(location='https://%s/iControl/iControlPortal.cgi' % host)
f5.BIGIP.set_host = set_host

# Theoretically this can be changed :)
def log(level, msg):
    print msg

def check_lbs(lbs, reip):
    # Parsing the WSDL takes time, cache it.
    lb10 = f5.BIGIP(hostname='dummy', username='dummy', password='dummy',
                  directory='/usr/share/wsdl/f5/v10',
                  wsdls=[
                      'System.SystemInfo',
                      'System.Failover',
                      'Management.Partition',
                      'LocalLB.Pool',
                      'LocalLB.NodeAddress',
                      'LocalLB.PoolMember'
                  ]    
    )  
    lb11 = f5.BIGIP(hostname='dummy', username='dummy', password='dummy',
                  directory='/usr/share/wsdl/f5/v11',
                  wsdls=[
                      'System.Session',
                      'System.SystemInfo',
                      'System.Failover',
                      'LocalLB.NodeAddressV2',
                      'Management.Partition',
                      'LocalLB.Pool',
                  ]    
    )  

    for lbo in lbs:
        lb, username, password = lb
        lb = lb10
        lb.set_host(lbo.name)
        lb.set_options(username=username, password=password)
        version = lb.System.SystemInfo.get_version()
        status = lb.System.Failover.get_failover_state()
        if status == 'FAILOVER_STATE_STANDBY':
            log(2, "Not checking standby loadbalancer %s" % lbo.name)
            continue
        log(2, "Checking %s %s" % (lbo.name, version))
        major_version = version[:version.find('.')] # BIG-IP_v10 or BIG-IP_v11


        for partition in lb.Management.Partition.get_partition_list():
            if partition.partition_name == 'Common':
                continue
            log(2, "  Checking partition %s" % partition.partition_name)
            # Most nodes are stored in the Common partition. We need to reread them
            # every time because they may have been changed.
            lb.Management.Partition.set_active_partition(active_partition='Common')
            if major_version == 'BIG-IP_v10':
                common_nodes = lb.LocalLB.NodeAddress.get_list()
                common_screen_names = lb.LocalLB.NodeAddress.get_screen_name(common_nodes)
                check_partition_v10(lb, partition, common_nodes, common_screen_names, reip)
            elif major_version == 'BIG-IP_v11':
                lb11.set_host(lbo.name)
                lb11.set_options(username=username, password=password)
                common_nodes = lb11.LocalLB.NodeAddressV2.get_list()
                common_addresses = lb11.LocalLB.NodeAddressV2.get_address(common_nodes)
                check_partition_v11(lb11, partition, common_nodes, common_addresses, reip)
            else:
                log(0, "%s is of unknown version %s" % (lbo.name, major_version))

def check_partition_v10(lb, partition, common_nodes, common_screen_names, reip):
    lb.Management.Partition.set_active_partition(active_partition=partition.partition_name)
    local_nodes = lb.LocalLB.NodeAddress.get_list()
    if local_nodes:
        local_screen_names = lb.LocalLB.NodeAddress.get_screen_name(local_nodes)
    else:
        local_screen_names = []

    nodes = common_nodes + local_nodes
    screen_names = common_screen_names + local_screen_names
    if len(nodes) != len(set(nodes)):
        raise ValueError("Duplicate nodes found")

    ip_to_name = dict(zip(nodes, screen_names))
    for name, (old_ip, new_ip) in reip.items():
        # Does this need to change?
        if old_ip in nodes:
            # Does the name match? Name may be FQDN or hostname
            # This catches IP address reuse issues
            if name == ip_to_name[old_ip] or name.startswith(ip_to_name[old_ip] + '.'):
                change_ip_v10(lb, partition.partition_name, old_ip, new_ip, ip_to_name)

def change_ip_v10(lb, partition, old_ip, new_ip, ip_to_name):
    pools = lb.LocalLB.Pool.get_list()
    if not pools:
        return
    # global_ratios = lb.LocalLB.NodeAddress.get_ratio(nodes)
    pools_to_update = {}
    pool_ratios = lb.LocalLB.PoolMember.get_ratio(pool_names=pools)
    for pool, ratios in zip(pools, pool_ratios):
        for (_, member), (_, ratio) in ratios:
            if member.address == old_ip:
                pools_to_update[pool] = (member.port, ratio)
    if not pools_to_update:
        return
    # Hot diggity, we have an update!
    log(1, "    Changing IP of %s from %s to %s" % (ip_to_name[old_ip], old_ip, new_ip))

    # Delete pool membersheeps
    new_pools = pools_to_update.keys()
    all_members = []
    for pool in new_pools:
        member = lb.LocalLB.Pool.typefactory.create('Common.IPPortDefinition')
        member.address = old_ip
        member.port = pools_to_update[pool][0]
        seq = lb.LocalLB.PoolMember.typefactory.create('Common.IPPortDefinitionSequence')
        seq.item = [member]
        all_members.append(seq)
    members = lb.LocalLB.PoolMember.typefactory.create('Common.IPPortDefinitionSequenceSequence')
    members.item = all_members
    lb.LocalLB.Pool.remove_member(new_pools, members)

    # Delete the node
    lb.Management.Partition.set_active_partition("Common")
    try:
        lb.LocalLB.NodeAddress.delete_node_address(node_addresses=[old_ip])
    except suds.WebFault, e:
        # The current update partition (Common) does not match the object's partition (CorpWeb) (node address) (10.10.10.10)'
        if re.search(r"current update partition.*does not match the object's partition", e.fault.faultstring):
            # Node was mistakenly created outside Common
            lb.Management.Partition.set_active_partition(partition)
            lb.LocalLB.NodeAddress.delete_node_address(node_addresses=[old_ip])
            lb.Management.Partition.set_active_partition("Common")
        else:
            raise
    # And recreate it
    lb.LocalLB.NodeAddress.create(node_addresses=[new_ip], limits=[0])
    lb.LocalLB.NodeAddress.set_screen_name(node_addresses=[new_ip], names=[ip_to_name[old_ip]])
    # Re-add to pools
    lb.Management.Partition.set_active_partition(partition)
    all_members = []
    all_ratios = []
    for pool in new_pools:
        member = lb.LocalLB.Pool.typefactory.create('Common.IPPortDefinition')
        member.address = new_ip
        member.port = pools_to_update[pool][0]
        seq = lb.LocalLB.PoolMember.typefactory.create('Common.IPPortDefinitionSequence')
        seq.item = [member]
        all_members.append(seq)

        ratio = lb.LocalLB.PoolMember.typefactory.create('LocalLB.PoolMember.MemberRatio')
        ratio.member = member
        ratio.ratio = pools_to_update[pool][1]
        seq = lb.LocalLB.PoolMember.typefactory.create('LocalLB.PoolMember.MemberRatioSequence')
        seq.item = [ratio]
        all_ratios.append(seq)

    members = lb.LocalLB.PoolMember.typefactory.create('Common.IPPortDefinitionSequenceSequence')
    members.item = all_members
    lb.LocalLB.Pool.add_member(new_pools, members)

    # And set priorities again
    ratios = lb.LocalLB.PoolMember.typefactory.create('LocalLB.PoolMember.MemberRatioSequenceSequence')
    ratios.item = all_ratios
    lb.LocalLB.PoolMember.set_ratio(new_pools, ratios)

def check_partition_v11(lb, partition, common_nodes, common_addresses, reip):
    lb.Management.Partition.set_active_partition(active_partition=partition.partition_name)
    local_nodes = lb.LocalLB.NodeAddressV2.get_list()
    if local_nodes:
        local_addresses = lb.LocalLB.NodeAddressV2.get_address(local_nodes)
    else:
        local_addresses = []

    nodes = common_nodes + local_nodes
    addresses = common_addresses + local_addresses
    if len(nodes) != len(set(nodes)):
        raise ValueError("Duplicate nodes found")

    ip_to_name = dict(zip(addresses, nodes))
    for name, (old_ip, new_ip) in reip.items():
        # Does this need to change?
        if old_ip in addresses:
            # Does the name match? Name may be FQDN or hostname
            # This catches IP address reuse issues
            name2 = ip_to_name[old_ip]
            name2 = name2[name2.rfind('/')+1:]
            if name == name2 or name.startswith(name2 + '.'):
                change_ip_v11(lb, partition.partition_name, old_ip, new_ip, ip_to_name)

def change_ip_v11(lb, partition, old_ip, new_ip, ip_to_name):
    name_to_ip = dict([(ip_to_name[x], x) for x in ip_to_name])
    pools = lb.LocalLB.Pool.get_list()
    if not pools:
        return
    # global_ratios = lb.LocalLB.NodeAddress.get_ratio(nodes)
    pools_to_update = {}
    members = lb.LocalLB.Pool.get_member_v2(pool_names=pools)
    # suds for some reason flattens this array automatically!
    members2 = []
    for pool in members:
        pool2 = lb.LocalLB.Pool.typefactory.create('Common.AddressPortSequence')
        pool2.item = pool
        members2.append(pool2)
    smembers = lb.LocalLB.Pool.typefactory.create('Common.AddressPortSequenceSequence')
    smembers.item = members2
    pool_ratios = lb.LocalLB.Pool.get_member_ratio(pool_names=pools, members=smembers)
    for pool, members, ratios in zip(pools, members, pool_ratios):
        for member, ratio in zip(members, ratios):
            if name_to_ip[member.address] == old_ip:
                pools_to_update[pool] = (member.port, ratio)
    if not pools_to_update:
        return
    # Hot diggity, we have an update!
    log(1, "    Changing IP of %s from %s to %s" % (ip_to_name[old_ip], old_ip, new_ip))

    # Delete pool membersheeps
    node = ip_to_name[old_ip]
    new_pools = pools_to_update.keys()
    all_members = []
    for pool in new_pools:
        member = lb.LocalLB.Pool.typefactory.create('Common.AddressPort')
        member.address = node
        member.port = pools_to_update[pool][0]
        seq = lb.LocalLB.Pool.typefactory.create('Common.AddressPortSequence')
        seq.item = [member]
        all_members.append(seq)
    members = lb.LocalLB.Pool.typefactory.create('Common.AddressPortSequenceSequence')
    members.item = all_members
    lb.LocalLB.Pool.remove_member_v2(new_pools, members)

    node_partition, node = node.split('/')[-2:]
    # Delete the node
    if node_partition != partition:
        lb.Management.Partition.set_active_partition(node_partition)
    lb.LocalLB.NodeAddressV2.delete_node_address(nodes=[node])
    # And recreate it
    lb.Management.Partition.set_active_partition("Common")
    lb.LocalLB.NodeAddressV2.create(nodes=[node], addresses=[new_ip], limits=[0])
    # Re-add to pools
    lb.Management.Partition.set_active_partition(partition)
    all_members = []
    all_ratios = []
    for pool in new_pools:
        member = lb.LocalLB.Pool.typefactory.create('Common.AddressPort')
        member.address = '/Common/%s' % node
        member.port = pools_to_update[pool][0]
        seq = lb.LocalLB.Pool.typefactory.create('Common.AddressPortSequence')
        seq.item = [member]
        all_members.append(seq)

        seq = lb.LocalLB.Pool.typefactory.create('Common.ULongSequence')
        seq.item = [pools_to_update[pool][1]]
        all_ratios.append(seq)

    members = lb.LocalLB.Pool.typefactory.create('Common.AddressPortSequenceSequence')
    members.item = all_members
    lb.LocalLB.Pool.add_member_v2(new_pools, members)

    # And set priorities again
    ratios = lb.LocalLB.Pool.typefactory.create('Common.ULongSequenceSequence')
    ratios.item = all_ratios
    lb.LocalLB.Pool.set_member_ratio(pool_names=new_pools, members=members, ratios=ratios)

def get_lbs():
    # Needs to return a list of tuples (hostname, username, password)
    return [('lb-1.kaarsemaker.net', 'lb_admin', 'hunter2')]

def get_changes():
    # Needs to return a dict of changes: {hostname: (old_ip, new_ip, ...}
    # Hostname should be FQDN or F5 display name
    return {
        'example-host-1.kaarsemaker.net': ('10.10.10.1', '10.10.20.1'),
        'example-host-2.kaarsemaker.net': ('10.10.10.2', '10.10.20.2'),
        'example-host-3.kaarsemaker.net': ('10.10.10.3', '10.10.20.3'),
    }

if __name__ == '__main__':
    lbs = get_lbs()
    reip = get_changes()
    check_lbs(lbs, reip)