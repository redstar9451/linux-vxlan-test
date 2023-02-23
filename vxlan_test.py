#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import getopt
import subprocess
import sys

CMD_ADD_NETWORK = "add_network"
CMD_ADD_DOCKER = "add_docker"
CMD_CLEAN_DOCKER = "clean_docker"

CMD_ADD_NETNS = "add_netns"
CMD_CLEAN_NETNS = "clean_netns"


def gen_network(vni):
    """
    generate network name for docker network,
    or generate name for netns
    :param vni: vxlan vni id
    :return: network or netns name
    """
    return "net-vpc%s" % vni


def gen_vxlan(vni):
    """
    generate vxlan link name
    :param vni: vxlan vni id
    :return: vxlan name
    """
    return "vxlan-vpc%s" % vni


def gen_docker(vni, name):
    return "%s%s" % (gen_docker_prefix(vni), name)


def gen_docker_prefix(vni):
    return "vpc%s-" % vni


def gen_br(vni):
    """
    generate netns bridge name for a vni
    :param vni: vxlan vni
    :return: linux bridge name
    """
    return "br-vpc%s" % vni


def gen_veth(vni):
    """
    generate veth pari name for a vni
    :param vni: vxlan vni
    :return: veth pair, (tap-name, veth-name)
    """
    return "tap-vpc%s" % vni, "veth-vpc%s" % vni


def usage(err_msg=""):
    help_str = """
vxlan test
    ./vxlan_test_0.py [command] [options]
    add_docker, add test docker
    add_network, add docker network
    clean_docker, clean_docker docker network and all dockers in the network

    add_netns, add a netns which acts as vxlan vtep
    clean_netns, clean_docker netns
"""
    print(err_msg + "\n")
    print(help_str)


def check_output(cmd):
    """
    execute shell commandline, return output
    :param cmd: commandline string
    :return:
        output string: empty string if output nothing. For shell command, the output has a "\n" in the end generally.
        None: failed to execute the commandline, do not use None to judge whether the execution result is ok.
    """
    if hasattr(subprocess, 'check_output'):
        try:
            p = subprocess.check_output(cmd, shell=True)
            if isinstance(p, bytes):
                return p.decode()
            else:
                return p
        except subprocess.CalledProcessError as e:
            print(e)
            return None
    else:
        # python version < 2.7
        try:
            output = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True).communicate()[0]
            return output
        except subprocess.CalledProcessError as e:
            print(e)
            return None


def check_output_raise_exception(cmd, strip=False):
    r = check_output(cmd)
    if r is None:
        raise Exception("execute [" + cmd + "] error")
    if strip:
        r = r.strip()
    return r


def _add_docker_pre_check(name, network):
    with open("/sys/module/vxlan/parameters/udp_port") as f:
        content = f.read()
        vxlan_udp_port = content.encode()
    if vxlan_udp_port.strip() != "4789":
        raise Exception("vxlan port is not 4789")

    r = check_output_raise_exception(
        "docker ps -a | grep -w %s || true" %
        name)
    if r != "":
        raise Exception("docker %s exists" % name)

    r = check_output_raise_exception(
        "docker network ls | grep -w %s || true" %
        network)
    if r == "":
        raise Exception("docker network %s not exist" % network)


def _add_docker(name, img, network, ip, mac, sip=None, arp=None):
    """
    create docker, add secondary ip to eth0; set static arp
    :param name: docker name
    :param img: docker image
    :param network: docker network
    :param ip: docker ip address
    :param mac: ip interface mac
    :param sip: secondary ip address
    :param arp: static arp, [ip]:[mac]
    :return: True or False
    """
    _add_docker_pre_check(name, network)
    cmd = "docker run -d --net %s --ip %s --privileged=true --name %s %s" % (
        network, ip, name, img)
    check_output_raise_exception(cmd)
    if mac:
        cmd = "docker exec %s ip link set dev eth0 addr %s" % (name, mac)
        check_output_raise_exception(cmd)
    if sip:
        cmd = "docker exec %s ip addr add %s dev eth0" % (name, sip)
        check_output_raise_exception(cmd)
    if arp:
        ip, mac = arp.split("-")
        cmd = "docker exec %s ip neigh add %s lladdr %s dev eth0" % (
            name, ip, mac)
        check_output_raise_exception(cmd)


def add_network_usage(err_msg=""):
    help_str = """
./vxlan_test.py add_network [options]
    -s | --subnet, subnet cidr, such as 192.168.1.0/24, do not use the cidr which has been configured
    -v | --vni, the vni id
    -l | --local, vxlan tunnel local vtep ip address
    -r | --remote, vxlan tunnel remote vtep ip address
    -e | --eth, ethernet name where local vtep ip is configured on, such as eth1
"""
    if err_msg:
        print(err_msg + "\n")
    print(help_str)


def network_exists(name):
    """
    check network exist.
    :param name: network name
    :return: True or False
    """
    r = check_output_raise_exception(
        "docker network ls | grep -w %s || true" % name)
    if r:
        return True
    return False


def _add_network_pre_check(network_name):
    """
    add network pre-check
    1. check whether network exists
    :param network_name:  network name
    :return: None if pass, else raise Exception
    """
    if network_exists(network_name):
        raise Exception("network %s exists" % network_name)


def _add_network(subnet, vni, local, remote, eth):
    """
    create docker network
    :param subnet: docker subnet cidr, such as 192.168.1.0/24
    :param vni: vni id
    :param local: vxlan tunnel local vtep ip address
    :param remote: vxlan tunnel remote vtep ip address
    :param eth: ethernet name which local ip address belongs to
    :return: True or False
    """
    net_name = gen_network(vni)
    _add_network_pre_check(net_name)
    check_output_raise_exception(
        "docker network create --subnet %s %s" %
        (subnet, net_name))

    net_id = check_output_raise_exception(
        "docker network ls | grep %s | awk '{print $1}'" %
        net_name).strip()
    if not net_id:
        raise Exception("unlikely error, can not find net id of %s" % net_name)
    br_name = check_output_raise_exception(
        "brctl show | grep %s | awk '{print $1}'" % net_id).strip()
    if not br_name:
        raise Exception(
            "unlikely error, can not find bridge name of %s" %
            net_name)

    vxlan_name = _add_vxlan(eth, local, remote, vni)
    check_output_raise_exception("brctl addif %s %s" % (br_name, vxlan_name))


def _add_vxlan(eth, local, remote, vni):
    vxlan_name = gen_vxlan(vni)
    check_output_raise_exception(
        "ip link add %s type vxlan id %s remote %s local %s dstport 4789 dev %s" %
        (vxlan_name, vni, remote, local, eth))
    check_output_raise_exception("ip link set %s up" % vxlan_name)
    return vxlan_name


def add_network(args):
    """
    add docker network
    :param args: option list, sub slice from sys.argv
    :return: None, print usage and sys.exit() if encounter errors
    """
    try:
        opts, args = getopt.getopt(
            args, "s:v:l:r:e:", [
                "subnet=", "vni=", "local=", "remote=", "eth="])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(str(err))  # will print something like "option -a not recognized"
        add_network_usage()
        sys.exit(2)
    subnet, vni, local, remote, eth = None, None, None, None, None
    for o, a in opts:
        if o in ("-s", "--subnet"):
            subnet = a
        elif o in ("-v", "--vni"):
            vni = a
        elif o in ("-l", "--local"):
            local = a
        elif o in ("-r", "--remote"):
            remote = a
        elif o in ("-e", "--eth"):
            eth = a
        else:
            add_network_usage("unknown option " + o)
            sys.exit(2)
    all_ops = [subnet, vni, local, remote, eth]
    if not all(all_ops):
        add_network_usage("missing some options " + str(all_ops))
        sys.exit(2)
    _add_network(subnet, vni, local, remote, eth)


def add_docker_usage(err_msg=""):
    help_str = """
./vxlan_test.py add_docker [options]
    --ip,  docker ip address
    --name, docker name suffix, full style is vpc[id]-[name]
    --vni, vxlan vni id
    --mac, ip interface mac, optional
    --sip, secondary ip address, optional
    --arp, static arp, [ip]:[mac], optional. For example 192.168.1.1-00:01:02:03:04:05
"""
    if err_msg:
        print(err_msg + "\n")
    print(help_str)


def add_docker(args):
    try:
        opts, args = getopt.getopt(
            args, "", [
                "img=", "vni=", "ip=", "name=", "mac=", "sip=", "arp=", ])
    except getopt.GetoptError as err:
        # print help information and exit:
        add_docker_usage(str(err))
        sys.exit(2)
    ip, img, vni, name, mac, sip, arp = None, None, None, None, None, None, None
    for o, a in opts:
        if o == "--ip":
            ip = a
        elif o == "--img":
            img = a
        elif o == "--vni":
            vni = a
        elif o == "--name":
            name = a
        elif o == "--mac":
            mac = a
        elif o == "--sip":
            sip = a
        elif o == "--arp":
            arp = a
        else:
            add_docker_usage("unknown option " + o)
            sys.exit(2)
    should_ops = [ip, img, name, vni]
    if not all(should_ops):
        add_docker_usage("missing some options " + str(should_ops))
        sys.exit(2)

    network = gen_network(vni)
    docker_name = gen_docker(vni, name)
    _add_docker(docker_name, img, network, ip, mac, sip, arp)


def clean_docker_usage(err_msg=""):
    help_str = """
./vxlan_test.py clean_docker [options]
    -v | --vni, the vni id
"""
    if err_msg:
        print(err_msg + "\n")
    print(help_str)


def get_docker_with_prefix(docker_prefix):
    r = check_output_raise_exception(
        "docker ps -a | grep %s | awk '{print $NF}'" %
        docker_prefix)
    return r.splitlines()


def _clean_docker_instance(docker_prefix):
    """
    clean_docker all docker which name starts with docker_prefix
    :param docker_prefix:  docker name prefix
    :return: None, raise Exception if encounters error
    """
    for i in get_docker_with_prefix(docker_prefix):
        check_output_raise_exception("docker stop %s" % i)
        check_output_raise_exception("docker rm %s" % i)


def _clean_network(network_name, vxlan_name):
    """
    clean_docker docker network, the bridge bind to this network will be cleaned automatically.
    :param network_name: network name
    :param vxlan_name: vxlan interface name
    :return: None, raise Exception if encounters error
    """
    check_output_raise_exception("docker network rm %s || true" % network_name)
    check_output_raise_exception("ip link del %s || true" % vxlan_name)


def _clean_docker(vni):
    """
    clean_docker the resource of a vpc: docker network, vxlan device, dockers, etc.
    :param vni:
    :return:
    """
    docker_prefix = gen_docker_prefix(vni)
    _clean_docker_instance(docker_prefix)
    _clean_network(gen_network(vni), gen_vxlan(vni))


def clean_docker(args):
    try:
        opts, args = getopt.getopt(args, "v:", ["vni=", ])
    except getopt.GetoptError as err:
        # print help information and exit:
        clean_docker_usage(str(err))
        sys.exit(2)
    vni = None
    for o, a in opts:
        if o in ("-v", "--vni"):
            vni = a
        else:
            clean_docker_usage("unknown option " + o)
            sys.exit(2)
    all_ops = [vni, ]
    if not all(all_ops):
        clean_docker_usage("missing some options " + str(all_ops))
        sys.exit(2)
    _clean_docker(vni)
    print("clean_docker successfully, maybe some error messages has been displayed because the resource not exist")


def add_netns_usage(err_msg=""):
    help_str = """
./vxlan_test.py add_docker [options]
    --ip,  docker ip address
    --vni, vxlan vni id
    --mac, ip interface mac, optional
    --sip, secondary ip address, optional
    --arp, static arp, [ip]:[mac], optional. for example 192.168.1.1-00:01:02:03:04:05
    --local, vxlan tunnel local vtep ip address
    --remote, vxlan tunnel remote vtep ip address
    --eth, ethernet name where local vtep ip is configured on, such as eth1
"""
    if err_msg:
        print(err_msg + "\n")
    print(help_str)


def _add_netns_pre_check(vni):
    netns = gen_network(vni)
    r = check_output_raise_exception("ip netns ls | grep %s || true" % netns)
    if r != "":
        raise Exception("netns %s exists" % netns)


def _add_netns(vni):
    netns = gen_network(vni)
    check_output_raise_exception("ip netns add %s" % netns)
    check_output_raise_exception(
        "ip netns exec %s ip link set dev lo up" %
        netns)
    return netns


def _add_netns_br(vni):
    br = gen_br(vni)
    check_output_raise_exception("ip link add %s type bridge" % br)
    check_output_raise_exception("ip link set dev %s up" % br)
    return br


def _add_veth(vni, br, netns):
    """
    create a pair of veth and bind to bridge and netns
    :param vni: vxlan vni
    :param br: linux bridge name
    :param netns: linux netns name
    :return: veth pair name
    """
    tap, veth = gen_veth(vni)
    check_output_raise_exception(
        "ip link add %s type veth peer name %s" %
        (tap, veth))
    check_output_raise_exception("ip link set %s master %s" % (veth, br))
    check_output_raise_exception("ip link set %s up" % veth)
    check_output_raise_exception("ip link set %s name eth0 netns %s" % (tap, netns))
    check_output_raise_exception(
        "ip netns exec %s ip link set eth0 up" %
        netns)


def _add_netns_vtep(vni, ip, mac, sip, arp, eth, local, remote):
    """
    create vxlan vtep via netns
    :param vni: vxlan vni id
    :param ip: primary ip address
    :param mac: ip interface mac
    :param sip: secondary ip address, such as 169.254.0.201/24
    :param arp: static arp
    :param eth: ethernet name which local ip address belongs to
    :param local: vxlan tunnel local vtep ip address
    :param remote: vxlan tunnel remote vtep ip address
    :return: None, raise Exception if encounter errors
    """
    _add_netns_pre_check(vni)
    netns = _add_netns(vni)
    br = _add_netns_br(vni)
    vxlan_name = _add_vxlan(eth, local, remote, vni)
    _add_veth(vni, br, netns)
    check_output_raise_exception("brctl addif %s %s" % (br, vxlan_name))
    check_output_raise_exception(
        "ip netns exec %s ip addr add %s dev eth0" %
        (netns, ip))

    if mac:
        check_output_raise_exception(
            "ip netns exec %s ip link set dev eth0 addr %s" %
            (netns, mac))

    if sip:
        check_output_raise_exception(
            "ip netns exec %s ip addr add %s dev eth0" %
            (netns, sip))

    if arp:
        arp_ip, arp_mac = arp.split("-")
        check_output_raise_exception(
            "ip netns exec %s ip neigh add %s lladdr %s dev eth0" %
            (netns, arp_ip, arp_mac))

    check_output_raise_exception("iptables -t filter -I FORWARD -j ACCEPT")


def add_netns(args):
    try:
        opts, args = getopt.getopt(
            args, "", [
                "vni=", "ip=", "mac=", "sip=", "arp=", "eth=", "local=", "remote="])
    except getopt.GetoptError as err:
        # print help information and exit:
        add_netns_usage(str(err))
        sys.exit(2)
    ip, vni, mac, sip, arp, eth, local, remote = None, None, None, None, None, None, None, None
    for o, a in opts:
        if o == "--ip":
            ip = a
        elif o == "--vni":
            vni = a
        elif o == "--mac":
            mac = a
        elif o == "--sip":
            sip = a
        elif o == "--arp":
            arp = a
        elif o == "--eth":
            eth = a
        elif o == "--local":
            local = a
        elif o == "--remote":
            remote = a
        else:
            add_netns_usage("unknown option " + o)
            sys.exit(2)
    should_ops = [ip, vni, eth, local, remote]
    if not all(should_ops):
        add_netns_usage("missing some options " + str(should_ops))
        sys.exit(2)

    _add_netns_vtep(vni, ip, mac, sip, arp, eth, local, remote)


def clean_netns_vtep_usage(err_msg=""):
    help_str = """
./vxlan_test.py clean_netns [options]
    -v | --vni, the vni id
"""
    if err_msg:
        print(err_msg + "\n")
    print(help_str)


def _clean_netns_vtep(vni):
    netns = gen_network(vni)
    tap, veth = gen_veth(vni)
    br = gen_br(vni)
    vxlan_name = gen_vxlan(vni)
    check_output_raise_exception("ip netns del %s || true" % netns)
    check_output_raise_exception("ip link del %s || true" % veth)
    check_output_raise_exception("ip link del %s || true" % br)
    check_output_raise_exception("ip link del %s || true" % vxlan_name)


def clean_netns_vtep(args):
    try:
        opts, args = getopt.getopt(args, "v:", ["vni=", ])
    except getopt.GetoptError as err:
        # print help information and exit:
        clean_netns_vtep_usage(str(err))
        sys.exit(2)
    vni = None
    for o, a in opts:
        if o in ("-v", "--vni"):
            vni = a
        else:
            clean_netns_vtep_usage("unknown option " + o)
            sys.exit(2)
    all_ops = [vni, ]
    if not all(all_ops):
        clean_netns_vtep_usage("missing some options " + str(all_ops))
        sys.exit(2)
    _clean_netns_vtep(vni)
    print("clean_netns successfully, maybe some error messages has been displayed because the resource not exist")


def main():
    if len(sys.argv) < 2:
        usage()
        sys.exit(2)
    cmd = sys.argv[1]
    if cmd not in (
            CMD_ADD_NETWORK,
            CMD_ADD_DOCKER,
            CMD_CLEAN_DOCKER,
            CMD_ADD_NETNS,
            CMD_CLEAN_NETNS):
        usage("invalid command " + sys.argv[1])
        sys.exit(2)

    if cmd == CMD_ADD_NETWORK:
        add_network(sys.argv[2:])
    elif cmd == CMD_ADD_DOCKER:
        add_docker(sys.argv[2:])
    elif cmd == CMD_CLEAN_DOCKER:
        clean_docker(sys.argv[2:])
    elif cmd == CMD_ADD_NETNS:
        add_netns(sys.argv[2:])
    elif cmd == CMD_CLEAN_NETNS:
        clean_netns_vtep(sys.argv[2:])


if __name__ == "__main__":
    main()
