#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
####################################################################################################


####################################################################################################
# imports
from scapy.all import *
import argparse
import xml.etree.ElementTree as ET
from time import sleep, gmtime, strftime
####################################################################################################


####################################################################################################
# types
class colors:
    HEADER      =   '\033[95m'
    OKBLUE      =   '\033[94m'
    OKGREEN     =   '\033[92m'
    WARNING     =   '\033[93m'
    FAIL        =   '\033[91m'
    ENDC        =   '\033[0m'
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
class distance:
    def __init__(self,low,high,distance):
        self.low = low
        self.high = high
        self.distance = distance
####################################################################################################


####################################################################################################
# classes
class DISTANCES:
    def __init__(self):
        self.distance = 0
        self.distances = []
#...................................................................................................
    def add_distance(self,root):
        try:
            self.distance = int(root.find('no_level').find('distance').text)
        except:
            print_log("ERROR: can't load <distance> at <no_level> node",4)
            print_end()
            exit()
        if debug[7]:
            print_log('Without level distance',1)
            print_log(self.distance,1)
            print_end()
        return
#...................................................................................................
    def add_sub_distance(self,root):
        if root.find('level') == None:
            if debug[8]:
                print_log("Haven't <level> nodes",3)
                print_end()
            return
        else:
            for child in root.findall('level'):
                try:
                    self.distances.append(distance(int(child.find('low').text), \
                    int(child.find('high').text), int(child.find('distance').text)))
                except:
                    print_log("ERROR: can't load <level> node",4)
                    print_end()
                    exit()
        if debug[9]:
            for i in self.distances:
                print_log('Low: ', 1)
                print_log(i.low,1)
                print_log('High: ', 1)
                print_log(i.high,1)
                print_log('Distance',1)
                print_log(i.distance,1)
                print_end()
        for counter in xrange(0,len(self.distances)):
            etalon = self.distances[counter]
            if etalon.low > etalon.high:
                print_log("ERROR: low > high at node: ",4)
                print_log(counter,4)
                print_end()
                exit()
            for i in xrange(counter + 1,len(self.distances)):
                if (self.distances[i].low <= etalon.low and self.distances[i].high >= etalon.high) \
                    or (etalon.low <= self.distances[i].low and etalon.high >= self.distances[i].low) \
                    or (etalon.low <= self.distances[i].high and etalon.high >= self.distances[i].high):
                    print_log("ERROR: nodes conflict: ",4)
                    print_log(counter,4)
                    print_log(i,4)
                    print_end()
                    exit()
        return
    def get_distance(self,length):
        for i in self.distances:
            if length >= i.low and length <= i.high:
                return i.distance
        return self.distance
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
class packet:
    def __init__(self, p):
        if Ether in p:
            self.mac_src = p[Ether].src
            self.mac_dst = p[Ether].dst
        else:
            self.mac_src = ''
            self.mac_dst = ''
        if IP in p:
            self.ip_src = p[IP].src
            self.ip_dst = p[IP].dst
        else:
            self.ip_src = ''
            self.ip_dst = ''
        if TCP in p:
            self.port_src = p[TCP].sport
            self.port_dst = p[TCP].dport
            self.type = 'TCP'
        elif UDP in p:
            self.port_src = p[UDP].sport
            self.port_dst = p[UDP].dport
            self.type = 'UDP'
        else:
            self.port_src = -1
            self.port_dst = -1
            self.type = 'Other'
        if Raw in p:
            self.payload = [i for i in p[Raw].load]
        else:
            self.payload = []
        self.group = -1
#...................................................................................................
    def print_packet(self):
        print_log(self.mac_src,1)
        print_log(self.mac_dst,1)
        print_log(self.ip_src,1)
        print_log(self.ip_dst,1)
        print_log(self.port_src,1)
        print_log(self.port_dst,1)
        print_log(self.type,1)
        print_log(self.group,1)
        if debug[10]:
            print_log(''.join(i for i in self.payload),1)
        else:
            for i in self.payload:
                print_log(format(ord(i), '02x'),1)
        print_end()
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
class group:
    def __init__(self, p, number):
        self.mac_src    = p.mac_src
        self.mac_dst    = p.mac_dst
        self.ip_src     = p.ip_src
        self.ip_dst     = p.ip_dst
        self.port_src   = p.port_src
        self.port_dst   = p.port_dst
        self.type       = p.type
        self.group      = number
        self.payload    = list(p.payload)
        self.mask       = ['\x00' for i in self.payload]
        self.distance   = 0
        if debug[12]:
            print_log(self.mac_src,1)
            print_log(self.mac_dst,1)
            print_log(self.ip_src,1)
            print_log(self.ip_dst,1)
            print_log(self.port_src,1)
            print_log(self.port_dst,1)
            print_log(self.type,1)
            print_log(self.group,1)
            print_log(''.join(i for i in self.payload),1)
            print_end()
    def check_packet(self, p):
        global config
        if  p.group != -1 or\
            not self.mac_src in p.mac_src or\
            not self.mac_src in p.mac_src or\
            not self.mac_dst in p.mac_dst or\
            not self.ip_src  in p.ip_src or\
            not self.ip_dst  in p.ip_dst or\
            self.port_src != p.port_src or\
            self.port_dst != p.port_dst or\
            not self.type in p.type or\
            len(self.payload) != len(p.payload):
            return False
        else:
            time_mask = list(self.mask)
            time_payload = list(self.payload)
            time_distance = self.distance
            for i in xrange(0,len(self.payload)):
                if not time_payload[i] in p.payload[i]:
                    if time_mask[i] == '\xFF':
                        continue
                    elif time_distance < config.get_distance(len(self.payload)):
                        time_mask[i] = '\xFF'
                        time_distance = time_distance + 1
                        time_payload[i] = '__'
                        continue
                    else:
                        return False
            self.payload = list(time_payload)
            self.mask = list(time_mask)
            self.distance = time_distance
            return True
    def print_group(self):
        #if self.port_dst != self.port_src or "10.4.0.6" != self.ip_src:
        #    return
        print_log(self.mac_src,1)
        print_log(self.mac_dst,1)
        print_log(self.ip_src,1)
        print_log(self.ip_dst,1)
        print_log(self.port_src,1)
        print_log(self.port_dst,1)
        print_log(self.type,1)
        print_log(self.group,1)
        print_log(len(self.payload),3)
        print_end()
        for i in self.mask:
            if i == '\xFF':
                print_log(format(ord(i), '02x'),4)
            else:
                print_log(format(ord(i), '02x'),1)
        print_end()
        if debug[13]:
            print_log(''.join(i for i in self.payload),1)
        elif debug[15]:
            print_end()
            for i in self.payload:
                if i == '__':
                    print_log(i,4)
                else:
                    #print_log('\\x'+str(format(ord(i), '02x')),1)
                    print_log(format(ord(i), '02x'),1)
        else:
            for i in self.payload:
                if i == '__':
                    print_log(i,4)
                else:
                    print_log(format(ord(i), '02x'),1)
        print_end()
        print_end()
####################################################################################################


####################################################################################################
# global variables
max_debug_levels = 20
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
GUI_on = False 
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
debug = [False for i in xrange(0,max_debug_levels)]
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
config = DISTANCES()
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
packets_list = []
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
groups_list = []
####################################################################################################


####################################################################################################
# functions
def print_time():
    if debug[0]:
        f = open('log.txt','a')
        f.write(strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())+'\n')
        f.close()
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def print_log(info, level):
    if debug[0]:
        f = open('log.txt','a')
        f.write(str(info)+' ')
        f.close()
    elif not debug[1]:
        print info,
        return
    elif level == 0:
        print colors.HEADER,info,colors.ENDC,
        return
    elif level == 1:
        print colors.OKBLUE,info,colors.ENDC,
        return
    elif level == 2:
        print colors.OKGREEN,info,colors.ENDC,
        return
    elif level == 3:
        print colors.WARNING,info,colors.ENDC,
        return
    elif level == 4:
        print colors.FAIL,info,colors.ENDC,
        return
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def print_end():
    if debug[0]:
        f = open('log.txt','a')
        f.write('\n')
        f.close()
    else:
        print
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def arguments_parser():
    global debug
    global GUI_on
    global packets_list
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--gui', action='store_true', help='set GUI mode on')
    parser.add_argument('-d', '--debug', type=int, action='append', \
    choices=[i for i in xrange(0,max_debug_levels)], help='turn on debug output')
    parser.add_argument('files', metavar='PCAPs', type=str, nargs='+', help='list of pcap files')
    args = parser.parse_args()
#...................................................................................................
    if args.gui:
        GUI_on = True
#...................................................................................................
    if args.debug != None:
        for i in args.debug:
            debug[i] = True
#...................................................................................................
    print_time()
#...................................................................................................
    if debug[2]:
        for i in debug:
            if i:
                print_log(i,1)
            else:
                print_log(i,3)
        print_end()
#...................................................................................................
    if debug[3]:
        print_log("GUI: ",3)
        print_log(GUI_on,3)
        print_end()
#...................................................................................................
    if debug[4]:
        for file in args.files:
            print_log(file,1)
        print_end()
#...................................................................................................
    for file in args.files:
        packets = rdpcap(file)
        for p in packets:
            packets_list.append(packet(p))
#...................................................................................................
    if debug[5]:
        counter = 0
        for p in packets_list:
            print_log(counter,3)
            print_end()
            p.print_packet()
            counter = counter + 1
#...................................................................................................
    return
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def read_config():
    global config
    if debug[6]:
        root = ET.fromstring('<data><no_level><distance>25</distance></no_level></data>')
    else:
        try:
            xml = ET.parse('config.xml')
            root = xml.getroot()
        except:
            print_log("ERROR: can't read 'config.xml' file, maybe file don't exist or bad format",4)
            print_end()
            exit()
    config.add_distance(root)
    config.add_sub_distance(root)
    return
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def div_to_groups():
    global packets_list
    global groups_list
    number = 0
    for counter in xrange(0,len(packets_list)):
        if packets_list[counter].group == -1:
            groups_list.append(group(packets_list[counter],number))
            for i in xrange(counter + 1,len(packets_list)):
                if groups_list[number].check_packet(packets_list[i]):
                    packets_list[i].group = number
            number = number + 1
    if debug[11]:
        print_log('Number of groups: ',3)
        print_log(number,3)
        print_log(len(groups_list),3)
        print_end()
    if debug[14]:
        for g in groups_list:
            g.print_group()
    return
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def test():
    print "test"
    return
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def main():
    print "main"
    return
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def GUI():
    print "GUI"
    return
####################################################################################################


####################################################################################################
# programm start point
if __name__ == "__main__":
    arguments_parser()
    read_config()
    div_to_groups()
    main()
    test()
    GUI()
####################################################################################################


####################################################################################################