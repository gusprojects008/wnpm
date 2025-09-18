# SCRIPT FOR ARCH LINUX, CONFIGURATION OF NETWORK, SIMPLE AND EASY!!!

# INPUTS EXPLAINING WHAT SHOULD INSERT AT HER
# CREATE ARCHIVER OF CONFIGURATION, FOR INIT WITH SYSTEM AND CONNECT IN NETWORK, OPTIONAL
# INPUT FOR USER CHOSE IF HE WANTS, DEFINE A SERVER DNS AUTOMATE OR MANUALLY!!!

# ALERT FOR USER EXECUTE THE PROGRAM IN VENV(AMBIENT VIRTUAL PYHTHON) INSTALL IWD AND 
# LIBRARIESS NEEDED IN ORDER. THIS PROGRAM SHOULD BE INSTALLED IDEALLY IN CHROOT IN MOMENT OF
# INSTALLATION OF ARCH LINUX!!! 

# PHASES STEP: VALIDATION DETAILED OF DATA AND FILTER OF DATA 

# MODULES BY DEFAULT IN PYTHON
import time
import subprocess
import getpass
import random
import socket
import os
import sys

# FUNCTIONALITIES ADDITIONAL: dhcp scan(checked), privacy mode(), auto config(), ipv6 optional(), verifcation for see've internet it's working
# VERIFY IF CONFIGURATION AUTO ALREADY EXIST 

# CODES ANSI FOR COLERED THE TERMINAL AND TEXT APRESENTED FOR USER
class colors:
      red = "\033[31m"
      green = "\033[32m"
      blue = "\033[34m"
      cyan = "\033[36m"
      purple = "\033[35m"
      reset = "\033[0m"
      pink = "\033[95m"

      # FORMAT TEXT
      bright = '\033[1m'
      background_green = '\033[32m'
      background_red = '\033[41m'
      blink = '\033[5m'
      sublime = '\033[4m'

      # COLOR + BRIGHT
      sb = f'{bright}{sublime}'
      gb = f'{bright}{green}'
      bb = f'{bright}{blue}'

# FLAGS FOR ALERT THE USER
class flags:
      ok = f'{colors.bright}{colors.green}[ * ]{colors.reset}'
      error = f'{colors.bright}{colors.red}[ * ]{colors.reset}'
      finalization = f'{colors.purple}{colors.bright}[ * ]{colors.reset}'      

# EFFECT MACHINE WRITE
def typewriter(text):
    for char in text:
        print(char, end='', flush=True) 
        speed = 0.02
        time.sleep(speed)

# INSTALLATION OF THE PACKETS NECESSARYS:
def install(path):
    # FLAG FOR USER KNOW WHAT SHOULD ARE EXECUTING
    text_alert = f"{flags.ok}{colors.blue} INSTALLING IWD AND LIBRARIES NEEDED ...{colors.reset}\n"
    typewriter(text_alert)

    # INSTALLING IWD AND LIBRARIES NEEDED FOR EXECUTION OF THE PROGRAM AND DIRECTING OUTPUT OF THE COMMANDS FOR FILES
    with open(path, 'w') as file_log:
         try:
            install_iwd = subprocess.run(['pacman', '-Syu', '--noconfirm', 'iwd'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
            install_libraries = subprocess.run(['pip', 'install', 'netifaces', 'scapy', 'ipaddress', 'wifi'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
            file_log.write(f"Output of the result of the command of installation of the IWD: {install_iwd.stdout.decode('utf-8')} \nResult of the operation of instalation of the libraries needed!!! {install_libraries.stdout.decode('utf-8')} \n")
         except Exception as error:
                print(f'{flags.error}{colors.blue} POSSIBLE ERROR: {colors.sb}NETWORK{colors.reset}\n')
                file_log.write(f"\n Error => {str(error)}")
         finally:
                text_finally = f"\n{flags.finalization}{colors.blue} see've results of installation in {colors.sb}{path}{colors.reset}\n\n"
                typewriter(text_finally)

# GETTING ADAPTER OF NETWORK AUTOMATICALLY
def get_interface():
    import netifaces
    interfaces_user = netifaces.interfaces()
    interface_find = [interface for interface in interfaces_user if 'wlan0' in interface or 'wlp' in interface or 'wlan' in interface or 'wlan1' in interface]
    return interface_find[0]

# GETTING ADDRESSES: MAC, MAC_BROADCAST OF THE ADAPTER INTERAFACE FOUND...
# THE INTERFACE COULD IT BE, THE INTERFACE ASSIGNMENT AUTOMATICALLY OR THE INTERFACE MANUALLY 
def get_addresses(interface):
    import netifaces
    address_interface = netifaces.ifaddresses(interface)
    if netifaces.AF_LINK in address_interface:
       return address_interface[netifaces.AF_LINK][0]

# SHOW NETWORKS CLOSE AVAILABLE
def show_networks(interface):
    import netifaces
    interfaces_availables = netifaces.interfaces()
    try: 
       if interface in interfaces_availables:
          text_alert = f"\n{flags.ok}{colors.gb} NETWORKS AVAILABLES: SSID: {colors.sublime}<NETWORK AVAILABLE>\n{colors.reset}"
          typewriter(text_alert)
          print('\n')
          scan_networks = subprocess.Popen(['iw', interface, 'scan'], stdout=subprocess.PIPE)
          grep_ssid = subprocess.run(['grep', 'SSID:'], stdin=scan_networks.stdout)
          return True
       else:
           print(f'\n{flags.error}{colors.bb} ERROR: TYPE IT INTERFACE AVAILABLE...{colors.reset}\n')
           return False

    except Exception as error:
           message_error = f"\n{flags.error}{colors.bb}DONT'T POSSIBLE SHOW NETWORKS AVAILABLE ...{colors.reset} {str(error)}\n"
           print(message_error)
           return False

# SHOW INTERFACES OF ADAPTERS LOCALS
def interfaces_local():
    import netifaces
    text_alert = f"{colors.blue}INTERFACES WIRELESS USUALLY START WITH {colors.cyan}{colors.bright}WLAN{colors.blue} ...{colors.reset}\n"
    typewriter(text_alert)
    interfaces_local = netifaces.interfaces()
    for interface in interfaces_local:
        interfaces_found = f"{colors.bb}INTERFACE FOUND =» {colors.cyan}{interface}{colors.reset} \n"
        typewriter(interfaces_found)
    print('\n')
    
# TEST INTERNET
def internet_test(interface):
    from scapy.layers.inet import IP, ICMP
    from scapy.sendrecv import sr1

    icmp_packet = IP(dst='1.1.1.1')  / ICMP()

    try:
       sent_packet_response = sr1(icmp_packet, iface=interface, timeout=20)
       if sent_packet_response:
          return True
       else:
           return False
    except:
          return False

def commands_ip(interface, ip, ip_gateway):
    try:
       subprocess.run(['ip', 'addr', 'flush', 'dev', interface])
       subprocess.run(['ip', 'addr', 'add', ip, 'dev', interface])
       subprocess.run(['ip', 'route', 'add', 'default', 'via', ip_gateway])
    except Exception as error:
           print(f'\n{flags.error}{colors.bb} ERROR =» ASSIGN ADDRESSES IP OF NETWORK ==> {colors.purple}{str(error)}{colors.reset}')           

def handle_packets(packet):  
    from scapy.layers.inet import IP
    from scapy.layers.dhcp import DHCP, BOOTP
    try:
       interface = get_interface()
       if packet.haslayer(DHCP) or packet.haslayer(BOOTP):
          address_gateway = f'{packet['IP'].src}'
          address_offered = packet['BOOTP'].yiaddr
          subnet_mask = packet['DHCP'].options[3][1]

          #print(address_gateway, address_offered, subnet_mask)

          # CONVERTING SUBNET_MASK IN CIDR(ROUTING DOMAINS IN CLASSES)
          subnet_mask_split = subnet_mask.split('.')
          subnet_mask_bin = [(bin(int(octet))[2:].zfill(8)) for octet in subnet_mask_split]
          subnet_mask_join_bin = ''.join(subnet_mask_bin)
          cidr_value = subnet_mask_join_bin.count('1')
          address_ip = f'{address_offered}/{cidr_value}'

          #print(subnet_mask_split, subnet_mask_bin, subnet_mask_join_bin, cidr_value, address_ip) 

          # SETUP NETWORK AUTOMATICALLY WITH INFO OBTAIN
          commands_ip(interface, address_ip, address_gateway)
 
    except Exception as error:
           print(f'\n{flags.error}{colors.bb} Error: TO GET INFORMATION OR SETUP NETWORK => {str(error)}{colors.reset}\n')

def operation_auto(interface):
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, UDP
    from scapy.layers.dhcp import DHCP, BOOTP, RandInt
    from scapy.layers.dot11 import sniff
    from scapy.sendrecv import sendp

    addresses = get_addresses(interface)
    mac_address = addresses.get('addr')
    mac_broadcast = addresses.get('broadcast')

    # TYPE OF THE REQUISITION DHCP FOR GATEWAY SERVER
    dhcp_options = [('message-type', 'discover'), ('requested_addr', '192.168.0.100'), 
                   ('subnet_mask', '0.0.0.0'), 'end', ('pad', b'\x00')]
    dhcp_discover_packet = Ether(dst=mac_broadcast, src=mac_address) / IP(src="0.0.0.0", dst="255.255.255.255") / \
                           UDP(sport=68, dport=67) / BOOTP(op=1, chaddr=mac_address, xid=RandInt(), flags=0x8000) / \
                           DHCP(options=dhcp_options)

    # SENDP, SEND 1 PACKET AND DON'T WAIT RESPONSE
    print('\n')
    sendp(dhcp_discover_packet, iface=interface)

    # HUNT RESPONSE OF THE GATEWAY FOR 10 SECONDS, RESPONSE EXCEPTED: DHCP OFFER AND PERFORMS AN OPERATION ON
    # FOR EACH PACKET CAPTURED
    print(f'\n{flags.ok}{colors.gb} CAPTURE RESPONSE ROUTER ...{colors.reset}\n')
    sniff(filter='udp and (port 67 or port 68)', iface=interface, timeout=10, store=True, prn=handle_packets)

def validate_ipv4_ipv6(ip):
    import ipaddress
    try:
       ipaddress.ip_address(ip)
       return True
    except:
          return False

def operation_manual(interface):
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.inet import IP
    from scapy.sendrecv import srp

    while True:
          text_ip = f'\n{colors.gb}TYPE IT A ADDRESS IPV4 OF YOUR NETWORK: {colors.reset}'
          typewriter(text_ip)
          ip = input()

          if validate_ipv4_ipv6(ip):
             ip_value = ip.split('.')
             ip_value.pop(-1)
             ip_value.append('0') # FORMATING OF THE IP ADDRESS
             ip_formater = '.'.join(ip_value)

             text_input_cidr = f"\n{colors.green}{colors.bright}TYPE IT CIDR FOR CONNECT IN SUBNET IN THE NETWORK: {colors.reset}"
             typewriter(text_input_cidr)
             cidr_ip = input()[:2] # CIDR OF THE NETWORK IP ADDRESS, IS FOR THE COMPUTER TO KNOW WHICH SUBNET YOU ARE ON THE NETWORK AND THUS COMMUNICATE WITH OTHER DEVICES THAT ARE ON THE SAME SUBNET WITH THE SAME IP ADDRESS FORMAT.
             
             ip_formated = f"{ip_formater}/{cidr_ip}" # IP FORMATTED

             addresses = get_addresses(interface)
             ip_broadcast = addresses.get('broadcast') # ADDRESS TO COMMUNICATE WITH ALL DEVICES ON THE NETWORK.
             mac_address = addresses.get('addr')

             packet_arp = Ether(src=mac_address, dst=ip_broadcast) / ARP(op=1, hwsrc=mac_address, pdst=ip_formated) # PACKET ARP ENCAPSULATED WITH FORMAT ETHERNET PROTOCOL

             #print(ip_formated)

             print('\n')
             packets, packets_no_reply = srp(packet_arp, iface=interface, timeout=5) # THE FIRST VARIABLE STORES PACKAGES SENT AND PACKETS RECEIVED, THE SECOND VARIABLE STORES PACKAGES SENT BUT NO RESPONSE AFTER 5 SECONDS OF WAITING .

             hosts_on = [] # LIST OF HOSTS ON WITH IP ADDRESS AND HOSTNAME 
             hosts_off = [] # LIST OF IP ADDRESS OF HOSTS OFF

             for packets_sent, packets_recv in packets: # ITERATING OVER STORED PACKAGES SENT AND RECEIVED IN THE PACKETS VARIABLE
                 if packets_recv:
                    ip_host_on = packets_recv.psrc
                    try:
                        host = socket.gethostbyaddr(ip_host_on) 
                        hosts_on.append(host)
                    except socket.herror:
                           pass
             for packets_sent in packets_no_reply: # ITERATING OVER STORED PACKAGES IN VARIABLE: packets_no_reply, PACKETS SENT BUT NO REPLY
                 ip_host_off = packets_sent.pdst
                 try:
                     host = socket.gethostbyaddr(ip_host_off)
                     hosts_on.append(host)
                 except socket.herror:
                        hosts_off.append(ip_host_off)

             try:
                random_number = random.randint(10, 240) # CHOOSING IP ADDRESS NOT USED IN: HOSTS_OFF BY: RANDOM INDEX
                ip_assign = f'{hosts_off[random_number]}/{cidr_ip}'
                ip_gateway = hosts_on[0][2][0]

                text_question = f'\n{flags.ok}{colors.blue} YOU WANT THIS CONFIGURATION OF ADDRESSES?: {colors.gb}TYPE IT 1 IF YES OR 2 FOR MANUAL CONFIGURATION ==>{colors.reset}'
                print(text_question)
                print(f"\n{flags.ok}{colors.bb} ADDRESS GATEWAY ROUTER:{colors.cyan} {ip_gateway}{colors.bb}, YOUR ADDRESS IP:{colors.cyan} {ip_assign}{colors.bb}, IN ADAPTER INTERFACE:{colors.cyan} {interface}{colors.reset}\n")
                question_option = input(f'{colors.gb}TYPE IT 1 FOR YES {colors.bb}OR {colors.red}2 FOR MANUAL SETUP ADDRESSES: {colors.reset}')

                if question_option == "1":
                   commands_ip(interface, ip_assign, ip_gateway)
                  
                elif question_option == "2":
                     print(f'\n{flags.ok}{colors.gb} MANUAL CONFIGURATION ==>{colors.reset}\n')
                     
                     ip_address = input(f'{colors.gb}TYPE IT THE YOUR ADDRESS IP FOR NETWORK: {colors.reset}')
                     print('\n')
                     gateway = input(f'{colors.gb}TYPE IT GATEWAY ROUTER ADDRESS: {colors.reset}')
                     print('\n')

                     cidr = input(f'{colors.gb}TYPE IT THE CIDR OF THE SUBNET FROM YOUR NETWORK: {colors.reset}')[:2]
                     ip_address_formated = f'{ip_address}/{cidr}'

                     commands_ip(interface, ip_address_formated, gateway)
                     print('\n')
                break
 
             except Exception as error:
                    print(f'\n{flags.error}{colors.bb} IT WAS NOT POSSIBLE SETUP NETWORK ==> {str(error)}{colors.reset}')
 
                    print(f'\n{flags.ok}{colors.gb} MANUAL CONFIGURATION ==>{colors.reset}\n')
                    ip_address = input(f'{colors.gb}TYPE IT THE YOUR ADDRESS IP FOR NETWORK: {colors.reset}')
                    print('\n')
                    gateway = input(f'{colors.gb}TYPE IT GATEWAY ROUTER ADDRESS: {colors.reset}')
                    print('\n')
                    cidr = input(f'{colors.gb}TYPE IT THE CIDR OF THE SUBNET FROM YOUR NETWORK: {colors.reset}')[:2]
                    print('\n')
                    ip_address_formated = f'{ip_address}/{cidr}'
   
                    commands_ip(interface, ip_address_formated, gateway)
                    break
          else:
              print(f'\n{flags.error}{colors.bb} TYPE IT OPTION VALID...')

# ANALYSATION OF THE NETWORK LOCAL AND CONFIGURATION OF NETWORK...
def analysis_network_configuration(interface):
    while True:
          option_text = f"\n{colors.gb}TYPE IT {colors.red}1 FOR SETUP ADDRESS NETWORK AUTOMATIC {colors.purple}*IMPRECISE*{colors.green} OR TYPE IT 2 FOR SETUP NET MANUALLY: {colors.reset}"
          typewriter(option_text)
          option = input()

          # IF IP IS EQUAL TO 1: AUTOMATIC SETUP NETWORK. ELSE: SETUP MANUALLY
          if option == '1':
             operation_auto(interface)
             if internet_test(interface):
                break
             else:
                 print(f'\n{flags.error}{colors.blue} SORRY ); COULD TO NOT POSSIBLE SETUP OF THE ADDRESSES... TRY MANUALLY{colors.reset}')
                 print(f'\n{flags.ok}{colors.bb} TRYING NOW ...{colors.reset}')
                 operation_manual(interface)
                 if internet_test(interface):
                    break
                 else:
                     print(f'\n{flags.error}{colors.blue} COULD TO NOT POSSIBLE SETUP OF THE ADDRESSES...{colors.reset}')
                     break
          elif option == '2':
                operation_manual(interface)
                if internet_test(interface):
                   break
                else:
                    print(f'\n{flags.error}{colors.blue} SORRY ); COULD TO NOT POSSIBLE SETUP OF THE ADDRESSES... TRY AUTMOMATIC{colors.reset}')
                    print(f'\n{flags.ok}{colors.bb} YOU WANT SETUP ADDRESSES AUTOMATICALLY? TYPE IT 1 IF YES OR 2 FOR NOT: {colors.reset}')
                    option_auto = input(f'{colors.gb}TYPE IT 1 FOR AUTOMATIC OR 2 FOR NOT: {colors.reset}')

                    if option_auto == '1':
                       operation_auto(interface)
                       if internet_test(interface):
                          break
                       else: 
                           print(f'\n{flags.error}{colors.blue} COULD TO NOT POSSIBLE SETUP OF THE ADDRESSES...{colors.reset}')
                           break
                    elif option == '2':
                         break
                    else:
                        print(f'\n{flags.error}{colors.gb} TYPE IT VALID OPTION...{colors.reset}')
                        break
          else:
              print(f'\n{flags.error}{colors.purple} TYPE IT: {colors.sb}1 OR 2{colors.reset}')

def connect_network(network, passphrase, interface):
    import wifi
    try:
       APS = wifi.Cell.all(interface)
       for ap in APS:
           if ap.ssid == network:
              subprocess.run(['iwctl', '--passphrase', passphrase, 'station', interface, 'connect', network], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)   
              return True
    except Exception as error:
           print(f'\n{flags.error}{colors.bb} ERROR =» CONNECTION IN NETWORK ==> {colors.purple}{str(error)}{colors.reset}')
           return False

# CONFIGURATION OF THE USER
def init_config():
    import netifaces

    # INPUT OF ADAPTER OF NETWORK
    interfaces_local()

    text_input_adapters = f"{colors.green}{colors.bright}TYPE IT THE ADAPTER OF NETWORK OR TYPE IT: {colors.red}1{colors.green} ASSIGN AUTOMATICALLY {colors.red}*IMPRECISE*{colors.green}: {colors.reset}"
    typewriter(text_input_adapters)
    adapter_wireless = input()
          
    if adapter_wireless == '1': # CONFIGURATION AUTOMATICALLY IF VALUE OF INPUT adapter_wireless IS EQUAL THE 1

       interface_get = get_interface()
       if show_networks(interface_get):

          try:
             print('\n')
             text_input_network = f"{colors.green}TYPE IT THE NETWORK FOR CONNECT: {colors.reset}"
             print(text_input_network)
             network = input()
 
             text_input_passphrase = f"{colors.green}TYPE IT {colors.red}PASSWORD(PSK){colors.green} OF YOUR NETWORK {colors.reset}"
             print(text_input_passphrase)
             passphrase = getpass.getpass()             

             if connect_network(network, passphrase, interface_get):
                analysis_network_configuration(interface_get)

          except Exception as error:
                 print(f"\n{flags.error}{colors.bb} Network or passphrase invalid or adapter Not found try manually... {str(error)}{colors.reset}\n")
          finally:
                 text_finaly = f"\n{flags.finalization}{colors.bb} SETUP CONFIGURATION NETWORK, FINALIZED!!!...{colors.reset}\n"       
                 typewriter(text_finaly)
    else:
        if show_networks(adapter_wireless):
           try:
              print('\n')
              text_input_network = f"{colors.green}TYPE IT THE NETWORK FOR CONNECT: {colors.reset}"
              print(text_input_network)
              network = input()

              text_input_passphrase = f"{colors.green}TYPE IT {colors.red}PASSWORD(PSK){colors.green} OF YOUR NETWORK {colors.reset}"
              print(text_input_passphrase)
              passphrase = getpass.getpass()
              
              if connect_network(network, passphrase, adapter_wireless):
                 analysis_network_configuration(adapter_wireless)

           except Exception as error:
                  print(f"\n{flags.error}{colors.bb} Network or passphrase invalid or adapter Not found try Manually... {str(error)} {colors.reset}")

           finally:
                  text_finaly = f"\n{flags.finalization}{colors.bb} SETUP CONFIGURATION NETWORK, FINALIZED!!!...{colors.reset}\n"
                  typewriter(text_finaly)
        
                
    # text_input_dns = f'{colors.green}TYPE IT YOUR DNS SERVER OR ASSIGN AUTOMATICALLY TYPE IT 1{colors.green}'
    #typewriter(text_input_dns, speed_text)
    #dns_server = input()

    #text_input_file_optional = f'{colors.green}YOU WANT CREATE A CONFIG FILE FOR INIT WITH SYSTEM AND CONENCT THE NETWORK AUTOMATICALLY? {colors.blue}Y/n{colors.green} :{colors.reset} '
    #typewriter(text_input_file_optional, speed_text)
    #file_config = input()
    
    
    # CONFIGURATION BASED IN INPUT OF THE USER!
    #if 

# VERFICATION IS USER IT'S AT IN AMBIENT PYTHON FOR RUNNING CODE WITH COMPACTIBILITY AND SECURITY!!! 
def verification_user_environ():
    if 'VIRTUAL_ENV' in os.environ:       
       path_file = './log_netconfig.txt'
 #      install(path_file)
       init_config()
    else:
        text_alert = f"{flags.error}{colors.bb} ENTER AN ENVIRONMENT VIRTUAL {colors.red}PYTHON{colors.bb} FOR {colors.red}RUNNING CODE{colors.bb} WITH {colors.red}COMPACTIBILITY{colors.bb} AND {colors.red}SECURITY{colors.bb} !!!{colors.reset}\n"
        typewriter(text_alert)
        subprocess.run(['source', '/path/to/new/virtual/environment/bin/activate'], shell=True)

verification_user_environ()
