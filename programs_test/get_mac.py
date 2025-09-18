import psutil

def get_address():
    address_interface = psutil.net_if_addrs()

    for addr_interface in address_interface:
        for info in address_interface.get(addr_interface):
            if psutil.AF_LINK in info:
               print(info.address)
            
get_address()
