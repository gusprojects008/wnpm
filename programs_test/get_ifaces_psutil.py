import psutil

def getInterfaces():
    interfaces = psutil.net_if_addrs()
getInterfaces()
