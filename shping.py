from scapy.all import *
import dns.resolver
import sys


def documentation(): #help message describing usage of the program
    """
    TODO: write precise arguments in usage category
    """
    documentation_string = "\nThis is a ping-like Scapy-based python script\nusage: python shping.py <destination address> <argument 1> <argument 2>..\nexample: python shping.py www.google.com TTL=64" 
    return documentation_string


def valid_ip(ip): #checks validity of ip adress given by user
    def valid_domain():
        try:
            dns.resolver.resolve(ip, 'A')
            return True
        except:
            return False
    
    
    def valid_num_ip(parts):
        if len(parts) != 4:
            return False
        
        for part in parts:
            ip_val = int(part)
            if ip_val > 255 or ip_val < 0:
                return False
        return True
    
    
    ip_parts = ip.split('.')
    for part in ip_parts:
        if not part.isdigit():
            return valid_domain()
    return valid_num_ip(ip_parts)


def send_ping(args): #sends message to ip given by user
    def check_ip(arg):
        ip_parts = arg.split('.')
        for part in ip_parts:
            if not part.isdigit():
                arg_resolve = dns.resolver.resolve(arg, 'A')
                for ip_val in arg_resolve:
                    arg = ip_val.to_text()
                return arg
        return arg
    
    def icmp_filter(pkt):
        return ICMP in pkt
    
    dst_ip = check_ip(args[1])

    ping = IP(dst = dst_ip)/ICMP()
    ping.show()
    replies = []
    for i in range(4):
        send(ping)
        echo = sniff(count=1, lfilter=icmp_filter)
        replies.append(echo)
    return replies
    

def display_replies(replies): #displays the results collected from ping
    """
    TODO: write out src, dst, ttl, t
    """
    for reply in replies:
        reply.show()


def main(sys_args):
    if sys_args[1] == 'help' or len(sys_args)<1:
        print(documentation())
    elif valid_ip(sys_args[1]):
        replies = send_ping(sys_args)
        display_replies(replies)
    else:
        print("Invalid IP address entered. use 'python shping.py help' for assistance")


if __name__ == "__main__":
    main(sys.argv)