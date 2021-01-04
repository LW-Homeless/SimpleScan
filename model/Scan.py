from scapy.all import sr1
from scapy.all import TCP
from scapy.all import IP
from scapy.all import ICMP
from model.ListPort import ListPort
import concurrent.futures


class Scan:

    def __init__(self):
        self.__response = None
        self.__list_port = ListPort()
        self.__result_scan = []

    def connect_scan(self, ip, port):

        probe = sr1(IP(dst=ip) / TCP(dport=port, flags="S"), verbose=False, timeout=3)
        if probe is not None:
            if probe.haslayer(TCP) and probe.getlayer(TCP).flags == 0x12:
                sr1(IP(dst=ip) / TCP(dport=port, flags="AR"), verbose=False, timeout=3)
                return [port, "TCP", "Abierto", self.__list_port.get_sevice("TCP", port)]

    def stealth_scan(self, ip, port):

        probe = sr1(IP(dst=ip) / TCP(dport=port, flags="S"), verbose=False, timeout=3)

        if probe is not None:
            if probe.haslayer(TCP) and probe.getlayer(TCP).flags == 0x12:
                sr1(IP(dst=ip) / TCP(dport=port, flags="R"), verbose=False, timeout=3)
                return [port, "TCP", "Abierto", self.__list_port.get_sevice("TCP", port)]
            elif probe.haslayer(ICMP):
                if int(probe.getlayer(ICMP).type) == 3 and int(probe.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                    return [port, "TCP", "Filtrado", self.__response.sport]

    def ack_scan(self, ip, port):

        probe = sr1(IP(dst=ip) / TCP(dport=port, flags="A"), verbose=False, timeout=3)
        if probe is not None:
            return 1
        elif probe.haslayer(ICMP):
            if int(probe.getlayer(ICMP).type) == 3 and int(probe.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                return 0
            else:
                return 0

    # Method that executes the selected scanner and assigns to a set of threads to improve performance
    def run_scan(self, ip, ports, type_scan):

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:

            if type_scan == "C":

                result_probe = {executor.submit(self.connect_scan, ip, port): port for port in ports}
                executor.shutdown(wait=True)

            elif type_scan == "S":
                result_probe = {executor.submit(self.stealth_scan, ip, port): port for port in ports}
                executor.shutdown(wait=True)

            elif type_scan == "A":
                result_probe = {executor.submit(self.ack_scan, ip, port): port for port in ports}
                executor.shutdown(wait=True)

            for future in concurrent.futures.as_completed(result_probe):
                if future.result() is not None:
                    self.__result_scan.append(future.result())

        if type_scan == "A":
            filtered_port = 0
            unfiltered_port = 0

            for port in self.__result_scan:
                if port == 1:
                    filtered_port += 1
                elif port == 0:
                    unfiltered_port += 1
            del self.__result_scan[:]
            self.__result_scan.append(filtered_port)
            self.__result_scan.append(unfiltered_port)

        return self.__result_scan
