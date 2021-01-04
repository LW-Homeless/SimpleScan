from datetime import datetime
from model.FormattingError import FormattingError
import re


# ScanUtil: Class offering global functionality for SimpleScan operation


class ScanUtil:

    # Method to get the current date
    @staticmethod
    def current_date():
        now = datetime.now()
        current_date = datetime.strftime(now, '%d/%m/%Y %H:%M:%S')
        return current_date

    # Method that checks the format of the ports entered, nomamalizes them and returns a "list" of the ports to scan
    @staticmethod
    def ports_formatting(args_ports):
        patter_port = re.compile('^\d{1,5}$')
        patter_range_port = re.compile('^\d{1,5}[-]\d{1,5}$')

        for port in args_ports:
            if patter_port.match(str(port)):
                continue
            elif patter_range_port.match(str(port)):
                continue
            else:
                raise FormattingError("Error al especificar puertos. ejecuta el comando -h o --help"
                                      " para mas informacion " + port)

        ports = []
        for x in args_ports:
            if patter_port.match(x):
                ports.append(int(x))
            elif patter_range_port.match(x):
                interval = x.split("-")
                for i in range(int(interval[0]), int(interval[1]) + 1):
                    ports.append(int(i))
        ports = list(set(ports))
        ports.sort()
        return ports

    @staticmethod
    def ip_formatting(ip):
        patter_ipv4 = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

        patter_ipv6 = re.compile("^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|"
                                 "([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
                                 "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
                                 "([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
                                 "([0-9a-fA-F]{1,4}:){1,3}'(:[0-9a-fA-F]{1,4}){1,4}|"
                                 "([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
                                 "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
                                 ":((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|"
                                 "::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|"
                                 "(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|"
                                 "(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|"
                                 "(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$")

        if not patter_ipv4.match(ip) and not patter_ipv6.match(ip):
            raise FormattingError("Error al especificar direccion IP: " + ip)

    @staticmethod
    def options_scan(type_scan):
        patter_option_scan = re.compile("^[CSA]$")

        if not patter_option_scan.match(type_scan):
            raise FormattingError("Error al especificar el tipo de escaner: " + type_scan)
