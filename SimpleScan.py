from model.Scan import Scan
from model.ScanUtil import ScanUtil
from model.FormattingError import FormattingError
from argparse import ArgumentParser
from argparse import RawTextHelpFormatter
from colorama import init, Fore
from tabulate import tabulate


class SimpleScan:
    @staticmethod
    def main():

        init()
        banner = ''' 
        --  (~. _ _  _ | _ (~ _ _  _
        --  _)|| | ||_)|(/__)(_(_|| |
        --          |
        '''

        parser = ArgumentParser(description="SimpleScan", formatter_class=RawTextHelpFormatter)

        parser.add_argument("-p", help="Lista de puerto a escanear, por defecto escanea los 1000 primeros puertos.\n" +
                                       "-p <puerto>: escanea un puerto especifico.\n" +
                                       "-p <puerto, puerto, puerto...>: escanea un conjunto de puertos especificos" +
                                       " separados por coma.\n" +
                                       "-p <puerto - puerto>: Escanea un intervalo de puertos.")

        parser.add_argument("-t", help="Direccion IP del objetivo a escanear.")

        parser.add_argument("-s",
                            help="Especifica el tipo de escaneo, por defecto escaner sera Stealth a"
                                 " los primeros 1000 puertos.\n" +
                                 "Esta opcion es sensible a mayuscula y minusculas." +
                                 "\n-sC: Ejecuta un escaneo de tipo Connect." +
                                 "\n-sS: Ejecuta un escaneo de tipo Stealth." +
                                 "\n-sA: Ejecuta un escaneo de tipo ACK.")

        args = parser.parse_args()

        if args.s is None:
            args.s = "S"

        if args.p is None:
            args.p = [x for x in range(0, 1001)]

        # Validate the format of scan
        try:
            ScanUtil.options_scan(args.s)
        except FormattingError as ex:
            print(Fore.RED + "[X] " + ex.__str__())
            exit(0)

        # Validate the format of ipv4 and ipv6
        try:
            ScanUtil.ip_formatting(args.t)
        except FormattingError as ex:
            print(Fore.RED + "[X] " + ex.__str__())
            exit(0)

        # Validate the format of the ports
        try:
            if str(type(args.p)) == "<class 'str'>":
                ports = args.p.split(",")
                args.p = ScanUtil.ports_formatting(ports)
        except FormattingError as ex:
            print(Fore.RED + "[X] " + ex.__str__())
            exit(0)

        print(Fore.RED + banner)
        print(Fore.RED + "\nCreated by: Homeless\nVersion: 1.0.0\n")
        print(Fore.RED + "[i] Iniciando: " + ScanUtil.current_date(), end="\n\n")

        if args.s is None or args.t is None:
            print("parametro -s y -t es obligatorio")

        elif args.s == "C":
            cnn = Scan()
            print("[i] Iniciando Connect Scan...", end="\n\n")
            result_cnn = cnn.run_scan(args.t, args.p, args.s)
            result_cnn.sort()
            head = ["N°", "PROTOCOLO", "ESTADO", "SERVICIO"]

            print(Fore.GREEN + tabulate(result_cnn, headers=head, tablefmt="psql"), end="\n\n")

            print(Fore.RED + "[i] Finalizado: " + ScanUtil.current_date())

        elif args.s == "S":
            stealth = Scan()
            print("[i] Iniciando Stealth Scan...", end="\n\n")
            result_stealth = stealth.run_scan(args.t, args.p, args.s)
            head = ["N°", "PROTOCOLO", "ESTADO", "SERVICIO"]
            result_stealth.sort()

            print(Fore.GREEN + tabulate(result_stealth, headers=head, tablefmt="psql"), end="\n\n")

            print(Fore.RED + "[i] Finalizado: " + ScanUtil.current_date())

        elif args.s == "A":
            ack = Scan()
            print("[i] Iniciando ACK Scan...", end="\n\n")
            result_ack = ack.run_scan(args.t, args.p, args.s)

            if result_ack[0] > 0:
                print(Fore.GREEN + "[*] Los puertos [{}] no estan filtrado en {}".format(result_ack[0], args.t),
                      end="\n\n")

                print(Fore.RED + "Finalizado: " + ScanUtil.current_date())

            elif result_ack[1] > 0:
                print(Fore.GREEN + "[*] Los puertos [{}] estan filtrados en {}".format(result_ack[1], args.t))

                print(Fore.RED + "Finalizado: " + ScanUtil.current_date())
        else:
            print("Ninguna opcion valida para escanear")


if __name__ == '__main__':
    SimpleScan.main()
