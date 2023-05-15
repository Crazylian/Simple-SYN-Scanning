import socket
import threading
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
from random import randint


class Single_IP_Scan:
    openport = []
    closeport = []
    filteredport = []
    Pnflag = 1
    dflag = 0
    def connScan(self, dHost, dPort, sPort, eth):
        try:
            syn = IP(dst=dHost) / TCP(sport=sPort, dport=dPort, flags="S") / b"wow"
            result_raw = sr1(syn, timeout=1, verbose=0, retry=5, iface=eth)
            # result_list = result_raw[0].res
            # ls(syn)
            if result_raw[TCP].flags == "SA":
                # print(f"[+] {dHost}:{dPort} is open.")
                self.openport.append(dPort)
                send(
                    (IP(dst=dHost) / TCP(sport=sPort, dport=dPort, flags="RA")),
                    verbose=0,
                )
            elif result_raw[TCP].flags == "RA":
                # print(f"[-] {dHost}:{dPort} is closed.")
                self.closeport.append(dPort)
            else:
                self.filteredport.append(dPort)
        except:
            # print(f"[-] {dHost}/tcp filtered")
            self.filteredport.append(dPort)
            pass

        return 0

    def portScan(self, dHost, dPort=None, sPort=20, eth=None):
        # try:
        #     dip = socket.gethostbyname(dHost)
        # except:
        #     print(f"[-] cannot connect {dip}")
        #     return
        try:
            dHost = socket.gethostbyname(dHost)
        except:
            pass
        try:
            ip = IP(dst=dHost)
        except:
            print("Invalid IP num!")
            sys.exit()

        for p in ip:
            dip = p.dst

            if self.Pnflag == 1:
                if self.livehostscan(dip) == 0:
                    continue
            threadlist=[]
            if dPort == "*":
                for port in range(0, 65536):
                    # time.sleep(1)
                    # print(f"scaning port: {port}")
                    t2 = threading.Thread(
                        target=self.connScan, args=(dip, port, sPort, eth)
                    )
                    threadlist.append(t2)
                    t2.start()
            elif dPort == None:
                for port in range(0, 1000):
                    # time.sleep(1)
                    # print(f"scaning port: {port}")
                    t2 = threading.Thread(
                        target=self.connScan, args=(dip, port, sPort, eth)
                    )
                    threadlist.append(t2)
                    t2.start()
            else:
                Port = dPort.split(",")
                for d in Port:
                    if "-" in d:
                        start = int(d.split("-", 1)[0])
                        finish = int(d.split("-", 1)[1])
                        for port in range(start, finish + 1):
                            t2 = threading.Thread(
                                target=self.connScan, args=(dip, port, sPort, eth)
                            )
                            threadlist.append(t2)
                            t2.start()
                    else:
                        t2 = threading.Thread(
                            target=self.connScan, args=(dip, int(d), sPort, eth)
                        )
                        threadlist.append(t2)
                        t2.start()
            [t.join() for t in threadlist]
            print(f"[+] scan results for: {dHost}")
            self.printResult()
        return 0

    def livehostscan(self, dHost):
        # ip_id = randint(1, 65535)
        icmp_id = randint(1, 65535)
        icmp_seq = randint(1, 65535)
        packet = (
            # IP(dst=dHost, ttl=64, id=ip_id)
            IP(dst=dHost, ttl=64)
            / ICMP(id=icmp_id, seq=icmp_seq)
            / b"wow"
        )
        result = sr1(packet, timeout=1, verbose=False, retry=2)
        if result:
            # for rcv in result:
            scan_ip = result[IP].src
            print("[+] " + scan_ip + "-->" "host is up")
            return 1
        else:
            print(
                "[-] "
                + dHost
                + "-->host seems down, or we have been blocked.\n[-] If the host is realy up, try to use -Pn option."
            )
            return 0

    def printResult(self):
        self.openport.sort()
        self.closeport.sort()
        self.filteredport.sort()
        print("%-10s%-10s%-10s" % ("PORT", "STATE", "SERVICE"))
        for result in self.openport:
            try:
                ser = socket.getservbyport(result)
            except:
                ser = "unknown"
            print("%-10s%-10s%-10s" % (result, "open", ser))
        if self.dflag == 0:
            print(f"Not shown: {len(self.closeport)} closed ports")
            # if len(self.closeport) > 20:
            #     print(f"Not shown: {len(self.closeport)} closed ports")
            # else:
            #     for result in self.closeport:
            #         print('%-10s%-10s%-10s' % (result, "close", ser))
            print(f"Not shown: {len(self.filteredport)} filtered ports")
        else:
            for result in self.closeport:
                try:
                    ser = socket.getservbyport(result)
                except:
                    ser = "unknown"
                print("%-10s%-10s%-10s" % (result, "close", ser))
            for result in self.filteredport:
                try:
                    ser = socket.getservbyport(result)
                except:
                    ser = "unknown"
                print("%-10s%-10s%-10s" % (result, "filtered", ser))
        self.openport.clear()
        self.closeport.clear()
        self.filteredport.clear()
        return 0
