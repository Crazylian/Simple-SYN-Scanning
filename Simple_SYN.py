from SYN_scanning import *
import getopt
import sys
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

fast_port = "7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157"


def main(argv):
    scan = Single_IP_Scan()
    shortargs = '-h-p:-e:-g:-F-d-n'
    longargs = [
        "help",
        "port=",
        "eth=",
        "sport="
        "fast",
        "detail",
        "no-ping",
    ]
    opts, args = getopt.getopt(argv[1:], shortargs, longargs)
    dPort, eth, sPort, fastflag = None, None, 20, 0
    for o, a in opts:
        if o in ("-h", "--help"):
            print('''用法：python Simple_SYN [option] [args...] <IP>
其中，选项包括：
\t -h --help\t 显示帮助信息
\t -p --port <端口号>\t 指定扫描的端口号或端口段，使用逗号分隔
\t -e --eth <网络接口卡名>\t 指定使用的网络接口卡
\t -g --sport <端口号>\t 指定扫描时发送请求的端口
\t -F --fast \t 进行快速扫描，扫描100个常见开放端口
\t -d --detail \t 展示扫描详细结果
\t -n --no-ping \t 禁用ping进行主机存活探测''')
            sys.exit()
        if o in ("-p", "--port"):
            dPort = a
        if o in ("-e", "--eth"):
            eth = a
        if o in ("-g", "--sport"):
            try:
                sPort = int(a)
                print(sPort)
                if int(a) > 0xFFFF or int(a) < 0:
                    print("Source port out of range!")
                    sys.exit()
            except:
                print("Invalid source port num!")
                sys.exit()
        if o in ("-F", "--fast"):
            fastflag = 1
        if o in ("-d", "--detail"):
            scan.dflag = 1
        if o in ("-n", "--no-ping"):
            scan.Pnflag = 0
    dHost = args[-1]
    # print(dHost)
    print("Initiating SYN Stealth Scan at",time.strftime("%H:%M"))
    start = time.perf_counter()
    if fastflag == 0:
        scan.portScan(dHost, dPort, sPort, eth)
    else:
        scan.portScan(dHost, fast_port, sPort, eth)
    end = time.perf_counter()
    print("Scanned at", time.strftime("%Y-%m-%d %H:%M:%S"),"for",(end-start)*1000,"ms")


if __name__ == "__main__":
    main(sys.argv)
    # scan = Single_IP_Scan()
    # scan.connScan(dHost="127.0.0.1",dPort=22)
    # scan.printResult()
