# -*- coding:utf-8 -*-
# !/usr/bin/env python

try:
    import os
    import re
    import ssl
    import sys
    import csv
    import uuid
    import warnings
    import requests
    import HTMLParser
    from time import sleep, time
    from requests.adapters import HTTPAdapter
    from collections import defaultdict
    from gevent.threadpool import ThreadPool
    from libnmap.process import NmapProcess
    from libnmap.parser import NmapParser
except:
    print '\033[1;34m[x] pip install python-libnmap gevent requests --user\033[0m'

reload(sys)
sys.setdefaultencoding('utf-8')
requests.packages.urllib3.disable_warnings()
warnings.filterwarnings("ignore")
try:
    requests.packages.urllib3.disable_warnings()
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context


class Scanner(object):
    def __init__(self, filename='ips.txt'):
        self.W = '\033[0m'
        self.G = '\033[1;32m'
        self.O = '\033[1;33m'
        self.R = '\033[1;31m'
        self.time = time()
        self.result = []
        self.ips = filename
        self.pool = ThreadPool(30)
        self.output_mode = "silent"  # debug or silent
        self.masscan_ports_max = 500
        self.masscan_ports = '0-65535'
        self.masscan_rate = 1000
        self.default_policy = '-P0 -sS -sV -O -Pn  --open --script=banner --script-timeout=7200 -script-args http.useragent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36"'
        self.nmap_timeout = 3600
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/52.0.2743.116 Safari/537.36 Edge/15.15063",
            "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
        self.patterns = (
            '<meta[\s]*http-equiv[\s]*=[\s]*[\'"]refresh[\'"][\s]*content[\s]*=[\s]*[\'"]\d+[\s]*;[\s]*url[\s]*=[\s]*(.*?)[\'"][\s]*/?>',
            'window.location[\s]*=[\s]*[\'"](.*?)[\'"][\s]*;',
            'window.location.href[\s]*=[\s]*[\'"](.*?)[\'"][\s]*;',
            'window.location.replace[\s]*\([\'"](.*?)[\'"]\)[\s]*;',
            'window.navigate[\s]*\([\'"](.*?)[\'"]\)',
            'location.href[\s]*=[\s]*[\'"](.*?)[\'"]',
        )
        self.default_top1000 = [1, 3, 4, 6, 7, 9, 11, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43,
                                49, 53, 67, 69,
                                70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 102, 104, 106, 109, 110, 111, 113,
                                119, 123,
                                125, 135, 137, 138, 139, 143, 144, 146, 161, 162, 163, 175, 179, 199, 211, 212, 222,
                                254, 255, 256,
                                259, 264, 280, 301, 306, 311, 340, 366, 389, 391, 406, 407, 416, 417, 425, 427, 443,
                                444, 445, 459,
                                464, 465, 481, 497, 500, 502, 503, 512, 513, 514, 515, 520, 523, 524, 541, 543, 544,
                                545, 548, 554,
                                555, 563, 564, 587, 593, 616, 617, 623, 625, 626, 631, 636, 646, 648, 666, 667, 668,
                                683, 687, 691,
                                700, 705, 711, 714, 720, 722, 726, 749, 765, 771, 777, 783, 787, 789, 800, 801, 808,
                                843, 873, 880,
                                888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001,
                                1002, 1007,
                                1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031,
                                1032, 1033, 1034,
                                1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048,
                                1049, 1050, 1051,
                                1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065,
                                1066, 1067, 1068,
                                1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082,
                                1083, 1084, 1085,
                                1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099,
                                1100, 1102, 1104,
                                1105, 1106, 1107, 1108, 1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123,
                                1124, 1126, 1130,
                                1131, 1132, 1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164,
                                1165, 1166, 1169,
                                1174, 1175, 1177, 1183, 1185, 1186, 1187, 1192, 1194, 1198, 1199, 1200, 1201, 1213,
                                1216, 1217, 1218,
                                1233, 1234, 1236, 1241, 1244, 1247, 1248, 1259, 1260, 1271, 1272, 1277, 1287, 1296,
                                1300, 1301, 1309,
                                1310, 1311, 1322, 1328, 1334, 1344, 1352, 1417, 1433, 1434, 1443, 1455, 1461, 1471,
                                1494, 1500, 1501,
                                1503, 1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1604, 1641, 1645, 1658, 1666,
                                1687, 1688, 1700,
                                1701, 1717, 1718, 1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812,
                                1839, 1840, 1862,
                                1863, 1864, 1875, 1883, 1900, 1911, 1914, 1935, 1947, 1962, 1967, 1971, 1972, 1974,
                                1984, 1991, 1993,
                                1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2013,
                                2020, 2021, 2022,
                                2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049,
                                2065, 2068, 2080,
                                2082, 2083, 2086, 2087, 2094, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121,
                                2123, 2126, 2135,
                                2144, 2152, 2160, 2161, 2170, 2179, 2181, 2190, 2191, 2196, 2200, 2222, 2251, 2260,
                                2288, 2301, 2323,
                                2332, 2366, 2375, 2376, 2379, 2381, 2382, 2383, 2393, 2394, 2399, 2401, 2404, 2424,
                                2425, 2427, 2455,
                                2480, 2492, 2500, 2501, 2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608, 2628,
                                2638, 2701, 2702,
                                2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910, 2920, 2967, 2968,
                                2998, 3000, 3001,
                                3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3050, 3052, 3071, 3077, 3128,
                                3168, 3211, 3221,
                                3260, 3261, 3268, 3269, 3283, 3288, 3299, 3300, 3301, 3306, 3307, 3310, 3322, 3323,
                                3324, 3325, 3333,
                                3351, 3367, 3369, 3370, 3371, 3372, 3388, 3389, 3390, 3404, 3460, 3476, 3493, 3517,
                                3527, 3541, 3542,
                                3546, 3551, 3580, 3659, 3671, 3689, 3690, 3702, 3703, 3737, 3749, 3766, 3780, 3784,
                                3800, 3801, 3809,
                                3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920,
                                3945, 3971, 3986,
                                3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4022, 4040, 4045, 4063, 4064,
                                4070, 4111, 4125,
                                4126, 4129, 4224, 4242, 4279, 4321, 4343, 4369, 4433, 4443, 4444, 4445, 4446, 4449,
                                4550, 4567, 4662,
                                4712, 4730, 4786, 4800, 4840, 4848, 4880, 4899, 4900, 4911, 4949, 4998, 5000, 5001,
                                5002, 5003, 5004,
                                5006, 5007, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5093, 5094,
                                5100, 5101, 5102,
                                5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5351, 5353, 5357,
                                5400, 5405, 5414,
                                5431, 5432, 5433, 5440, 5500, 5510, 5544, 5550, 5554, 5555, 5560, 5566, 5577, 5601,
                                5631, 5632, 5633,
                                5666, 5672, 5678, 5679, 5683, 5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822,
                                5825, 5850, 5859,
                                5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925,
                                5938, 5950, 5952,
                                5959, 5960, 5961, 5962, 5963, 5984, 5985, 5986, 5987, 5988, 5989, 5998, 5999, 6000,
                                6001, 6002, 6003,
                                6004, 6005, 6007, 6009, 6025, 6059, 6082, 6100, 6101, 6106, 6112, 6123, 6129, 6156,
                                6346, 6379, 6389,
                                6488, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6664, 6665, 6666, 6667,
                                6668, 6669, 6689,
                                6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004,
                                7007, 7019, 7025,
                                7070, 7071, 7077, 7100, 7103, 7106, 7200, 7201, 7288, 7402, 7435, 7443, 7474, 7496,
                                7512, 7547, 7548,
                                7625, 7627, 7634, 7676, 7741, 7777, 7778, 7779, 7800, 7911, 7920, 7921, 7937, 7938,
                                7999, 8000, 8001,
                                8002, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8023, 8031, 8042, 8045, 8060, 8069,
                                8080, 8081, 8082,
                                8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8098, 8099, 8100, 8112, 8125,
                                8126, 8139, 8161,
                                8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300, 8333, 8334,
                                8377, 8378, 8383,
                                8400, 8402, 8443, 8471, 8500, 8545, 8554, 8600, 8649, 8651, 8652, 8654, 8686, 8701,
                                8800, 8834, 8873,
                                8880, 8883, 8888, 8889, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040,
                                9042, 9050, 9051,
                                9071, 9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9151, 9160,
                                9191, 9200, 9207,
                                9220, 9290, 9300, 9333, 9415, 9418, 9443, 9471, 9485, 9500, 9502, 9503, 9535, 9575,
                                9593, 9594, 9595,
                                9600, 9618, 9653, 9666, 9700, 9711, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943,
                                9944, 9968, 9981,
                                9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025, 10082,
                                10162,
                                10180, 10215, 10243, 10333, 10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778,
                                11001, 11110,
                                11111, 11211, 11300, 11310, 11967, 12000, 12174, 12265, 12345, 13456, 13579, 13722,
                                13782, 13783,
                                14000, 14147, 14238, 14265, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15672,
                                15742, 16000,
                                16001, 16010, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17185, 17877, 17988,
                                18001, 18040,
                                18081, 18101, 18245, 18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 19888,
                                20000, 20005,
                                20031, 20221, 20222, 20547, 20828, 21571, 22105, 22222, 22939, 23023, 23424, 23502,
                                24444, 24800,
                                25105, 25565, 25734, 25735, 26214, 27000, 27015, 27017, 27019, 27080, 27352, 27353,
                                27355, 27356,
                                27715, 28017, 28201, 28784, 30000, 30310, 30311, 30312, 30313, 30718, 30951, 31038,
                                31337, 32400,
                                32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779,
                                32780, 32781,
                                32782, 32783, 32784, 32785, 33338, 33354, 33899, 34571, 34572, 34573, 34962, 34964,
                                35500, 37777,
                                38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 44818, 45100, 45554,
                                47808, 48080,
                                48899, 49151, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161,
                                49163, 49165,
                                49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006, 50050, 50070,
                                50090, 50100,
                                50300, 50389, 50500, 50636, 50800, 51103, 51106, 51493, 52673, 52822, 52848, 52869,
                                54045, 54328,
                                55055, 55056, 55553, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 59110, 60020,
                                60443, 61532,
                                61613, 61616, 61900, 62078, 63331, 64623, 64680, 64738, 65000, 65129, 65389]

    def targetsByFile(self):
        targets = []
        try:
            with open(self.ips) as fr:
                for ip in fr.readlines():
                    targets.append(ip.strip())
        except Exception as e:
            print self.R + u'\n[x] file does not exist...' + self.W
        return targets

    def scanByMasscan(self, target):
        report_dict = defaultdict(list)
        tmp_file = '{}.xml'.format(uuid.uuid4())
        try:
            cmd = 'masscan {} -p {} -oX {} --rate {} --wait 1 >> /dev/null 2>&1'.format(target, self.masscan_ports,
                                                                                        tmp_file, self.masscan_rate) \
                if self.output_mode == "silent" else 'masscan {} -p {} -oX {} --rate {} --wait 1'.format(
                target, self.masscan_ports, tmp_file, self.masscan_rate)
            os.system(cmd)
            if os.path.exists(tmp_file) and os.path.getsize(tmp_file):
                report = NmapParser.parse_fromfile(tmp_file)
                for host in report.hosts:
                    for service in host.services:
                        report_dict[host.ipv4].append(service.port)
        except Exception as e:
            print e
        finally:
            if os.path.exists(tmp_file):
                os.remove(tmp_file)
            return report_dict

    def scanByNmap(self, target, policy):
        runtime = 0
        try:
            nmap_proc = NmapProcess(targets=target, options=policy, safe_mode=True)
            nmap_proc.run_background()
            while nmap_proc.is_running():
                if runtime >= self.nmap_timeout:
                    nmap_proc.stop()
                    if self.output_mode != "silent":
                        print self.R + u'\n[x] scan_host {} timeout...'.format(target) + self.W
                    break
                else:
                    if self.output_mode != "silent":
                        sys.stdout.write(
                            u'\033[1;34m[~] scan_host is {},scan progress is {}%({} sec)\n\033[0m'.format(target,
                                                                                                          nmap_proc.progress,
                                                                                                          runtime))
                        sys.stdout.flush()
                    sleep(5)
                    runtime += 5
            if nmap_proc.is_successful() and nmap_proc.stdout:
                self.parserReport(nmap_proc.stdout)
        except Exception as e:
            print e

    def parserTitle(self, url):
        def html_decoder(html_entries):
            try:
                hp = HTMLParser.HTMLParser()
                return hp.unescape(html_entries)
            except:
                return html_entries

        def match_title(content):
            title = re.findall("document\.title[\s]*=[\s]*['\"](.*?)['\"]", content, re.I | re.M | re.S)
            if title and len(title) >= 1:
                return title[0]
            else:
                title = re.findall('<title.*?>(.*?)</title>', content, re.I | re.M | re.S)
                if title and len(title) >= 1:
                    return title[0]
                else:
                    return ""

        def page_decode(html_content):
            raw_content = html_content
            try:
                html_content = raw_content.decode('utf-8')
            except UnicodeError:
                try:
                    html_content = raw_content.decode('gbk')
                except UnicodeError:
                    try:
                        html_content = raw_content.decode('gb2312')
                    except UnicodeError:
                        try:
                            html_content = raw_content.decode('big5')
                        except:
                            pass
            return html_content

        html_content = ''
        title = ''
        if '://' not in url:
            url = 'http://' + url.strip()
        url = url.rstrip('/') + '/'
        try:
            try:
                s = requests.Session()
                s.mount('http://', HTTPAdapter(max_retries=1))
                s.mount('https://', HTTPAdapter(max_retries=1))
                req = s.get(url, headers=self.headers, verify=False, allow_redirects=True, timeout=15)
                html_content = req.content
                html_content = page_decode(html_content)
                req.close()
            except:
                pass
            title = match_title(html_content) if html_content else ''
            try:
                if title:
                    if re.findall('\$#\d{3,};', title):
                        title = html_decoder(title)
            except:
                pass
            for pattern in self.patterns:
                jump = re.findall(pattern, html_content, re.I | re.M)
                if len(jump) == 1:
                    if "://" in jump[0]:
                        url = jump[0]
                    else:
                        url += jump[0]
                    break
            try:
                s = requests.Session()
                s.mount('http://', HTTPAdapter(max_retries=1))
                s.mount('https://', HTTPAdapter(max_retries=1))
                req = s.get(url, headers=self.headers, verify=False, timeout=15)
                html_content = req.content
                req.close()
            except:
                pass
            html_content = page_decode(html_content)
            title = match_title(html_content) if html_content else ""
            try:
                if title:
                    if re.findall("[$#]\d{3,};", title):
                        title = html_decoder(title)
            except:
                pass
        except:
            pass
        finally:
            if title and len(title) > 255:
                title = title[:250]
            return title

    def parserReport(self, report):
        try:
            parsed = NmapParser.parse(report)
            for host in parsed.hosts:
                for services in host.services:
                    if ("http" in services.service) or ("ssl" in services.service):
                        url = "https://" + host.ipv4 + ":" + str(services.port) if ('ssl' in services.service) or (
                                'https' in services.service) else "http://" + host.ipv4 + ":" + str(services.port)
                        title = self.parserTitle(url)
                        self.result.append(
                            (host.ipv4, services.port, services.protocol, services.state, services.service,
                             services.banner, title))
                        print u'{}[+] scan_host is {},scan result is {}|{}|{}|{}|{}|{}{}'.format(self.G, host.ipv4,
                                                                                                 services.port,
                                                                                                 services.protocol,
                                                                                                 services.state,
                                                                                                 services.service,
                                                                                                 services.banner,
                                                                                                 title,
                                                                                                 self.W)
        except Exception as e:
            print e

    def scanMasscanToNmap(self, target):
        try:
            ip_port_list = self.scanByMasscan(target)
            if ip_port_list:
                for target, ports in ip_port_list.items():
                    if len(ports) < self.masscan_ports_max:
                        policy = self.default_policy + " -p {}".format(
                            ','.join(map(str, list(set(self.default_top1000 + ports)))))
                        self.scanByNmap(str(target), policy)
                    else:
                        if self.output_mode != "silent":
                            print self.R + u'\n[x] scan_host {} maybe honeypot or network reasons...'.format(
                                target) + self.W
            else:
                if self.output_mode != "silent":
                    print self.R + u'\n[x] scan_host {} not found live ports...'.format(target) + self.W
        except Exception as e:
            print e

    def main(self):
        try:
            print '\033[1;37m[*] Console starting({} mode), please wait...\033[0m'.format(self.output_mode)
            self.pool.map(self.scanMasscanToNmap, self.targetsByFile())
            self.pool.join()
            if self.result:
                csvfile = file('result.csv', 'wb')
                csvfile.write(u'\ufeff'.encode('utf8'))
                writer = csv.writer(csvfile)
                writer.writerow(['Address', 'Port', 'Protocol', 'State', 'Service', 'Banner', 'Title'])
                writer.writerows(self.result)
                csvfile.close()
            print u'{}[✓] scan completion time : {} sec.{}'.format(self.O, time() - self.time, self.W)
        except Exception as e:
            print e
        except KeyboardInterrupt:
            print self.R + u'\n[x]  user Ctrl+C aborts scan ...' + self.W
            sys.exit(1)


if __name__ == "__main__":
    banner = '''
                  ___====-_  _-====___
            _--^^^#####//      \\#####^^^--_
         _-^##########// (    ) \\##########^-_
        -############//  |\^^/|  \\############-
      _/############//   (@::@)   \\############\_
     /#############((     \\//     ))#############\_
    -###############\\    (oo)    //###############-
   -#################\\  / VV \  //#################-
  -###################\\/      \//###################-
 _#/|##########/\######(   /\   )######/\##########|\#_
 |/ |#/\#/\#/\/  \#/\##\  |  |  /##/\#/  \/\#/\#/\#| \|
 `  |/  V  V  `   V  \#\| |  | |/#/  V   '  V  V  \|  '
    `   `  `      `   / | |  | | \   '      '  '   '
                     (  | |  | |  )
                    __\ | |  | | /__
                   (vvv(VVV)(VVV)vvv)
                  轻量化端口扫描@Coco413
            '''
    print '\033[1;34m{}\033[0m'.format(banner)
    if len(sys.argv) != 2:
        print '[!] Usage: python {} ips.txt'.format(sys.argv[0])
        sys.exit(0)
    else:
        hand = Scanner(sys.argv[1])
        hand.main()