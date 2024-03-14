#! /usr/bin/env python3

import cv2
from datetime import date
from urllib.parse import quote
from multiprocessing import Lock, Pool, cpu_count
from optparse import OptionParser
from colorama import Fore, Back, Style
from time import strftime, localtime, sleep, time

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

def loginRTSP(ip, user, password):
    user = quote(user)
    password = quote(password)
    try:
        if user == '':
            video_capture = cv2.VideoCapture(f"rtsp://{ip}")
        else:
            video_capture = cv2.VideoCapture(f"rtsp://{user}:{password}@{ip}")
        if video_capture.isOpened():
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
                    display('+', f"{Back.BLUE}{detail['user']}{Back.RESET}:{Back.CYAN}{detail['password']}{Back.RESET}@{Back.MAGENTA} {detail['ip']}{Back.RESET} => Access Granted")
                else:
                    print(f"{Back.RESET}", end='')
    return group_successful_logins

if __name__ == "__main__":
    arguments = get_arguments(('-i', "--ip", "ip", "File Name of List of IP Addresses (Seperated by ',', either File Name or IP itself)"),
                              ('-u', "--user", "user", "Username for Brute Force (Seperated by ',', either File Name or User itself)"),
                              ('-p', "--password", "password", "Password For Brute Force (Seperated by ',', either File Name or Password itself)"),
                              ('-v', "--verbose", "verbose", f"Dislay Additional Information (True/False, Default={verbose})"),
                              ('-w', "--write", "write", "Name of the CSV File for the Successfully Logged In IPs to be dumped (default=current data and time)"))
    if not arguments.ip:
        display('-', "Please Provide a List of IP Addresses")
        exit(0)
    else:
        ips = []
        for ip_detail in arguments.ip.split(','):
            try:
                with open(ip_detail, 'r') as file:
                    display(':', f"Loading IPs from File {Back.MAGENTA}{ip_detail}{Back.RESET}")
                    ips.extend(file.read().split('\n'))
                    display('+', f"IPs Loaded = {Back.MAGENTA}{len(arguments.ip)}{Back.RESET}")
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
                display(':', f"Loading Users from File {Back.MAGENTA}{arguments.users}{Back.RESET}")
                arguments.users = [user for user in file.read().split('\n')]
                display('+', f"Users Loaded = {Back.MAGENTA}{len(arguments.users)}{Back.RESET}")
        except FileNotFoundError:
            arguments.user = [user for user in arguments.user.split(',')]
        except OSError:
            arguments.user = [user for user in arguments.user.split(',')]
        except:
            display('-', f"Error Loading Users from File {Back.YELLOW}{arguments.user}{Back.RESET}")
            exit(0)
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
    arguments.threads = threads_number
    pool = Pool(arguments.threads)
    if arguments.verbose == "True":
        arguments.verbose = True
    else:
        arguments.verbose = False
    if not arguments.write:
        arguments.write = f"{date.today()} {strftime('%H_%M_%S', localtime())}.csv"
    details = []
    for user in arguments.user:
        for password in arguments.password:
            details.extend([{"ip": ip, "user": user, "password": password} for ip in ips])
    total_ips = len(ips)
    total_details = len(details)
    display(':', f"Total Number of IP Addresses = {Back.MAGENTA}{total_ips}{Back.RESET}")
    display(':', f"Creating {Back.MAGENTA}{arguments.threads}{Back.RESET} Threads Details", start='\n')
    detail_division = [details[group*total_details//arguments.threads:(group+1)*total_details//arguments.threads] for group in range(arguments.threads)]
    display('+', f"Created {Back.MAGENTA}{arguments.threads}{Back.RESET} Threads")
    display(':', f"Starting {Back.MAGENTA}{arguments.threads}{Back.RESET} Threads Details", start='\n')
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