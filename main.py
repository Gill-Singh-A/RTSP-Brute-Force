#! /usr/bin/env python3

import cv2, pickle, json
from datetime import date
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

threads = 100
verbose = False

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
    display('+', "Loaded IP Addresses from Files")
    display(':', f"Total Number of IP Addresses = {Back.MAGENTA}{len(ips)}{Back.RESET}")