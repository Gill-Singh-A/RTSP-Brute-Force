# RTSP Brute Force
A Python Program that uses OpenCV module to brute force RTSP (Real Time Streaming Protocol) Service used by IoT (Internet of Things) devices like CCTVs (Closed-circuit television), etc.
## Requirements
Language Used = Python3<br />
Modules/Packages used:
* cv2
* pickle
* scapy
* hashlib
* base64
* sys
* datetime
* urllib
* multiprocessing
* optparse
* colorama
* time
<!-- -->
Install the dependencies:
```bash
pip install -r requirements.txt
```
## Arguments
It takes in the following command line arguments:
* '-i', "--ip" : File Name of List of IP Addresses (Seperated by ',', either File Name or IP itself)
* '-C', "--capture-file" : Packet Capture Files (Seperated by ',')
* '-D', "--capture-file-data" : Dump Data Extracted from Capture File in Pickle Format (Optional)
* '-u', "--user" : Username for Brute Force (Seperated by ',', either File Name or User itself)
* '-p', "--password" : Password For Brute Force (Seperated by ',', either File Name or Password itself)
* '-v', "--verbose" : Dislay Additional Information (True/False, Default=True)
* '-c', "--capture" : Capture Frame if Successful Login (True/False, Default=False)
* '-w', "--write" : Name of the CSV File for the Successfully Logged In IPs to be dumped (default=current data and time)
<!-- --><br />
To see how we can Brute-Force RTSP Protocol and gain access to CCTVs using this Program, see the Blog [Compromising CCTVs 101](https://medium.com/@amansg22/compromising-cctvs-101-ecd41748c90c) on [Medium](https://medium.com/@amansg22).