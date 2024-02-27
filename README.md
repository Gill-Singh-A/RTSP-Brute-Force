# RTSP Brute Force
A Python Program that uses OpenCV module to brute force RTSP (Real Time Streaming Protocol) Service used by IoT (Internet of Things) devices like CCTVs (Closed-circuit television), etc.

## Requirements
Language Used = Python3<br />
Modules/Packages used:
* cv2
* contextlib
* io
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
* '-u', "--user" : Username for Brute Force (Seperated by ',', either File Name or User itself)
* '-p', "--password" : Password For Brute Force (Seperated by ',', either File Name or Password itself)
* '-v', "--verbose" : Dislay Additional Information (True/False, Default=True)
* '-w', "--write" : Name of the CSV File for the Successfully Logged In IPs to be dumped (default=current data and time)