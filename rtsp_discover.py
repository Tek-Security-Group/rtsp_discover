# RTSP Auth Grinder
# USAGE: rtsp_authgrind [-l username | -L username_file] [-p password | -P password_file] <target ip[:port]>
# Author: TekTengu
# Copyright (C) 2014 Luke Stephens and Tek Security Group, LLC - all rights reserved

"""
	rtsp_discover.py - A quick tool to run the DESCRIBE and OPTIONS verbs against an RTSP
	connection. Will provide key information or clue the auditor into this
	possibly not being a true RTSP connection.

	Copyright (C) 2014 Luke Stephens and Tek Security Group, LLC - all rights reserved

	This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

	RTSP Discover is provided for testing purposes only and is not
	authorized for use to conduct malicious, illegal or other nefarious activities.

	Standard usage is:

	python rtsp_discover <target ip [:port]>

"""

import socket
import sys
import time
import select

PORT = 554
IP = ""
DESCRIBEPACKET = ""
OPTIONSPACKET = ""
TIMEOUT = 10

def is_Unauthorized(s):
	return '401 Unauthorized' in s

def create_describe_packet():
	global DESCRIBEPACKET
	if len(DESCRIBEPACKET) <= 0:
		DESCRIBEPACKET = 'DESCRIBE rtsp://%s RTSP/1.0\r\n' % IP
		DESCRIBEPACKET += 'CSeq: 2\r\n'
	return DESCRIBEPACKET

def create_options_packet():
	global OPTIONSPACKET
	if len(OPTIONSPACKET) <= 0:
		OPTIONSPACKET = 'OPTIONS * RTSP/1.0\r\n'
		OPTIONSPACKET += 'CSeq: 1\r\n'
	return OPTIONSPACKET

def create_test_packet1():
    return create_describe_packet() + "\r\n"

def create_test_packet2():
	return create_options_packet() + "\r\n"


def test_describe():
	pkt = create_test_packet1()
	print "********************************************************************************"
	print "\n"
	print "Start of RTSP DESCRIBE Test"
	print "\n"
	print "********************************************************************************"
	print ">>>>>>>>>>>>>> SENDING <<<<<<<<<<<<<"
	print pkt
	print ">>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<"
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(TIMEOUT)
		s.connect((IP, PORT))
		s.sendall(pkt)
		data = s.recv(1024)
	except KeyboardInterrupt :
		print "The run was interrupted by the user pressing Ctl-C"
		return
	except socket.timeout :
		print "The test timed out trying to reach the IP provided. Check your IP and network and try again"
		return
	except socket.error :
		print "There is a networking problem. Please check your network and try again"
		return
	print ">>>>>>>>>>>> RESULTS <<<<<<<<<<<<<<"
	print repr(data)
	print ">>>>>>>>> END OF RESULTS <<<<<<<<<<"
	print "********************************************************************************"
	print "\n"
	print "End of RTSP DESCRIBE Test"
	print "\n"
	print "********************************************************************************"

def test_options():
	pkt = create_test_packet2()
	print "********************************************************************************"
	print "\n"
	print "Start of RTSP OPTIONS Test"
	print "\n"
	print "********************************************************************************"
	print ">>>>>>>>>>>>>> SENDING <<<<<<<<<<<<<"
	print pkt
	print ">>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<"
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(TIMEOUT)
		s.connect((IP, PORT))
		s.sendall(pkt)
		data = s.recv(1024)
	except KeyboardInterrupt :
		print "The run was interrupted by the user pressing Ctl-C"
		return
	except socket.timeout :
		print "The test timed out trying to reach the IP provided. Check your IP and network and try again"
		return
	except socket.error :
		print "There is a networking problem. Please check your network and try again"
		return
	print ">>>>>>>>>>>> RESULTS <<<<<<<<<<<<<<"
	print repr(data)
	print ">>>>>>>>> END OF RESULTS <<<<<<<<<<"
	print "********************************************************************************"
	print "\n"
	print "End of RTSP OPTIONS Test"
	print "\n"
	print "********************************************************************************"


if __name__ == '__main__':
	print "\n\n   rtsp_discover.py - Discovery tool for RTSP Protocol"
	print "   Copyright (C) 2014 Luke Stephens and Tek Security Group, LLC"
	print "   This program comes with ABSOLUTELY NO WARRANTY. This is free software, and"
	print "   you are welcome to use and redistribute it under certain conditions. See"
	print "   the license file provided with the distribution,"
	print "   or https://github.com/tektengu/rtsp_discover/license.txt\n\n"

	if len(sys.argv) != 1:
		print "you must supply an ip and optional port"

	ipport = sys.argv[1]
	sep = ipport.find(":")
	if sep > 0:
		IP = ipport[:sep]
		PORT = int(ipport[sep + 1 :])
	else:
		IP = ipport

	print "********************************************************************************"
	print "\n"
	print "Starting RTSP Discover on IP: " + IP + " and PORT: " + str(PORT)
	print "\n"
	print "********************************************************************************"
	test_describe()
	test_options()
