rtsp_discover.py
=================

rtsp_discover.py - A quick and simple tool to validate ports as supporting RTSP
and obtaining the DESCRIBE and OPTIONS response content.

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

RTSP Discover is provided for testing purposes only and is not authorized for use to conduct malicious, illegal or other nefarious activities.

Standard usage is:

	python rtsp_discover.py <target ip [:port]>

Right now the discover program runs a DESCRIBE request and a OPTIONS request. DESCIBE
is defined by the standard as an optionally supported verb, while OPTIONS is a
mandatory verb. If both of these don't return anything, it is a pretty good bet that
the port doesn't actually support RTSP (even if it is on the 554 standard port).

To Do:
  1. Validate there are no other inquiry verbs that could help discover RTSP connections
	   in the standard.
  2. Check whether there are other DESCRIBE or OPTIONS formats that may illuminate
	   RTSP active ports.
  3. Add the ability to search scan (give it a IP block and port block)
  4. Add more intelligent reporting.
