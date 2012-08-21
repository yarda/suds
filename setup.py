#! /usr/bin/python
# encoding: utf-8

#*    sudsds - Python SOAP library forked from suds with special features
#*    for Datove schranky
#*
#*    This library is free software; you can redistribute it and/or
#*    modify it under the terms of the GNU Library General Public
#*    License as published by the Free Software Foundation; either
#*    version 2 of the License, or (at your option) any later version.
#*
#*    This library is distributed in the hope that it will be useful,
#*    but WITHOUT ANY WARRANTY; without even the implied warranty of
#*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#*    Library General Public License for more details.
#*
#*    You should have received a copy of the GNU Library General Public
#*    License along with this library; if not, write to the Free
#*    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA


from setuptools import setup

# sudsds subpackages
sudsds_dir = "./"
pkgdirs = ["bindings","mx","sax","transport","umx","xsd"]
sudsds_subpackages = []
for pkgdir in pkgdirs:
  sudsds_subpackages.append("sudsds."+pkgdir.replace("/","."))

data = dict(
  name = 'sudsds',
  version = "1.0",
  description = "sudsds is a Python SOAP library for accessing Datove schranky",
  author = "CZ.NIC Labs",
  author_email = "datove-schranky@labs.nic.cz",
  url = "http://labs.nic.cz/datove-schranky/",
  license = "GNU LGPL",
  platforms = ["Unix", "Windows","MacOS X"],
  long_description = "sudsds is a Python SOAP library for accessing Datove "\
  "schranky. It is based on suds (https://fedorahosted.org/suds) and contains "\
  "some specific features to support Datove schranky.",
  
  packages=["sudsds"]+sudsds_subpackages,
  package_dir = {'sudsds': './'},
  data_files = [('share/sudsds', ['README', 'LICENSE.txt']),
                ],
  requires = [],
  install_requires = [],
  provides=["sudsds"],
  )

set = setup(**data)

