/*
    Copyright 1991-2015 Amebis

    This file is part of ArnesLink.

    ArnesLink is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ArnesLink is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ArnesLink. If not, see <http://www.gnu.org/licenses/>.
*/

//
// Product version as a single DWORD
// Note: Used for version comparison within C/C++ code.
//
#define AL_VERSION        0x01000300

//
// Product version by components
// Note: Resource Compiler has limited preprocessing capability,
// thus we need to specify major, minor and other version components
// separately.
//
#define AL_VERSION_MAJ    1
#define AL_VERSION_MIN    0
#define AL_VERSION_REV    3
#define AL_VERSION_BUILD  0

//
// Human readable product version and build year for UI
//
#define AL_VERSION_STR    "1.1-pre3"
#define AL_BUILD_YEAR_STR "2015"

//
// Numerical version presentation for ProductVersion propery in
// MSI packages (syntax: N.N[.N[.N]])
//
#define AL_VERSION_INST   "1.0.3"

//
// The product code for ProductCode property in MSI packages
// Replace with new on every version change, regardless how minor it is.
//
#define AL_VERSION_GUID   "{96247D57-B6A6-435A-8D71-6FAB4FD3657A}"
