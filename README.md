#libatl
Provides additional templates and function helpers for Microsoft Active Template Library

##Building
- The _.h_ files can be used individually. However, we do encourage you to include the entire library project and reference it in dependant projects of your solution, as libatl might develop some non-inline code over time.
- The _libatl.vcxproj_ requires Microsoft Visual Studio 2010 SP1 and _..\..\include_ folder with _common.props_, _Debug.props_, _Release.props_, _Win32.props_, and _x64.props_ files to customize building process for individual applications.
