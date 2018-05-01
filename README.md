# cvechk
Source for the site [cvechk.net](https://cvechk.net).

### Description
A simple and consolidated method for checking vendor API data for CVE information. This site is built strictly with Python using the flask framework, no JavaScript is used. Data returned is a list of vendor CVE links along with versions of packages which fix the applicable issues.

### Supported Application/Server Configuration
Only Python 3.6 is supported at this time, older releases may not work as expected and are considered unsupported.
No information will provided for operating systems which are end of life per the respective vendor to encourage meeting modern security practices.

Running cvechk with docker is **not** supported. The files are provided for ease of testing during development only.

### Available Operating System Lookup
The following operating systems are currently available for data reporting.
Additional operating systems will be added in future releases.

- RHEL 6/7 (including CentOS)
- Ubuntu 14.04/16.04

### Contributing
See CONTRIBUTING.md for current contributing information.

### Providing Feedback
For any feedback, suggestions, requests, or bugs please utilize the issue tracker on GitHub.
