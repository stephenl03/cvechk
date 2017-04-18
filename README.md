# cvechk
Source for the site [cvechk.net](https://cvechk.net).

### Description
A simple and consolidated method for checking vendor API data for CVE information. This site is built strictly with Python using the flask framework, no JavaScript is used. Data returned is a list of vendor CVE links along with versions of packages which fix the applicable issues.

### Supported Application/Server Configuration
Only the newest versions of Python and infrastructure services are supported. Older Python releases may not allow the code to work as expected.

The recommended server applications are nginx and gunicorn on operating systems utilizing systemd.

### Available Operating System Lookup
The following operating systems are currently available for data reporting.
Additional operating systems will be added in future releases.

- RHEL 6/7 (including CentOS)

### Contributing
See CONTRIBUTING.md for the most recent contributing guidelines.

### Providing Feedback
For any feedback, suggestions, requests, or bugs please utilize the issue tracker on GitHub.
