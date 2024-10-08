# Network Utility Tools

A comprehensive web-based toolkit for network engineers, system administrators, and cybersecurity professionals. This application provides essential network utilities such as IP address conversion, subnet calculations, reverse DNS lookup, and a ping utility—all in one convenient interface.

## Table of Contents

- [Features](#features)
- [Demo](#demo)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Setup](#setup)
- [Usage](#usage)
  - [IP Converter](#ip-converter)
  - [Subnet Calculator](#subnet-calculator)
  - [Reverse DNS Lookup](#reverse-dns-lookup)
  - [Ping Utility](#ping-utility)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Features

- **IP Converter**: Convert between IP addresses and their hexadecimal representations. Supports both IPv4 and IPv6.
- **Subnet Mask to CIDR Conversion**: Convert subnet masks to CIDR notation and vice versa.
- **Subnet Calculator**: Calculate network information based on IP address and subnet mask or CIDR notation.
- **Reverse DNS Lookup**: Find the domain name associated with an IP address.
- **Ping Utility**: Check the reachability of a host by sending ICMP echo requests.

## Demo

You can access a live demo of the application [here](https://network-utility-tools-5n57vbum9qb9xyw3uk8wp8.streamlit.app/). 

## Installation

### Prerequisites

- **Python 3.6+**
- **pip** (Python package installer)

### Setup

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/your-repo-name.git
   cd your-repo-name
   ```

2. **Create a Virtual Environment (Optional but Recommended)**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Application**

   ```bash
   python app.py
   ```

5. **Access the Application**

   Open your web browser and navigate to `http://localhost:5000`

## Usage

### IP Converter

- **IP Address to Hexadecimal**
  - Enter an IPv4 or IPv6 address.
  - Select "IP Address to Hexadecimal".
  - Click "Convert" to get the hexadecimal representation.

- **Hexadecimal to IP Address**
  - Enter a hexadecimal value.
  - Select "Hexadecimal to IP Address".
  - Click "Convert" to get the IP address.

### Subnet Calculator

- Enter an IP address.
- Enter a subnet mask or CIDR notation.
- Click "Calculate" to view subnet information such as network address, broadcast address, subnet mask, wildcard mask, number of hosts, and IP version.

### Reverse DNS Lookup

- Enter an IP address.
- Click "Lookup" to find the associated domain name.

### Ping Utility

- Enter an IP address or hostname.
- Click "Ping" to send ICMP echo requests and receive the response time.


## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create your feature branch: `git checkout -b feature/your-feature-name`
3. Commit your changes: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin feature/your-feature-name`
5. Open a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **[Flask](https://flask.palletsprojects.com/)** - The web framework used.
- **[Bootstrap](https://getbootstrap.com/)** - For responsive UI components.
- **[ping3](https://github.com/kyan001/ping3)** - Used for the Ping Utility.
- **[ipaddress](https://docs.python.org/3/library/ipaddress.html)** - Python module for IP address manipulation.
