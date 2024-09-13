from flask import Flask, render_template, request, jsonify
import ipaddress
import socket
from ping3 import ping

app = Flask(__name__)

def ip_to_hex(ip_address):
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return ''.join(['{:02X}'.format(int(octet)) for octet in ip_address.split('.')])
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            full_ipv6 = ip_obj.exploded
            return full_ipv6.replace(':', '')
    except ValueError:
        return 'Invalid IP address format.'

def hex_to_ip(hex_address):
    try:
        hex_address = hex_address.replace(':', '').replace('-', '')
        if len(hex_address) == 8:
            return '.'.join([str(int(hex_address[i:i+2], 16)) for i in (0, 2, 4, 6)])
        elif len(hex_address) == 32:
            ip_address = ':'.join([hex_address[i:i+4] for i in range(0, 32, 4)])
            ip_obj = ipaddress.IPv6Address(ip_address)
            return ip_obj.compressed
        else:
            return 'Invalid hexadecimal length for IP conversion.'
    except ValueError:
        return 'Invalid hexadecimal format.'

def subnetmask_to_cidr(subnet_mask):
    try:
        if '/' in subnet_mask:
            return 'Input is already in CIDR notation.'
        else:
            mask_octets = subnet_mask.split('.')
            if len(mask_octets) != 4:
                return 'Invalid subnet mask format.'
            binary_str = ''.join([bin(int(octet)).lstrip('0b').zfill(8) for octet in mask_octets])
            if '01' in binary_str:
                return 'Invalid subnet mask: bits are not contiguous.'
            cidr = str(binary_str.count('1'))
            return f"/{cidr}"
    except ValueError:
        return 'Invalid subnet mask.'

def cidr_to_subnetmask(cidr_notation):
    try:
        if not cidr_notation.startswith('/'):
            cidr_notation = '/' + cidr_notation
        cidr_value = int(cidr_notation.strip('/'))
        if not (0 <= cidr_value <= 32):
            return 'CIDR notation must be between 0 and 32 for IPv4.'
        network = ipaddress.ip_network('0.0.0.0' + cidr_notation, strict=False)
        return str(network.netmask)
    except ValueError:
        return 'Invalid CIDR notation.'

def calculate_subnet(ip_address, subnet_mask):
    try:
        if '/' in ip_address:
            network = ipaddress.ip_network(ip_address, strict=False)
        else:
            if not subnet_mask.startswith('/'):
                subnet_mask_validation = subnetmask_to_cidr(subnet_mask)
                if 'Invalid' in subnet_mask_validation:
                    return {'error': subnet_mask_validation}
            network = ipaddress.ip_network(f"{ip_address}{subnet_mask}", strict=False)

        subnet_info = {
            'Network Address': str(network.network_address),
            'Broadcast Address': str(network.broadcast_address) if network.version == 4 else 'N/A',
            'Subnet Mask': str(network.netmask),
            'Wildcard Mask': str(network.hostmask),
            'Number of Hosts': network.num_addresses - 2 if network.version == 4 and network.num_addresses >= 2 else network.num_addresses,
            'IP Version': f"IPv{network.version}"
        }

        return subnet_info

    except ValueError as e:
        return {'error': str(e)}

def reverse_dns_lookup(ip_address):
    try:
        ipaddress.ip_address(ip_address)  # Validate IP address format
        result = socket.gethostbyaddr(ip_address)
        return result[0]
    except ValueError:
        return 'Invalid IP address format.'
    except socket.herror:
        return 'No reverse DNS record found for this IP.'
    except Exception as e:
        return f'An error occurred: {str(e)}'


def ping_host(host):
    try:
        # Validate IP address or hostname
        try:
            ipaddress.ip_address(host)
        except ValueError:
            # If not an IP, check if it's a valid hostname
            try:
                socket.gethostbyname(host)
            except socket.gaierror:
                return {'error': 'Invalid IP address or hostname.'}

        response_time = ping(host, timeout=2, unit='ms')
        if response_time is None:
            return {'result': f'Host {host} is unreachable.'}
        else:
            return {'result': f'Reply from {host}: time={response_time:.2f} ms'}
    except Exception as e:
        return {'error': f'An error occurred: {str(e)}'}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/convert', methods=['POST'])
def convert():
    data = request.get_json()
    input_value = data.get('input_value')
    conversion_type = data.get('conversion_type')

    if conversion_type == 'ip_to_hex':
        result = ip_to_hex(input_value)
    elif conversion_type == 'hex_to_ip':
        result = hex_to_ip(input_value)
    elif conversion_type == 'subnetmask_to_cidr':
        result = subnetmask_to_cidr(input_value)
    elif conversion_type == 'cidr_to_subnetmask':
        result = cidr_to_subnetmask(input_value)
    else:
        result = 'Invalid conversion type.'

    return jsonify({'result': result})

@app.route('/calculate_subnet', methods=['POST'])
def calculate_subnet_route():
    data = request.get_json()
    ip_address = data.get('ip_address')
    subnet_mask = data.get('subnet_mask')

    result = calculate_subnet(ip_address, subnet_mask)

    return jsonify(result)

@app.route('/reverse_dns', methods=['POST'])
def reverse_dns_route():
    data = request.get_json()
    ip_address = data.get('ip_address')

    result = reverse_dns_lookup(ip_address)

    return jsonify({'result': result})

@app.route('/ping_host', methods=['POST'])
def ping_host_route():
    data = request.get_json()
    host = data.get('host')

    result = ping_host(host)

    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
