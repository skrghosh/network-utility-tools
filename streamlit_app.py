import ipaddress
import socket
from ping3 import ping
import streamlit as st
import base64
# from streamlit_copyable_text import copyable_text


st.set_page_config(page_title="Network Utility Tools", page_icon="🌐")

st.title("Network Utility Tools")


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
            return '.'.join([str(int(hex_address[i:i + 2], 16)) for i in (0, 2, 4, 6)])
        elif len(hex_address) == 32:
            ip_address = ':'.join([hex_address[i:i + 4] for i in range(0, 32, 4)])
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
                subnet_mask = subnetmask_to_cidr(subnet_mask)
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


def js_copy_button(text_to_copy, button_text):
    """
    Generates HTML and JavaScript to create a button that copies text to the clipboard.

    Parameters:
    - text_to_copy (str): The text to copy to the clipboard.
    - button_text (str): The text to display on the button.

    Returns:
    - str: HTML and JavaScript code for the button.
    """
    copy_code = f"""
    <button onclick="copyToClipboard('{text_to_copy}')" style='background-color:#004747;color:white;padding:8px 16px;border:none;border-radius:5px;cursor:pointer;margin-top:10px;'>{button_text}</button>
    <script>
    function copyToClipboard(text) {{
        const el = document.createElement('textarea');
        el.value = text;
        document.body.appendChild(el);
        el.select();
        document.execCommand('copy');
        document.body.removeChild(el);
        alert('Copied to clipboard!');
    }}
    </script>
    """
    return copy_code

# Create tabs
tabs = st.tabs(["IP Converter", "Subnet Calculator", "Reverse DNS Lookup", "Ping Utility"])

# IP Converter Tab
with tabs[0]:
    st.header("IP Converter")
    input_value = st.text_input("Enter IP Address, Hexadecimal Value, Subnet Mask, or CIDR Notation:", key="converter_input")
    conversion_type = st.radio(
        "Select Conversion Type:",
        (
            "IP Address to Hexadecimal",
            "Hexadecimal to IP Address",
            "Subnet Mask to CIDR Notation",
            "CIDR Notation to Subnet Mask"
        ),
        key="converter_type"
    )
    if st.button("Convert", key="converter_button"):
        if not input_value:
            st.error("Please enter a value to convert.")
        else:
            if conversion_type == 'IP Address to Hexadecimal':
                result = ip_to_hex(input_value)
            elif conversion_type == 'Hexadecimal to IP Address':
                result = hex_to_ip(input_value)
            elif conversion_type == 'Subnet Mask to CIDR Notation':
                result = subnetmask_to_cidr(input_value)
            elif conversion_type == 'CIDR Notation to Subnet Mask':
                result = cidr_to_subnetmask(input_value)
            else:
                result = 'Invalid conversion type.'
            st.subheader("Result:")
            st.code(result, language='')

# Subnet Calculator Tab
with tabs[1]:
    st.header("Subnet Calculator")
    ip_address = st.text_input("Enter IP Address:", key="subnet_ip")
    subnet_mask = st.text_input("Enter Subnet Mask or CIDR Notation:", key="subnet_mask")
    if st.button("Calculate", key="subnet_button"):
        if not ip_address:
            st.error("Please enter an IP address.")
        elif not subnet_mask:
            st.error("Please enter a subnet mask or CIDR notation.")
        else:
            result = calculate_subnet(ip_address, subnet_mask)
            if 'error' in result:
                st.error(result['error'])
            else:
                st.subheader("Subnet Information:")
                all_results = '\n'.join(f"{key}: {value}" for key, value in result.items())
                st.code(all_results, language='')

# Reverse DNS Lookup Tab
with tabs[2]:
    st.header("Reverse DNS Lookup")
    reverse_ip = st.text_input("Enter IP Address:", key="reverse_dns_ip")
    if st.button("Lookup", key="reverse_dns_button"):
        if not reverse_ip:
            st.error("Please enter an IP address.")
        else:
            result = reverse_dns_lookup(reverse_ip)
            st.subheader("Result:")
            st.code(result, language='')

# Ping Utility Tab
with tabs[3]:
    st.header("Ping Utility")
    host = st.text_input("Enter IP Address or Hostname:", key="ping_host")
    if st.button("Ping", key="ping_button"):
        if not host:
            st.error("Please enter an IP address or hostname.")
        else:
            st.write("Pinging...")
            result = ping_host(host)
            if 'error' in result:
                st.error(result['error'])
            else:
                st.subheader("Result:")
                st.code(result['result'], language='')
