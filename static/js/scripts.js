document.addEventListener('DOMContentLoaded', function() {
    // IP Converter
    const convertBtn = document.getElementById('convertBtn');
    const resultText = document.getElementById('resultText');
    const copyResultBtn = document.getElementById('copyResultBtn');

    if (convertBtn) {
        convertBtn.addEventListener('click', function() {
            const inputValue = document.getElementById('inputValue').value.trim();
            const conversionType = document.querySelector('input[name="conversionType"]:checked').value;

            if (!inputValue) {
                resultText.textContent = 'Please enter a value to convert.';
                return;
            }

            fetch('/convert', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    input_value: inputValue,
                    conversion_type: conversionType
                })
            })
            .then(response => response.json())
            .then(data => {
                resultText.textContent = data.result;
            })
            .catch(error => {
                console.error('Error:', error);
                resultText.textContent = 'An error occurred during conversion.';
            });
        });

        copyResultBtn.addEventListener('click', function() {
            const textToCopy = resultText.textContent;
            navigator.clipboard.writeText(textToCopy).catch(err => {
                console.error('Error:', err);
            });
        });
    }

    // Subnet Calculator
    const calculateBtn = document.getElementById('calculateBtn');
    const subnetResult = document.getElementById('subnetResult');
    const copySubnetBtn = document.getElementById('copySubnetBtn');

    if (calculateBtn) {
        calculateBtn.addEventListener('click', function() {
            const ipAddress = document.getElementById('ipAddress').value.trim();
            const subnetMask = document.getElementById('subnetMask').value.trim();

            if (!ipAddress) {
                subnetResult.innerHTML = '<li class="list-group-item text-danger">Please enter an IP address.</li>';
                return;
            }

            if (!subnetMask) {
                subnetResult.innerHTML = '<li class="list-group-item text-danger">Please enter a subnet mask or CIDR notation.</li>';
                return;
            }

            fetch('/calculate_subnet', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    ip_address: ipAddress,
                    subnet_mask: subnetMask
                })
            })
            .then(response => response.json())
            .then(data => {
                subnetResult.innerHTML = '';
                if (data.error) {
                    subnetResult.innerHTML = `<li class="list-group-item text-danger">${data.error}</li>`;
                } else {
                    for (const [key, value] of Object.entries(data)) {
                        subnetResult.innerHTML += `<li class="list-group-item"><strong>${key}:</strong> ${value}</li>`;
                    }
                }
            })
            .catch(error => {
                console.error('Error:', error);
                subnetResult.innerHTML = '<li class="list-group-item text-danger">An error occurred during calculation.</li>';
            });
        });

        copySubnetBtn.addEventListener('click', function() {
            const items = subnetResult.getElementsByTagName('li');
            let textToCopy = '';
            for (let item of items) {
                textToCopy += item.textContent + '\n';
            }
            navigator.clipboard.writeText(textToCopy).catch(err => {
                console.error('Error:', err);
            });
        });
    }

    // Ping Utility
    const pingBtn = document.getElementById('pingBtn');
    const pingResult = document.getElementById('pingResult');
    const copyPingBtn = document.getElementById('copyPingBtn');

    if (pingBtn) {
        pingBtn.addEventListener('click', function() {
            const host = document.getElementById('pingInput').value.trim();

            if (!host) {
                pingResult.textContent = 'Please enter an IP address or hostname.';
                return;
            }

            pingResult.textContent = 'Pinging...';

            fetch('/ping_host', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    host: host
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    pingResult.textContent = data.error;
                } else {
                    pingResult.textContent = data.result;
                }
            })
            .catch(error => {
                console.error('Error:', error);
                pingResult.textContent = 'An error occurred during ping.';
            });
        });

        copyPingBtn.addEventListener('click', function() {
            const textToCopy = pingResult.textContent;
            navigator.clipboard.writeText(textToCopy).catch(err => {
                console.error('Error:', err);
            });
        });
    }

    // Reverse DNS Lookup
    const reverseDnsBtn = document.getElementById('reverseDnsBtn');
    const reverseDnsResult = document.getElementById('reverseDnsResult');
    const copyReverseDnsBtn = document.getElementById('copyReverseDnsBtn');

    if (reverseDnsBtn) {
        reverseDnsBtn.addEventListener('click', function() {
            const ipAddress = document.getElementById('reverseDnsInput').value.trim();

            if (!ipAddress) {
                reverseDnsResult.textContent = 'Please enter an IP address.';
                return;
            }

            fetch('/reverse_dns', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    ip_address: ipAddress
                })
            })
            .then(response => response.json())
            .then(data => {
                reverseDnsResult.textContent = data.result;
            })
            .catch(error => {
                console.error('Error:', error);
                reverseDnsResult.textContent = 'An error occurred during lookup.';
            });
        });

        copyReverseDnsBtn.addEventListener('click', function() {
            const textToCopy = reverseDnsResult.textContent;
            navigator.clipboard.writeText(textToCopy).catch(err => {
                console.error('Error:', err);
            });
        });
    }
});
