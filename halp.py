import ipaddress
import socket
import requests
import yaml
import os
from bs4 import BeautifulSoup
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import nmap
import re
import http.server
import socketserver
from datetime import datetime, timedelta
import time
import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from http.server import SimpleHTTPRequestHandler

# Disable InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def load_config(config_file):
    with open(config_file, 'r') as file:
        config = yaml.safe_load(file)
    return config

config = load_config("config.yaml")


def configure_logging():
    # Main script logging
    main_logger = logging.getLogger('HALPMain')
    main_log_level = getattr(logging, config['log_settings']['main_log_level'].upper(), logging.INFO)
    main_logger.setLevel(main_log_level)
    main_handler = logging.FileHandler(config['log_settings']['main_log_file'])
    main_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    main_handler.setFormatter(main_formatter)
    main_logger.addHandler(main_handler)

    # Web server logging
    ws_logger = logging.getLogger('HALPWebServer')
    ws_log_level = getattr(logging, config['log_settings']['web_server_log_level'].upper(), logging.INFO)
    ws_logger.setLevel(ws_log_level)
    ws_handler = logging.FileHandler(config['log_settings']['web_server_log_file'])
    ws_handler.setFormatter(main_formatter)
    ws_logger.addHandler(ws_handler)

    return main_logger, ws_logger

main_logger, ws_logger = configure_logging()

def get_dns_name(ip, timeout=3):
    try:
        socket.setdefaulttimeout(timeout)
        # Convert IP address to string
        ip_str = str(ip)
        return socket.gethostbyaddr(ip_str)[0]
    except Exception as e:  # Catching a broader range of exceptions
        main_logger.warning(f"DNS resolution failed for {ip}: {e}")  # Debugging statement
        return None
    finally:
        socket.setdefaulttimeout(None)

def run_nmap_scan(ip):
    nm = nmap.PortScanner()
    try:
        ip_str = str(ip)
        nm.scan(ip_str, arguments='-sT -p- -T5 --host-timeout 60s')

        if ip_str in nm.all_hosts():
            tcp_scan_data = nm[ip_str].get('tcp', {})
            return tcp_scan_data  # Pass only the TCP scan data
        else:
            main_logger.warning(f"No scan results for {ip_str}")
            return {}

    except Exception as e:
        main_logger.warning(f"Error scanning {ip_str}: {e}")
        return {}


def parse_nmap_output(ip, tcp_scan_data):
    open_ports = []

    # Iterate over the TCP scan data
    for port, port_data in tcp_scan_data.items():
        if port_data.get('state') == 'open':
            open_ports.append(port)

    return open_ports

def check_http_response(url):
    try:
        response = requests.get(url, timeout=3, verify=False)
        return response.status_code == 200
    except Exception:
        return False
    
def get_content_type(response):
    """Extracts content type from the HTTP response headers."""
    content_type = response.headers.get('Content-Type', '')
    return content_type.split(';')[0]  # Return MIME type without charset

def is_valid_image(mime_type):
    """Checks if the MIME type is one of the valid image formats."""
    valid_types = ['image/svg+xml', 'image/png', 'image/x-icon', 'image/vnd.microsoft.icon']
    return mime_type in valid_types

def download_favicon(favicon_url, output_directory, ip, port):
    """
    Downloads the favicon from the given URL and saves it with a unique name based on the IP and port.

    Args:
        favicon_url (str): URL of the favicon to download.
        output_directory (str): Directory where the favicon should be saved.
        ip (str): IP address of the server the favicon belongs to.
        port (int): Port number of the service the favicon belongs to.

    Returns:
        str: Path to the saved favicon relative to the output_directory, or None if download failed.
    """
    try:
        response = requests.get(favicon_url, timeout=3, stream=True, verify=False)
        mime_type = get_content_type(response)
        if response.status_code == 200 and is_valid_image(mime_type):
            parsed_url = urlparse(favicon_url)
            filename = os.path.basename(parsed_url.path)
            # Create a unique filename by appending the IP and port
            unique_filename = f"{ip}_{port}_{filename}"
            save_path = os.path.join(output_directory, "assets", unique_filename)
            
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            
            with open(save_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    
            return os.path.join("assets", unique_filename)
    except Exception as e:
        main_logger.error(f"Error downloading favicon from {favicon_url}: {e}")
    
    return None

def get_favicon_and_title(url, output_directory, ip, port):
    paths = ['','images', 'assets', 'img', 'Content/Images/Icons', 'Content/Images', 'images/favicon']
    prefixes = [ 'apple-touch-icon', 'logo', 'favicon', 'icon']
    separators = ['','-', '_']
    resolutions = ['','256x256', '196x196', '180x180', '128x128',]
    filetypes = ['svg', 'png']

    try:
        response = requests.get(url, timeout=3, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')
        title = soup.title.string if soup.title else "No Title Found"
        
        # Look for a <link rel="icon"> tag
        icon_tags = soup.find_all('link', rel=['apple-touch-icon'])
        for icon_tag in icon_tags:
            icon_url = icon_tag.get('href')
            if icon_url:
                full_icon_url = urljoin(url, icon_url)
                if check_http_response(full_icon_url):
                    relative_path = download_favicon(full_icon_url, output_directory, ip, port)
                    if relative_path:
                        return relative_path, title  
        
        icon_tags = soup.find_all('link', rel=['icon'], attrs={'type': ['image/svg+xml']})
        for icon_tag in icon_tags:
            icon_url = icon_tag.get('href')
            if icon_url:
                full_icon_url = urljoin(url, icon_url)
                if check_http_response(full_icon_url):
                    relative_path = download_favicon(full_icon_url, output_directory, ip, port)
                    if relative_path:
                        return relative_path, title 
                    
        # Try all combinations
        for filetype in filetypes:
            for prefix in prefixes:
                for path in paths:
                    for separator in separators:
                        for res in resolutions:
                            icon_url = f"{url}/{path}/{prefix}{separator}{res}.{filetype}"
                            if check_http_response(icon_url):
                                relative_path = download_favicon(icon_url, output_directory, ip, port)  # Corrected variable here
                                if relative_path:
                                    # Use the relative path in your HTML instead of the direct URL
                                    main_logger.debug(f"The relative path is {relative_path}")
                                    icon_url = relative_path
                                return icon_url, title 
                    
        # Fallback to favicon.ico
        favicon_url = urljoin(url, '/favicon.ico')
        if check_http_response(favicon_url):
            relative_path = download_favicon(favicon_url, output_directory, ip, port)  # This is correct
            if relative_path:
                    # Use the relative path in your HTML instead of the direct URL
                    main_logger.debug(f"The relative path is {relative_path}")
                    favicon_url = relative_path  # Here you should also use favicon_url or adjust accordingly
            return favicon_url, title  # Adjust based on the previous line
    
        favicon_url = 'assets/missing_favicon.png'

    except Exception as e:
        main_logger.error(f"Error getting favicon and title for {url}: {e}")

    return favicon_url, "No Title Found"



def scan_ip(ip, open_ports, html_lock, output_file, output_directory):
    main_logger.info(f"Currently scanning IP: {ip} with ports: {open_ports}")  # Debug: IP and open ports
    dns_name = get_dns_name(ip, timeout=2) or ip
    section_content = []
    applications_detected = False
    for port in open_ports:
        # Initially, try connecting using HTTP
        url_http = f"http://{ip}:{port}"
        http_success = check_http_response(url_http)

        if http_success:
            favicon_url, title = get_favicon_and_title(url_http, output_directory, ip, port)
            url_used = url_http
        else:
            # If HTTP fails, try HTTPS on the same port
            url_https = f"https://{ip}:{port}"
            https_success = check_http_response(url_https)
            if https_success:
                favicon_url, title = get_favicon_and_title(url_https, output_directory, ip, port)
                url_used = url_https
            else:
                continue  # Move to the next port if both HTTP and HTTPS attempts fail

        # If either HTTP or HTTPS was successful
        applications_detected = True
        section_content.append(f"<div class='server'><a href='{url_used}' target='_blank'><img src='{favicon_url}' class='logo' alt=''><div class='title'>{title}</div><div class='url'>{url_used}</div></a></div>")
        main_logger.info(f"URL detected: {url_used}")  # Debug: URL detected

    with html_lock:
        with open(output_file, "a") as file:
            if applications_detected:
                file.write(f"<div class='ip-section'>\n")  # Start a new section for each IP
                file.write(f"<h2 class='ip-title'>{dns_name} - {ip}</h2>\n")
                file.write("<div class='servers-container'>\n")  # Container for server tiles
                file.write("".join(section_content))
                file.write("</div>\n")  # Close the servers container
                file.write("</div>\n")  # Close the IP section

    main_logger.info(f"Finished scanning IP: {ip}")

def create_html_skeleton(output_file):
    with open(output_file, "w") as file:
        last_updated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file.write(f'''
<html>
<head>
<style>
body {{
    font-family: Arial, sans-serif;
    background-color: #121212;
    color: #e0e0e0;
    margin: 0;
    padding: 20px;
}}
.ip-section {{
    margin-bottom: 30px; /* Space between each IP section */
}}
.ip-title {{
    margin-bottom: 10px; /* Space between IP title and server tiles */
}}
.servers-container {{
    display: flex;
    flex-wrap: wrap;
    gap: 20px;
    justify-content: left;
}}
.server {{
    width: 256px; /* Width of each server tile */
    height: 256px; /* Height of each server tile */
    background-color: #1e1e1e;
    border-radius: 8px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    overflow: hidden;
    transition: transform 0.3s ease, font-size 0.3s ease;
}}
.server:hover {{
    transform: scale(1.05);
    background-color: #292929;
}}
.server a {{
    color: #e0e0e0;
    text-decoration: none;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
}}
.server a:hover, .server a:visited {{
    color: #c0c0c0;
}}
.logo {{
    height: 128px;
    width: 128px;
    object-fit: contain;
    margin-bottom: 10px;
}}
.title, .url {{
    transition: font-size 0.3s ease;
}}
.server:hover .title, .server:hover .url {{
    font-size: larger;
}}
.title {{
    font-weight: bold;
    text-align: center;
    margin: 5px 10px;
}}
.url {{
    font-size: 0.8em;
    text-align: center;
    margin: 5px 10px;
}}
.last-updated {{
    position: absolute;
    top: 10px;
    right: 10px;
    font-size: 12px;
}}
</style>
        <title>HomeserverAutoLandingPage (HALP)</title>
</head>
<body>
<div class="last-updated">Last Updated: {last_updated}</div>
<div class="container">
<!-- Server tiles and other content will go here -->
</div>
</body>
</html>
''')

# Note: Make sure to dynamically add the server tiles and other content within the container div in your script.


class CustomHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        ws_logger.info("%s - %s" % (self.address_string(), format % args))


def start_web_server(port, directory):
    os.chdir(directory)
    handler = CustomHTTPHandler

    with socketserver.TCPServer(("", port), handler) as httpd:
        main_logger.info(f"Serving at port {port}")
        httpd.serve_forever()

def main(config_file='config.yaml'):
    main_logger.info(f"Script started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    while True:
        start_time = datetime.now()
        config = load_config(config_file)

        web_server_port = config.get('web_server_port', 8000)
        output_directory = config.get('output_directory', '.')
        update_interval_hours = config.get('update_interval_hours', 24)
        enable_webserver = config.get('enable_webserver', False)  # Default to False if not specified

        os.makedirs(output_directory, exist_ok=True)

        temp_output_file = os.path.join(output_directory, 'temp_web_servers.html')
        final_output_file = os.path.join(output_directory, config.get('output_file', 'web_servers.html'))

        # Check if update is needed
        create_html_skeleton(temp_output_file)

        cidr_ranges = config.get('cidr_ranges', '').split(',')
        num_threads = config.get('num_threads', 2)
        html_lock = threading.Lock()

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            for cidr in cidr_ranges:
                for ip in ipaddress.ip_network(cidr):
                    nmap_output = run_nmap_scan(ip)
                    open_ports = parse_nmap_output(ip, nmap_output)
                    if open_ports:
                        executor.submit(scan_ip, ip, open_ports, html_lock, temp_output_file,output_directory)

        # Replace the old HTML file with the updated one
        os.replace(temp_output_file, final_output_file)

        # Start or restart the web server
        main_logger.info(f"Update completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        main_logger.info(f"Next update scheduled after {update_interval_hours} hours")

        if enable_webserver:
            main_logger.warning("Web server functionality is enabled.")
            start_web_server(web_server_port, output_directory)
        else:
            main_logger.warning("Web server functionality is disabled. Skipping web server start.")


        time.sleep(update_interval_hours * 3600)

if __name__ == "__main__":
    main()