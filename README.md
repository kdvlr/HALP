# HomeserverAutoLandingPage (HALP)

***Disclaimer: This script uses port scanning techniques. Use it responsibly and with authorized permission. Unauthorized port scanning may be considered illegal or intrusive.***

**HALP automatically scans your home network, identifies web services running on your servers, and creates a visual web page to access them easily.**

## Features

- Scans specified IP ranges for open ports
- Identifies web services running on those ports
- Fetches favicons and titles for the services
- Generates a user-friendly HTML page with clickable tiles for each service
- Optionally hosts the HTML page on a built-in web server
- Updates the information periodically

## Screenshot
![HALP Screenshot](./screenshot.png?raw=true "HALP-Screenshot")

## Configuration

Refer to the `config.yaml` file for configuration options.

## Installation

1. Clone this repository:
   ```git clone [https://github.com/your-username/HALP.git](https://github.com/your-username/HALP.git)```

2. Install required libraries:
```pip install -r requirements.txt```

3. Edit the config.yaml file to match your network settings and preferences.

Run the script:
```python halp.py```

You can also use `halp.sh` to start the script

## Instructions
### Accessing the Landing Page:

If you enabled the web server, access the landing page by opening http://localhost:8000 (or the specified port) in your web browser. 

If you prefer to use your own web server, serve the www directory using a web server of your choice

### Updates:

The script automatically updates the information periodically. You can also manually trigger an update by restarting the script.

Configuration Options: 
- cidr_ranges: A comma-separated list of CIDR ranges to scan.
- output_directory: The directory where the HTML file and assets will be saved.
- output_file: The name of the output HTML file.
- web_server_port: The port on which the web server will listen (if enabled).
- enable_webserver: Set to True to enable the web server.
- update_interval_hours: The interval in hours between updates.
- main_log_level: The logging level for the main script.
- web_server_log_level: The logging level for the web server.

Additional Information
The script logs its activity to two log files: halp.log and halp_ws.log.
