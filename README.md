# CRLF Scanner

CRLF Scanner is a Burp Suite extension written in Python that actively tests for CRLF (Carriage Return Line Feed) injection vulnerabilities by appending encoded newline payloads to URLs and analyzing HTTP response headers for injected headers.

## Features

### Detection of CRLF Injection
The extension performs active scans by appending various encoded newline sequences followed by a test header payload (`Set-Cookie:param=6h4ack`) to URL paths and monitors the server’s HTTP response headers for the injected header. This helps detect vulnerabilities where user input is improperly sanitized and injected into response headers.

### Active Scanning Approach
- Iterates over all URLs found in the Burp site map for the target host.
- For each URL, sends requests appending a variety of CRLF payloads.
- Checks response headers for presence of `Set-Cookie: param=6h4ack` to confirm vulnerability.
- Flags confirmed findings as issues with high severity.

### Manual Scan via Context Menu
- Right-click on any request in Burp.
- Choose **"Scan CRLF Injection on Host"** to launch a scan against all URLs for the selected host.
- Progress and results are outputted in Burp’s extension output tab.

## How It Works

### Payload Injection
The scanner appends encoded newline characters plus a test header to URLs. Examples of payloads include:

```
%0aSet-Cookie:param=6h4ack
%0d%0aSet-Cookie:param=6h4ack
%0d%0a%09Set-Cookie:param=6h4ack
%3f%0aSet-Cookie:param=6h4ack
```

These payloads try to break HTTP header boundaries and inject a new header.

### Response Analysis
The extension scans the returned response headers for exact matches of:

```
Set-Cookie: param=6h4ack
```

If found, it flags the URL as vulnerable to CRLF injection.

### Issue Reporting
When a vulnerability is found, a Burp scan issue is created with details about the affected URL and the injected header observed.

## Installation

### Clone the Repository

```sh
git clone https://github.com/6h4ack/CRLF-Scanner.git
cd CRLF-Scanner
```

### Load Extension in Burp Suite

1. Open Burp Suite.  
2. Go to the Extender tab and click **Add**.  
3. Select **Python** as the extension type.  
4. Choose the `crlf-scanner.py` file from this repository.  
5. Click **Next** and then **Done**.

### Verification

Check Burp’s Extension Output tab for the message:

```
Starting CRLF scan on: <host>
```

and subsequent scan progress messages when you trigger a scan.

## Usage

### Active Scan

1. Right-click any request in Burp and select **Scan CRLF Injection on Host**.
2. The extension will scan all URLs on the target host for CRLF vulnerabilities.
3. Results will be displayed as issues in Burp’s Scanner tab and output logs.

## Contributing

Feel free to open issues or pull requests to improve the extension.
