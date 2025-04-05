import argparse
import re
import logging
import sys
import pandas as pd

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define IOC regular expressions
IP_REGEX = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
URL_REGEX = r'(?:(?:https?|ftp):\/\/)?[\w/\-?=%.]+\.[\w/\-?=%.]+'
EMAIL_REGEX = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
MD5_REGEX = r'\b[0-9a-fA-F]{32}\b'
SHA1_REGEX = r'\b[0-9a-fA-F]{40}\b'
SHA256_REGEX = r'\b[0-9a-fA-F]{64}\b'
DOMAIN_REGEX = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'


def setup_argparse():
    """
    Sets up the argument parser for the command line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Extracts Indicators of Compromise (IOCs) from text.")
    parser.add_argument("input", nargs="?", type=str, default="-",
                        help="Input file or '-' for stdin (default: stdin)")
    parser.add_argument("-o", "--output", type=str, help="Output file (CSV format)", required=False)
    parser.add_argument("-i", "--ioc-type", type=str, choices=['ip', 'url', 'email', 'md5', 'sha1', 'sha256', 'domain', 'all'],
                        default='all', help="Type of IOC to extract (default: all)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (logging)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress all output except errors")

    return parser


def extract_iocs(text, ioc_type='all'):
    """
    Extracts IOCs from the given text based on the specified type.

    Args:
        text (str): The input text to analyze.
        ioc_type (str): The type of IOC to extract ('ip', 'url', 'email', 'md5', 'sha1', 'sha256', 'domain', 'all').

    Returns:
        dict: A dictionary containing lists of extracted IOCs for each type.
    """
    iocs = {
        'ip': [],
        'url': [],
        'email': [],
        'md5': [],
        'sha1': [],
        'sha256': [],
        'domain': []
    }

    try:
        if ioc_type in ('ip', 'all'):
            iocs['ip'] = list(set(re.findall(IP_REGEX, text)))
        if ioc_type in ('url', 'all'):
            iocs['url'] = list(set(re.findall(URL_REGEX, text)))
        if ioc_type in ('email', 'all'):
            iocs['email'] = list(set(re.findall(EMAIL_REGEX, text)))
        if ioc_type in ('md5', 'all'):
            iocs['md5'] = list(set(re.findall(MD5_REGEX, text)))
        if ioc_type in ('sha1', 'all'):
            iocs['sha1'] = list(set(re.findall(SHA1_REGEX, text)))
        if ioc_type in ('sha256', 'all'):
            iocs['sha256'] = list(set(re.findall(SHA256_REGEX, text)))
        if ioc_type in ('domain', 'all'):
            iocs['domain'] = list(set(re.findall(DOMAIN_REGEX, text)))

    except Exception as e:
        logging.error(f"Error during IOC extraction: {e}")
        return None

    return iocs


def main():
    """
    Main function to drive the IOC extraction process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Configure logging based on verbosity
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")
    elif args.quiet:
        logging.getLogger().setLevel(logging.ERROR)

    try:
        # Read input from file or stdin
        if args.input == "-":
            logging.debug("Reading input from stdin.")
            input_text = sys.stdin.read()
        else:
            logging.debug(f"Reading input from file: {args.input}")
            try:
                with open(args.input, 'r', encoding='utf-8') as f:
                    input_text = f.read()
            except FileNotFoundError:
                logging.error(f"Error: Input file not found: {args.input}")
                sys.exit(1)
            except Exception as e:
                logging.error(f"Error reading input file: {e}")
                sys.exit(1)

        # Extract IOCs
        iocs = extract_iocs(input_text, args.ioc_type)

        if iocs is None:
            logging.error("IOC extraction failed.")
            sys.exit(1)

        # Prepare data for output
        data = []
        for ioc_type, ioc_list in iocs.items():
            for ioc in ioc_list:
                data.append({'ioc_type': ioc_type, 'ioc_value': ioc})

        df = pd.DataFrame(data)

        # Output results to file or stdout
        if args.output:
            try:
                df.to_csv(args.output, index=False)
                logging.info(f"IOCs written to: {args.output}")
            except Exception as e:
                logging.error(f"Error writing to output file: {e}")
                sys.exit(1)
        else:
            if not args.quiet:
                print(df.to_string())

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()


# Usage examples:
# 1. Extract all IOCs from a file:
#    python main.py input.txt
#
# 2. Extract only IP addresses from a file and save to output.csv:
#    python main.py input.txt -o output.csv -i ip
#
# 3. Extract all IOCs from stdin:
#    cat input.txt | python main.py -
#
# 4. Verbose mode (debug logging):
#    python main.py input.txt -v
#
# 5. Quiet mode (only errors are printed):
#   python main.py input.txt -q