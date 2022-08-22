#!/usr/bin/env python3

import argparse
import xml.etree.ElementTree as ET
from os import path


def print_banner():
    separator = "#" * 50
    banner_text = "# Nmap XML to CSV converter v 1.0" + " " * 16 + "#\n"
    banner_text += "# By terasi" + " " * 38 + "#\n"
    banner_text += "# https://github.com/tera-si" + " " * 21 + "#"

    print(separator)
    print(banner_text)
    print(separator)


def check_file_exists(filename):
    return path.exists(filename)

def parse_xml(xml_file):
    parsed_data = {}
    ports_data = []

    try:
        document_root = ET.parse(xml_file).getroot()
        scan_info = document_root.find("scaninfo")
        host = document_root.find("host")

        port_type = scan_info.attrib["protocol"].upper()

        ip_address = host.find("address").attrib["addr"]
        parsed_data["ip"] = ip_address

        if host.find("os"):
            if host.find("os").find("osmatch"):
                detected_os = host.find("os").find("osmatch").attrib["name"]
                parsed_data["os"] = detected_os

        ports = host.find("ports").findall("port")
        for port in ports:
            port_details = {}

            port_details["number"] = port.attrib["portid"]
            port_details["type"] = port_type

            state = port.find("state")
            if state.attrib["state"] == "open":
                service_object = port.find("service")

                if service_object is not None:
                    port_details["service"] = service_object.attrib["name"].upper()

                    if "product" in service_object.attrib:
                        port_details["product"] = service_object.attrib["product"]
                    else:
                        port_details["product"] = ""

                    if "version" in service_object.attrib:
                        port_details["version"] = service_object.attrib["version"]
                    else:
                        port_details["version"] = ""

                else:
                    port_details["service"] = "unknown"
                    port_details["product"] = ""
                    port_details["version"] = ""

                ports_data.append(port_details)

        parsed_data["port_details"] = ports_data
        return parsed_data

    except Exception as e:
        print(f"[!] Unable to parse {xml_file}")
        print(f"[!] Exception: {e}")
        print("[!] Aborting...")
        print("[!] Check if the file is in valid XML syntax")
        exit()


def write_csv(filename, combined_ports):
    header = "protocol,number,service,product,version"

    with open(filename, "w") as opened_file:
        opened_file.write(header + "\n")

        for port in combined_ports:
            opened_file.write(f"{port['type']},{port['number']},{port['service']},{port['product']},{port['version']}\n")


def main():
    description = "Generate a CSV output from Nmap XML scan outputs."

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("tcp_xml", help="nmap TCP scan XML output", nargs="?")
    parser.add_argument("udp_xml", help="nmap UDP scan XML output", nargs="?")

    args = parser.parse_args()
    tcp_xml = args.tcp_xml
    udp_xml = args.udp_xml

    if tcp_xml is None and udp_xml is None:
        parser.print_help()
        print("\n[!] No XML output provided.")
        print("[!] Please provide at least one nmap XML output file.")
        exit()

    print_banner()
    combined_ports = []
    ip = None
    os = None

    print("[i] Parsing XML file(s)...")
    if tcp_xml:
        parsed_tcp = parse_xml(tcp_xml)

        if "ip" in parsed_tcp:
            ip = parsed_tcp["ip"]

        if "os" in parsed_tcp:
            os = parsed_tcp["os"]

        combined_ports += parsed_tcp["port_details"]

    if udp_xml:
        parsed_udp = parse_xml(udp_xml)

        if "ip" in parsed_udp:
            if ip is not None:
                if ip != parsed_udp["ip"]:
                    print("[!] Conflicting IPs detected in both nmap files")
                    print("[!] Aborting...")
                    exit()

            else:
                ip = parsed_udp["ip"]

        if "os" in parsed_udp:
            if os is not None:
                if os != parsed_udp["os"]:
                    os = f"{os}-or-{parsed_udp['os']}"

            else:
                os = parsed_udp["os"]

        combined_ports += parsed_udp["port_details"]

    if os is None:
        os = "unknown"

    filename = f"{ip}-{os}.csv"
    print(f"[i] Writing output csv file to '{filename}'...")
    if check_file_exists(filename) == True:
        print(f"[!] Output file '{filename}' already exists!")
        print("[!] Aborting...")
        exit()

    write_csv(filename, combined_ports)


if __name__ == "__main__":
    main()
