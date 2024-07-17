import argparse
import sys
import os
from termcolor import colored
from time import sleep
import subprocess


hostList = []


class Mode:
    def __init__(self, target) -> None:
        self.target = target

    def subfinder(self):
        tool_name="subfinder"
        command = [f"{tool_name}", "-d", self.target, "-silent"]
        print(colored("[+] Running {0} on {1}".format(tool_name,self.target), "green"))
        try:
            output = subprocess.check_output(command, text=True)
            print(output)
            with open(f"{tool_name}.txt", "a") as file:
                file.write(output)
        except subprocess.CalledProcessError as e:
            print(f"Command failed with return code {e.returncode}")

    def assetfinder(self):
        tool_name="assetfinder"
        command = [f"{tool_name}", "-subs-only", self.target]
        print(colored("[+] Running {0} on {1}".format(tool_name,self.target), "green"))
        try:
            output = subprocess.check_output(command, text=True)
            print(output)
            with open(f"{tool_name}.txt", "a") as file:
                file.write(output)
        except subprocess.CalledProcessError as e:
            print(f"Command failed with return code {e.returncode}")


def processHostFile(target, modes):
    with open(target, "r") as file:
        for line in file:
            host = line.strip()
            hostList.append(host)
    for host in hostList:
        findSubDomains(host, modes)


def findSubDomains(target, modes):
    p1 = Mode(target)
    for mode in modes:
        if mode == "subfinder":
            p1.subfinder()
        elif mode == "assetfinder":
            p1.assetfinder()


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Subdomain Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-d", "-domain", dest="domainName", metavar="", help="Domain Name"
    )
    parser.add_argument(
        "-dL",
        "-domains",
        dest="domainFile",
        metavar="",
        help="File Containing multiple Domain Names",
    )
    parser.add_argument(
        "-m",
        "-modes",
        dest="modes",
        metavar="",
        choices=["subfinder", "assetfinder"],
        nargs="+",
        help="Specify Modes",
    )
    return parser.parse_args()


def main():
    args = parse_arguments()

    if args.domainFile and args.modes:
        if os.path.exists(args.domainFile):
            processHostFile(args.domainFile, args.modes)
        else:
            sys.stderr.write(
                colored("[!] {} Not Found".format(args.domainFile), "yellow")
            )
            sys.exit()
    elif args.domainName and args.modes:
        findSubDomains(args.domainName, args.modes)
        sys.exit()
    else:
        print("help")


if __name__ == "__main__":
    if sys.platform.startswith("win"):
        os.system("cls")
    elif sys.platform.startswith("clear"):
        os.system("clear")

    try:
        os.makedirs("SubDomains")
        print(colored("[~] SubDomains Directory Created", "cyan"))
        os.chdir("SubDomains")
        main()
    except OSError as e:
        sys.stderr.write(
            colored(f"[!] Error creating or accessing directory: {e}", "red")
        )
        sys.exit()
    except Exception as e:
        sys.stderr.write(colored(f"[!] Unexpected error: {e}", "red"))
        sys.exit()
