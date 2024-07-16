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
        print(colored("[+] Running subfinder on {}".format(self.target), "green"))
        command = [
            "subfinder",
            "-d",
            self.target
        ]
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = process.communicate()
        if stderr:
            print(colored(f"Error running subfinder on {self.target}: {stderr}", "red"))
            return

        if stdout:
            for line in stdout.splitlines():
                print(line.strip())
        else:
            print(colored(f"No subdomains found for {self.target}", "yellow"))

    def assetfinder(self):
        print(colored("[+] Running assetfinder on {}".format(self.target), "blue"))


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
        description="", formatter_class=argparse.RawDescriptionHelpFormatter
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
    main()
