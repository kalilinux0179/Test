import argparse
import sys
import os
from termcolor import colored
from time import sleep
import subprocess

hostList = []
chaos_key = "77548576-370c-4b63-81dc-bd62b278b7e9"


def createDirectory(directory):
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(colored("[-] {} Directory Created".format(directory), "cyan"))
            os.chdir(directory)
            return True
        else:
            os.chdir(directory)
            return True
    except OSError:
        sys.stderr.write(colored("[-] Unable to create {}".format(directory), "red"))
        sys.stderr.write(colored("Exiting...", "red"))


def clearScreen():
    if sys.platform.startswith("win"):
        os.system("cls")
    elif sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
        os.system("clear")


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
        metavar="",
        dest="domainFile",
        help="File Containing multiple Domain Names",
    )
    parser.add_argument(
        "-m",
        "-modes",
        dest="modes",
        # change here
        choices=[
            "subfinder",
            "assetfinder",
            "asnmap",
            "amass",
            "chaos",
            "findomain",
            "vita",
            "subcat",
            "rapiddns",
            "crtsh",
            "jldc",
            "all",
        ],
        nargs="+",
        help="Specify Modes",
    )
    return parser.parse_args()


class Mode:
    def __init__(self, target) -> None:
        self.target = target

    def subfinder(self):
        sleep(1)
        clearScreen()
        tool_name = "subfinder"
        command = "{} -d {} -silent".format(tool_name, self.target)
        print(colored("[+] Running {0} on {1}".format(tool_name, self.target), "green"))
        try:
            process = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            output, error = process.communicate()
            if output:
                print(colored(output), "green")
            if error:
                sys.stderr.write(colored(error), "red")
            with open(f"{tool_name}.txt", "a") as file:
                file.write(output)
        except subprocess.CalledProcessError as e:
            print(f"Command failed with return code {e.returncode}")
            sys.exit()
        except KeyboardInterrupt:
            sys.stderr.write("[!] Pressed CTRL+C")
            sleep(0.5)
            sys.stderr.write("[!] Exiting...")
            sys.exit()

    def assetfinder(self):
        sleep(1)
        clearScreen()
        tool_name = "assetfinder"
        command = "{} -subs-only {}".format(tool_name, self.target)
        print(colored("[+] Running {0} on {1}".format(tool_name, self.target), "green"))
        try:
            process = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            output, error = process.communicate()
            if output:
                print(colored(output), "green")
            if error:
                sys.stderr.write(colored(error), "red")
            with open(f"{tool_name}.txt", "a") as file:
                file.write(output)
        except subprocess.CalledProcessError as e:
            print(f"Command failed with return code {e.returncode}")
            sys.exit()
        except KeyboardInterrupt:
            sys.stderr.write("[!] Pressed CTRL+C")
            sleep(0.5)
            sys.stderr.write("[!] Exiting...")
            sys.exit()

    def asnmap(self):
        sleep(1)
        clearScreen()
        tool_name = "asnmap"
        command = "{0} -d {1} -silent | tlsx -san -silent".format(
            tool_name, self.target
        )
        print(colored("[+] Running {0} on {1}".format(tool_name, self.target), "green"))
        try:
            process = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            output, error = process.communicate()
            if output:
                print(colored(output), "green")
            if error:
                sys.stderr.write(colored(error), "red")
            with open(f"{tool_name}.txt", "a") as file:
                file.write(output)
        except subprocess.CalledProcessError as e:
            print(f"Command failed with return code {e.returncode}")
            sys.exit()
        except KeyboardInterrupt:
            sys.stderr.write("[!] Pressed CTRL+C")
            sleep(0.5)
            sys.stderr.write("[!] Exiting...")
            sys.exit()

    def amass(self):
        sleep(1)
        clearScreen()
        tool_name = "amass"

        # amass passive
        try:
            print(
                colored(
                    "[+] Running {0} Passive on {1}".format(
                        tool_name.capitalize(), self.target
                    ),
                    "green",
                )
            )
            amass_passive_command = (
                "{0} enum -passive -d {1} -timeout 60 -silent".format(
                    tool_name, self.target
                )
            )
            process = subprocess.Popen(
                amass_passive_command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            output, error = process.communicate()
            if output:
                print(colored(output), "green")
            if error:
                sys.stderr.write(colored(error), "red")
            with open(f"{tool_name}_passive.txt", "a") as file:
                file.write(output)
        except subprocess.CalledProcessError as e:
            print(f"Command failed with return code {e.returncode}")
            sys.exit()
        except KeyboardInterrupt:
            sys.stderr.write("[!] Pressed CTRL+C")
            sleep(0.5)
            sys.stderr.write("[!] Exiting...")
            sys.exit()

        # amass active
        try:
            print(
                colored(
                    "[+] Running {0} Active on {1}".format(
                        tool_name.capitalize(), self.target
                    ),
                    "green",
                )
            )
            amass_active_command = "{0} enum -active -d {1} -timeout 60 -config ~/.config/amass/datasources.yaml -silent".format(
                tool_name, self.target
            )
            process = subprocess.Popen(
                amass_passive_command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            output, error = process.communicate()
            if output:
                print(colored(output), "green")
            if error:
                sys.stderr.write(colored(error), "red")
            with open(f"{tool_name}_active.txt", "a") as file:
                file.write(output)
        except subprocess.CalledProcessError as e:
            print(f"Command failed with return code {e.returncode}")
            sys.exit()
        except KeyboardInterrupt:
            sys.stderr.write("[!] Pressed CTRL+C")
            sleep(0.5)
            sys.stderr.write("[!] Exiting...")
            sys.exit()

        # getting only domains from amsass
        try:
            print(
                colored(
                    "[+] Getting only Domains from Amass Passive and Amass Active",
                    "green",
                )
            )
            amass_output_command = "cat amass_passive.txt amass_active.txt | grep -oE '[\.a-zA-Z0-9-]+\.tesla.com' | tee -a amass.txt"
            process = subprocess.Popen(
                amass_output_command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            output, error = process.communicate()
            if output:
                print(colored(output), "green")
            if error:
                sys.stderr.write(colored(error), "red")
            with open(f"{tool_name}.txt", "a") as file:
                file.write(output)
        except subprocess.CalledProcessError as e:
            print(f"Command failed with return code {e.returncode}")
            sys.exit()
        except KeyboardInterrupt:
            sys.stderr.write("[!] Pressed CTRL+C")
            sleep(0.5)
            sys.stderr.write("[!] Exiting...")
            sys.exit()

    def chaos(self):
        sleep(1)
        clearScreen()
        tool_name = "chaos"
        command = "{0} -d {1} -key {2}".format(tool_name, self.target, chaos_key)
        print(colored("[+] Running {0} on {1}".format(tool_name, self.target), "green"))
        try:
            process = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            output, error = process.communicate()
            if output:
                print(colored(output), "green")
            if error:
                sys.stderr.write(colored(error), "red")
            with open(f"{tool_name}.txt", "a") as file:
                file.write(output)
        except subprocess.CalledProcessError as e:
            print(f"Command failed with return code {e.returncode}")
            sys.exit()
        except KeyboardInterrupt:
            sys.stderr.write("[!] Pressed CTRL+C")
            sleep(0.5)
            sys.stderr.write("[!] Exiting...")
            sys.exit()

    def findomain(self):
        sleep(1)
        clearScreen()
        tool_name = "findomain"
        command = "{0} --target {1} --quiet".format(tool_name, self.target)
        print(colored("[+] Running {0} on {1}".format(tool_name, self.target), "green"))
        try:
            process = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            output, error = process.communicate()
            if output:
                print(colored(output), "green")
            if error:
                sys.stderr.write(colored(error), "red")
            with open(f"{tool_name}.txt", "a") as file:
                file.write(output)
        except subprocess.CalledProcessError as e:
            print(f"Command failed with return code {e.returncode}")
            sys.exit()
        except KeyboardInterrupt:
            sys.stderr.write("[!] Pressed CTRL+C")
            sleep(0.5)
            sys.stderr.write("[!] Exiting...")
            sys.exit()

    def vita(self):
        sleep(1)
        clearScreen()
        tool_name = "vita"
        command = "{0} -d {1}".format(tool_name, self.target)
        print(colored("[+] Running {0} on {1}".format(tool_name, self.target), "green"))
        try:
            process = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            output, error = process.communicate()
            if output:
                print(colored(output), "green")
            if error:
                sys.stderr.write(colored(error), "red")
            with open(f"{tool_name}.txt", "a") as file:
                file.write(output)
        except subprocess.CalledProcessError as e:
            print(f"Command failed with return code {e.returncode}")
            sys.exit()
        except KeyboardInterrupt:
            sys.stderr.write("[!] Pressed CTRL+C")
            sleep(0.5)
            sys.stderr.write("[!] Exiting...")
            sys.exit()

    def subcat(self):
        sleep(1)
        clearScreen()
        tool_name = "subcat"
        print("coming soon.")

    def rapiddns(self):
        sleep(1)
        clearScreen()
        tool_name = "rapiddns"
        command = 'curl -s "https://rapiddns.io/subdomain/{0}?full=1" | grep -oE "[\.a-zA-Z0-9-]+\.{0} | sort -u'.format(
            self.target
        )
        print(colored("[+] Running {0} on {1}".format(tool_name, self.target), "green"))
        try:
            process = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            output, error = process.communicate()
            if output:
                print(colored(output), "green")
            if error:
                sys.stderr.write(colored(error), "red")
            with open(f"{tool_name}.txt", "a") as file:
                file.write(output)
        except subprocess.CalledProcessError as e:
            print(f"Command failed with return code {e.returncode}")
            sys.exit()
        except KeyboardInterrupt:
            sys.stderr.write("[!] Pressed CTRL+C")
            sleep(0.5)
            sys.stderr.write("[!] Exiting...")
            sys.exit()

    def crtsh(self):
        sleep(1)
        clearScreen()
        tool_name = "crtsh"
        command = "curl -s \"https://crt.sh/?q=%25.{}&group=none&output=json\" | jq .[].common_name | sed -e 's/\"$//' -e 's/^\"//'".format(
            self.target
        )
        print(colored("[+] Running {0} on {1}".format(tool_name, self.target), "green"))
        try:
            process = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            output, error = process.communicate()
            if output:
                print(colored(output), "green")
            if error:
                sys.stderr.write(colored(error), "red")
            with open(f"{tool_name}.txt", "a") as file:
                file.write(output)
        except subprocess.CalledProcessError as e:
            print(f"Command failed with return code {e.returncode}")
            sys.exit()
        except KeyboardInterrupt:
            sys.stderr.write("[!] Pressed CTRL+C")
            sleep(0.5)
            sys.stderr.write("[!] Exiting...")
            sys.exit()

    def jldc(self):
        sleep(1)
        clearScreen()
        tool_name = "jldc"
        command = 'curl -s https://jldc.me/anubis/subdomains/{0} | jq -r ".[]"'.format(
            self.target
        )
        print(colored("[+] Running {0} on {1}".format(tool_name, self.target), "green"))
        try:
            process = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            output, error = process.communicate()
            if output:
                print(colored(output), "green")
            if error:
                sys.stderr.write(colored(error), "red")
            with open(f"{tool_name}.txt", "a") as file:
                file.write(output)
        except subprocess.CalledProcessError as e:
            print(f"Command failed with return code {e.returncode}")
            sys.exit()
        except KeyboardInterrupt:
            sys.stderr.write("[!] Pressed CTRL+C")
            sleep(0.5)
            sys.stderr.write("[!] Exiting...")
            sys.exit()

    # change here

    def allModules(self):
        sleep(1)
        self.subfinder()
        self.assetfinder()


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
        elif mode == "asnmap":
            p1.asnmap()
        elif mode == "amass":
            p1.amass()
        elif mode == "chaos":
            p1.chaos()
        elif mode == "findomain":
            p1.findomain()
        elif mode == "vita":
            p1.vita()
        elif mode == "subcat":
            p1.subcat()
        elif mode == "rapiddns":
            p1.rapiddns()
        elif mode == "crtsh":
            p1.crtsh()
        elif mode == "jldc":
            p1.jldc()
        # change here
        elif mode == "all":
            p1.allModules()


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
    clearScreen()
    if createDirectory("SubDomains"):
        main()
