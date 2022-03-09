import nmap
import os
import sys

# A class for all of our options and their functions
class options:
    
    # Option to run our nmap scan
    def run_portscan(self, ip, port_range):
        
        nm = nmap.PortScanner()
        print("Scanning...")
        nm.scan(ip, port_range)
        
        # Print output in a nice way
        for host in nm.all_hosts():
            print("\nScan Results:")
            print('----------------------------------------------------')
            print('Host : %s (%s)' % (host, nm[host].hostname()))
            print('State : %s' % nm[host].state())
            for proto in nm[host].all_protocols():
                print('----------')
                print('Protocol : %s' % proto)

                lport = sorted(nm[host][proto].keys())
                for port in lport:
                        print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
                print('----------------------------------------------------\n')

    # Option to run netstat
    def run_netstat(self):
        print()
        os.system("netstat -antp")
        print()

    # Option to restart/shutdown the system
    def run_restart(self):
        options = "1) Restart\n"
        options += "2) Shutdown\n"
        options += "3) Back\n"
        print(options)
        answer = input("Select: ")
        if answer == "1":
            os.system("shutdown -P now")
        elif answer == "2":
            os.system("shutdown -r now")
        elif answer == "3":
            return
        else:
            print("Invalid option\n")

# Prompt user to select an option
    def select_option(self):
        answer = input("Select: ")
        if answer == "1":
            ip = input("IP Address to scan: ")
            ports = input("Port range to scan ex:(1-1000): ")
            self.run_portscan(ip, ports)
        
        elif answer == "2":
            self.run_netstat()
        elif answer == "3":
            self.run_restart()
        elif answer == "4":
            print("Goodbye!")
            sys.exit()
        else:
            print("Invalid option\n")

# Print the options for our user
    def show_options(self):
        options = "1) Run a port scan\n"
        options += "2) Run Netstat\n"
        options += "3) Shutdown/Restart\n"
        options += "4) Exit\n"
        print(options)
        self.select_option()

# main loop to show options and select one
def main():
    print("Successful login\n")
    program_options = options()
    while True:
        program_options.show_options()

# Function to check username and password
def check_login(username: str, password: str) -> bool:
    if username == "student" and password == "password":
        return True
    else:
        return False

# Login loop 3 times
def get_login():
    for i in range(1,4):
        username = input("Username: ")
        password = input ("Password: ")
        # Check login, current creds are "student" and "password"
        if check_login(username, password) == True:
            main()
            return
        else:
            print("Wrong Username or Password")
            print(f"Atempt {i}/3")
    print("Failed to login")
    return

# Run main program      
if __name__ == "__main__":
    get_login()