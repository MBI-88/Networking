"""
@autor: MBI
Description: Script for Front-end development
"""
#=== Packs ===#
from tkinter import ttk,messagebox,Menu,scrolledtext
import tkinter as tk
from Backend import NetworkBackend
import os,time
from threading import Thread

#=== Class ===#

class Tooltip():
    def __init__(self, widget, tip_text=None):
        self.widget = widget
        self.tip_text = tip_text
        widget.bind("<Enter>", self.mouse_enter)
        widget.bind("<Leave>", self.mouse_leave)
      
    def mouse_enter(self,_event):
        self.show_tooltip()

    def mouse_leave(self,_event):
        self.hide_tooltip()

    def show_tooltip(self):
        if self.tip_text:
            x_left = self.widget.winfo_rootx()
            y_top = self.widget.winfo_rooty() - 15
            self.tip_window = tk.Toplevel(self.widget)
            self.tip_window.overrideredirect(True)
            self.tip_window.geometry("+%d+%d" % (x_left, y_top))
            label = tk.Label(self.tip_window, text=self.tip_text, justify=tk.LEFT, background="#FFFFe0",
                             relief=tk.SOLID,
                             borderwidth=1, font=("tahoma", "8", "normal"))
            label.pack(ipadx=1)

    def hide_tooltip(self):
        if self.tip_window:
            self.tip_window.destroy()

class NetworkingFrontEnd():
    def __init__(self) -> None:
        self.window = tk.Tk()
        self.window.title('Networking')
        self.window.iconbitmap('adaware.ico')
        self.window.geometry('700x600')
        self.window.resizable(False,False)
        self.net = NetworkBackend()
        self.pathSave = "C:\\Users\\"+os.getlogin()+'\\Documents\\'

        self.createWidget()
    
    def createWidget(self) -> None:
        listInterface: list[str] = self.net.listIface
        
        menu_bar = Menu(master=self.window)
        self.window.config(menu=menu_bar)
        file_menu = Menu(menu_bar,tearoff=0)
        file_menu.add_command(label='About',command=self.credict)
        file_menu.add_command(label='Information',command=self.info)
        menu_bar.add_cascade(label='Help',menu=file_menu)

        tabcontrol = ttk.Notebook(master=self.window)
        tab1 = tk.Frame(master=tabcontrol,background='lightblue')
        tabcontrol.add(tab1,text='Scanner')
        tab2 = tk.Frame(master=tabcontrol,background='lightblue')
        tabcontrol.add(tab2,text='Sniffer')
        tab3 = tk.Frame(master=tabcontrol,background='lightblue')
        tabcontrol.add(tab3,text='Telnet')
        tab4 = tk.Frame(master=tabcontrol,background='lightblue')
        tabcontrol.add(tab4,text='Arp Spoofing')
        tab5 = tk.Frame(master=tabcontrol,background='lightblue')
        tabcontrol.add(tab5,text='DoS')
        tabcontrol.pack(expand=True,fill='both')
        
        #====== Tab 1 Scanner ======#

        #==== Sub 1 ====#

        sub1 = tk.LabelFrame(master=tab1,text='',bg='lightyellow',borderwidth=8)
        sub1.grid(column=0,row=0,sticky='N',padx=10,pady=6)
        

        ttk.Label(master=sub1,text='Scan network',background='lightyellow').grid(column=0,row=0,sticky='WE',padx=8,pady=4)
        self.netAddress = tk.StringVar() 
        netAddressEntery = tk.Entry(master=sub1,textvariable=self.netAddress,width=25)
        netAddressEntery.grid(column=0,row=1,sticky='WE',padx=8,pady=4)

        ttk.Label(master=sub1,text='Select commands',background='lightyellow').grid(column=0,row=2,sticky='WE',padx=8,pady=4)
        self.commandScan = tk.StringVar()
        commandScanEntry = tk.Entry(master=sub1,textvariable=self.commandScan,width=25)
        commandScanEntry.grid(column=0,row=3,sticky='WE',padx=8,pady=4)

        Tooltip(commandScanEntry,'Go to info to see commands information')
        
        self.StartScan = tk.Button(master=sub1,text='Run',command=self.startscan,width=10,bg='lightgreen',fg='black')
        self.StartScan.grid(column=1,row=3,sticky='WE',padx=8,pady=4)

    
        #==== Sub 2 ====#

        sub2 = tk.LabelFrame(master=tab1,text='',bg='lightyellow',borderwidth=8)
        sub2.grid(column=0,row=1,sticky='W',padx=10,pady=6)

        self.scrollScan = scrolledtext.ScrolledText(master=sub2,width=78,height=15,wrap=tk.WORD)
        self.scrollScan.grid(column=0,row=0,sticky='WE',padx=8,pady=4,columnspan=2)
        

        #==== Sub 3 ====#

        sub3 = tk.LabelFrame(master=tab1,text='',bg='lightyellow',borderwidth=8,font=5)
        sub3.grid(column=0,row=2,sticky='W',padx=10,pady=6)

        self.SaveScan = tk.Button(master=sub3,text='Save',command=self.savescan,width=10,bg='lightblue',fg='black')
        self.SaveScan.grid(column=0,row=0,sticky='WE',padx=8,pady=4)

        self.ClearScan = tk.Button(master=sub3,text='Clear',command=self.clearscan,width=10,bg='lightblue',fg='black')
        self.ClearScan.grid(column=1,row=0,sticky='WE',padx=8,pady=4)

        #====== Tab 2 Sniffer ======#

        #==== Sub 4 ====#

        sub4 = tk.LabelFrame(master=tab2,text='',bg='lightyellow',borderwidth=8)
        sub4.grid(column=0,row=0,sticky='N',padx=10,pady=6)

        ttk.Label(master=sub4,text='Select interface',background='lightyellow').grid(column=0,row=0,sticky='WE',padx=8,pady=4)
        self.interfaceSniff = tk.StringVar()
        interfaceSniffEntry = ttk.Combobox(master=sub4,textvariable=self.interfaceSniff,value=listInterface,state='readonly')
        interfaceSniffEntry.grid(column=0,row=1,sticky='WE',padx=8,pady=4)   

        ttk.Label(master=sub4,text='Select filter',background='lightyellow').grid(column=0,row=2,sticky='WE',padx=8,pady=4)
        self.filterSniff = tk.StringVar()
        filterSniffEntry = tk.Entry(master=sub4,textvariable=self.filterSniff,width=20)
        filterSniffEntry.grid(column=0,row=3,sticky='WE',padx=8,pady=4)

        Tooltip(filterSniffEntry,'Go to info to see filters information')

        self.StartSniff = tk.Button(master=sub4,text='Run',command=self.startsniff,width=10,bg='lightgreen',fg='black')
        self.StartSniff.grid(column=2,row=4,sticky='WE',padx=8,pady=4)

        self.StopSniff = tk.Button(master=sub4,text='Stop',command=self.stopsniff,width=10,bg='lightgreen',fg='black')
        self.StopSniff.grid(column=2,row=5,sticky='WE',padx=8,pady=4)

        #==== Sub 5 ====#

        sub5 = tk.LabelFrame(master=tab2,text='',bg='lightyellow',borderwidth=8)
        sub5.grid(column=0,row=1,sticky='WE',padx=10,pady=6)

        self.scrollSniff = scrolledtext.ScrolledText(master=sub5,width=78,height=15,wrap=tk.WORD)
        self.scrollSniff.grid(column=0,row=0,sticky='WE',padx=8,pady=4,columnspan=2)

        #==== Sub 6 ====#

        sub6 = tk.LabelFrame(master=tab2,text='',bg='lightyellow',borderwidth=8)
        sub6.grid(column=0,row=2,sticky='W',padx=10,pady=6)

        self.SaveSniff = tk.Button(master=sub6,text='Save',command=self.savesniff,width=10,bg='lightblue',fg='black')
        self.SaveSniff.grid(column=0,row=0,sticky='WE',padx=8,pady=4)
        self.ClearSniff = tk.Button(master=sub6,text='Clear',command=self.clearsniff,width=10,bg='lightblue',fg='black')
        self.ClearSniff.grid(column=1,row=0,sticky='WE',padx=8,pady=4)


        #====== Tab 3 Telnet ======#

        #==== Sub 7 ====#

        sub7 = tk.LabelFrame(master=tab3,text='',bg='lightyellow',borderwidth=8)
        sub7.grid(column=0,row=0,sticky='N',padx=10,pady=6)
        

        ttk.Label(master=sub7,text='Ip target',background='lightyellow').grid(column=0,row=0,sticky='WE',padx=8,pady=4)
        self.targetTelnet = tk.StringVar()
        targetTelnetEntry = tk.Entry(master=sub7,textvariable=self.targetTelnet,width=35)
        targetTelnetEntry.grid(column=0,row=1,sticky='WE',padx=8,pady=4)

        ttk.Label(master=sub7,text='Send command',background='lightyellow').grid(column=0,row=2,sticky='WE',padx=8,pady=4)
        self.sedTelnetCommand = tk.StringVar()
        sendTelnetCommandEntry = tk.Entry(master=sub7,textvariable=self.sedTelnetCommand,width=35)
        sendTelnetCommandEntry.grid(column=0,row=3,sticky='WE',padx=8,pady=4)
        sendTelnetCommandEntry.focus_set()
        sendTelnetCommandEntry.bind("<Return>",func=self.sendtelnet)
        Tooltip(sendTelnetCommandEntry,'Press Enter to send')

        ttk.Label(master=sub7,text='Select port',background='lightyellow').grid(column=1,row=0,sticky='WE',padx=8,pady=4)
        self.telnetPort = tk.StringVar()
        telnetPortEntry = tk.Entry(master=sub7,textvariable=self.telnetPort,width=3)
        telnetPortEntry.grid(column=1,row=1,sticky='WE',padx=8,pady=4)

        self.connectTelnet = tk.Button(master=sub7,text='Connect...',command=self.connecttelnet,bg='lightgreen',fg='black',width=10)
        self.connectTelnet.grid(column=2,row=1,sticky='WE',padx=8,pady=4)
        
        #==== Sub 8 ====#
        sub8 = tk.LabelFrame(master=tab3,text='',bg='lightyellow',borderwidth=8)
        sub8.grid(column=0,row=1,sticky='WE',padx=10,pady=6)

        self.scrollTelnet = scrolledtext.ScrolledText(master=sub8,width=78,height=15,wrap=tk.WORD)
        self.scrollTelnet.grid(column=0,row=0,sticky='WE',padx=8,pady=4,columnspan=2)

        #==== Sub 9 ===#
        sub9 = tk.LabelFrame(master=tab3,text='',bg='lightyellow',borderwidth=8)
        sub9.grid(column=0,row=2,sticky='W',padx=10,pady=6)

        self.Savetelnet = tk.Button(master=sub9,text='Save',command=self.savetelnet,width=10,bg='lightblue',fg='black')
        self.Savetelnet.grid(column=0,row=0,sticky='WE',padx=8,pady=4)
        self.Cleartelnet = tk.Button(master=sub9,text='Clear',command=self.cleartelnet,width=10,bg='lightblue',fg='black')
        self.Cleartelnet.grid(column=1,row=0,sticky='WE',padx=8,pady=4)


        #====== Tab 4 Arp Spoofing ======#

        #==== Sub 10 ====#

        sub10 = tk.LabelFrame(master=tab4,text='',bg='lightyellow',borderwidth=8)
        sub10.grid(column=0,row=0,sticky='N',padx=10,pady=6)

        ttk.Label(master=sub10,text='Select interface',background='lightyellow').grid(column=0,row=0,sticky='WE',padx=8,pady=4)
        self.ArpInterface = tk.StringVar()
        ArpInterfaceEntry = ttk.Combobox(master=sub10,textvariable=self.ArpInterface,value=listInterface,state='readonly')
        ArpInterfaceEntry.grid(column=0,row=1,sticky='WE',padx=8,pady=4)

        ttk.Label(master=sub10,text=' Ip gatway',background='lightyellow').grid(column=0,row=2,sticky='WE',padx=8,pady=4)
        self.ArpGatway = tk.StringVar()
        ArpGatwayEntry = tk.Entry(master=sub10,textvariable=self.ArpGatway)
        ArpGatwayEntry.grid(column=0,row=3,sticky='WE',padx=8,pady=4)

        ttk.Label(master=sub10,text='Ip target',background='lightyellow').grid(column=0,row=4,sticky='WE',padx=8,pady=4)
        self.ArpTarget = tk.StringVar()
        ArpTargetEntry = tk.Entry(master=sub10,textvariable=self.ArpTarget)
        ArpTargetEntry.grid(column=0,row=5,sticky='WE',padx=8,pady=4)

        self.StartArp = tk.Button(master=sub10,text='Run',command=self.startarp,bg='lightgreen',fg='black',width=10)
        self.StartArp.grid(column=1,row=4,sticky='WE',padx=8,pady=4)
        self.StopArp = tk.Button(master=sub10,text='Stop',command=self.stoparp,bg='lightgreen',fg='black',width=10)
        self.StopArp.grid(column=1,row=5,sticky='WE',padx=8,pady=4)

        #==== Sub 11 ====#

        sub11 =  tk.LabelFrame(master=tab4,text='',bg='lightyellow',borderwidth=8)
        sub11.grid(column=0,row=1,sticky='WE',padx=10,pady=6)

        self.scrollArp = scrolledtext.ScrolledText(master=sub11,width=78,height=10,wrap=tk.WORD)
        self.scrollArp.grid(column=0,row=0,sticky='WE',padx=8,pady=4,columnspan=2)

        #==== Sub 12 ====#
        sub12 =  tk.LabelFrame(master=tab4,text='',bg='lightyellow',borderwidth=8)
        sub12.grid(column=0,row=2,sticky='W',padx=10,pady=6)

        self.ClearArp = tk.Button(master=sub12,text='Clear',command=self.cleararp,bg='lightblue',fg='black',width=10)
        self.ClearArp.grid(column=0,row=0,sticky='WE',padx=8,pady=4)


        #====== Tab 5 DoS ======#

        #==== Sub 13 ====#
        
        sub13 = tk.LabelFrame(master=tab5,text='',bg='lightyellow',borderwidth=8)
        sub13.grid(column=0,row=0,sticky='N',padx=10,pady=6)

        ttk.Label(master=sub13,text='Ip target',background='lightyellow').grid(column=0,row=0,sticky='WE',padx=8,pady=4)
        self.DosIptarget = tk.StringVar()
        DosIptargetEntry = tk.Entry(master=sub13,textvariable=self.DosIptarget,width=26)
        DosIptargetEntry.grid(column=0,row=1,sticky='WE',padx=8,pady=4)

        ttk.Label(master=sub13,text='Interface to send',background='lightyellow').grid(column=0,row=2,sticky='WE',padx=8,pady=4)
        self.Dosiface = tk.StringVar()
        DosifaceEntry = ttk.Combobox(master=sub13,textvariable=self.Dosiface,value=listInterface,state='readonly')
        DosifaceEntry.grid(column=0,row=3,sticky='WE',padx=8,pady=4)

        ttk.Label(master=sub13,text='Lan source',background='lightyellow').grid(column=0,row=4,sticky='WE',padx=8,pady=4)
        self.Doslan = tk.StringVar()
        DoslanEntry = tk.Entry(master=sub13,textvariable=self.Doslan,width=10)
        DoslanEntry.grid(column=0,row=5,sticky='WE',padx=8,pady=4)

        ttk.Label(master=sub13,text='Select port',background='lightyellow').grid(column=1,row=0,sticky='WE',padx=8,pady=4)
        self.DosPortTarget = tk.StringVar()
        DosPortTargetEntry = tk.Entry(master=sub13,textvariable=self.DosPortTarget,width=10)
        DosPortTargetEntry.grid(column=1,row=1,sticky='WE',padx=8,pady=4)

        self.StartDos = tk.Button(master=sub13,text='Run',command=self.startdos,bg='lightgreen',fg='black').grid(column=1,row=5,sticky='WE',padx=8,pady=4)
        self.StopDos = tk.Button(master=sub13,text='Stop',command=self.stopdos,bg='lightgreen',fg='black').grid(column=1,row=6,sticky='WE',padx=8,pady=4)

        #==== Sub 14 ====#

        sub14 = tk.LabelFrame(master=tab5,text='',bg='lightyellow',borderwidth=8)
        sub14.grid(column=0,row=1,sticky='WE',padx=10,pady=6)

        self.scrollDos = scrolledtext.ScrolledText(master=sub14,width=78,height=10,wrap=tk.WORD)
        self.scrollDos.grid(column=0,row=0,sticky='WE',padx=8,pady=4,columnspan=2)

        #==== Sub 15 ====#

        sub15 = tk.LabelFrame(master=tab5,text='',background='lightyellow',borderwidth=8)
        sub15.grid(column=0,row=2,sticky='W',padx=10,pady=6)

        self.ClearDos = tk.Button(master=sub15,text='Clear',command=self.cleardos,bg='lightblue',fg='black',width=10).grid(column=0,row=0,sticky='WE',padx=8,pady=4)



    #==== Commands ====#

    def info(self):
        return messagebox.showinfo('',message="""
        Aplication for test,attack and sniff network
        
        Scanning Commands:
            TARGET SPECIFICATION:
            Can pass hostnames, IP addresses, networks, etc.
            Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
            -iL <inputfilename>: Input from list of hosts/networks
            -iR <num hosts>: Choose random targets
            --exclude <host1[,host2][,host3],...>: Exclude hosts/networks
            --excludefile <exclude_file>: Exclude list from file

            HOST DISCOVERY:
            -sL: List Scan - simply list targets to scan
            -sn: Ping Scan - disable port scan
            -Pn: Treat all hosts as online -- skip host discovery
            -PS/PA/PU/PY[portlist]: TCP SYN/ACK, UDP or SCTP discovery to given ports
            -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes
            -PO[protocol list]: IP Protocol Ping
            -n/-R: Never do DNS resolution/Always resolve [default: sometimes]
            --dns-servers <serv1[,serv2],...>: Specify custom DNS servers
            --system-dns: Use OS's DNS resolver
            --traceroute: Trace hop path to each host

            SCAN TECHNIQUES:
            -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
            -sU: UDP Scan
            -sN/sF/sX: TCP Null, FIN, and Xmas scans
            --scanflags <flags>: Customize TCP scan flags
            -sI <zombie host[:probeport]>: Idle scan
            -sY/sZ: SCTP INIT/COOKIE-ECHO scans
            -sO: IP protocol scan
            -b <FTP relay host>: FTP bounce scan

            PORT SPECIFICATION AND SCAN ORDER:
            -p <port ranges>: Only scan specified ports
            Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9
            --exclude-ports <port ranges>: Exclude the specified ports from scanning
            -F: Fast mode - Scan fewer ports than the default scan
            -r: Scan ports consecutively - don't randomize
            --top-ports <number>: Scan <number> most common ports
            --port-ratio <ratio>: Scan ports more common than <ratio>

            SERVICE/VERSION DETECTION:
            -sV: Probe open ports to determine service/version info
            --version-intensity <level>: Set from 0 (light) to 9 (try all probes)
            --version-light: Limit to most likely probes (intensity 2)
            --version-all: Try every single probe (intensity 9)
            --version-trace: Show detailed version scan activity (for debugging)

            OS DETECTION:
            -O: Enable OS detection
            --osscan-limit: Limit OS detection to promising targets
            --osscan-guess: Guess OS more aggressively

            MISC:
            -6: Enable IPv6 scanning
            -A: Enable OS detection, version detection, script scanning, and traceroute.

        Sniff filters:
        tcp and (port 25 or port 110),    
        icmp and host 66.35.250.151

        """)

    def credict(self):
        return messagebox.showinfo('', message="""
        Copyright ©
        Maked: 20/09/2021
        Autor: MBI
        Lincense: Open source
        Contact: maikel8807@gmail.com
        Version: 1.0.0
        Language: Python 3.9.6
        Right recerved
        """)

    #==== Scan Commands ====#
    def startscan(self) -> None: 
        def start(host:str,command:str) -> None:
            try:
                result = self.net.networkScan(host,command)
            except:
                messagebox.showwarning('Warning',message='OS Scan is unreliable without a port scan.  You need to use a scan type along with it, such as -sS, -sT, -sF, etc instead of -sn')
            self.scrollScan.insert(tk.INSERT, str(result)+'\n')
        try:
            thread = Thread(target=start,args=(self.netAddress.get(),self.commandScan.get()),name='Thread-Scan',daemon=True)
            thread.start()
        except:
            messagebox.showerror(title='Error',message='Scannig Network error')
    
    def savescan(self) -> None:
        if (self.scrollScan.get('1.0',tk.END).split('\n')[0] == ''):
            messagebox.showwarning('Warning',message='You need to run a command')
        else:
            with open(self.pathSave+'Net_Scannig.txt',mode='a') as f:
                f.write(self.scrollScan.get('1.0',tk.END))
            f.close()
            messagebox.showinfo('Info',message='Saved Scannig in your Documnets')

    def clearscan(self) -> None:
        self.scrollScan.delete('1.0',tk.END)
            
    #==== Sniff Commands ====#

    def showScrollSniff(self,*args) -> None:
        result = None
        while (self.flag):
            result = str(self.net.package)
            if (result != "deque([], maxlen=1)"):
                result = result.split('[',maxsplit=1)[1]
                result = result.split('], max')[0]
                self.scrollSniff.insert(tk.INSERT, result+'\n'+'\n')
                self.net.package.pop()

            

    def startsniff(self) -> None:
        def start(iface:str,filter:str='') -> None:
            try:
                self.net.networkSniff(iface=iface,filter=filter)
            except:
                messagebox.showerror('Error','Command error')
        try:
            self.flag = True
            self.net.sniff = True
            self.threadsniff = Thread(target=start,
            args=(self.interfaceSniff.get(),self.filterSniff.get()),daemon=True,name='Thread-Sniff')
            self.threadsniff.start()
            showScroll = Thread(target=self.showScrollSniff,args=(None,),daemon=True,name='Thread-ShorScroll')
            showScroll.start()
        except:
            messagebox.showerror(title='Error',message='Sniff network error')

        
    def stopsniff(self) -> None:
        if self.net.sniff is not None:
           self.net.sniff = False
           time.sleep(1.5)
           if (not self.threadsniff.is_alive()): 
               self.scrollSniff.insert(tk.INSERT, '[*] Stop Sniff\n')
        
        self.flag = False
        

    
    def savesniff(self) -> None:
        if (self.scrollSniff.get('1.0',tk.END).split('\n')[0] == ''):
            messagebox.showwarning('Warning',message='You need to run a command')
        else:
            with open(self.pathSave+'Net_Sniff.txt',mode='a') as f:
                f.write(self.scrollSniff.get('1.0',tk.END))
            f.close()
            messagebox.showinfo('Info',message='Saved Sniff in your Documnets')
    
    def clearsniff(self) -> None:
        self.scrollSniff.delete('1.0',tk.END)

    #==== Telnet Commands ====#

    def connecttelnet(self) -> None:
        def start(*args) -> None:
            try:
                recived = self.net.networkTelnetConnect(self.targetTelnet.get(),self.telnetPort.get())
                self.scrollTelnet.insert(tk.INSERT,recived + '\n')
            except : messagebox.showerror('Error',message='Error connecting to {}'.format(self.targetTelnet.get()))
        
        thread = Thread(target=start,args=(None,),daemon=True,name='Thread-ConnectTelnet')
        thread.start()
    
    def sendtelnet(self,_event) -> None:
        def start(cmd:str) -> None:
            try:
                recived = self.net.networkTelnetSend(cmd)
                self.scrollTelnet.insert(tk.INSERT,recived + '\n')
                self.sedTelnetCommand.set('')
            except : messagebox.showerror('Error',message='Error sintaxis commands')
        
        try:
            thread = Thread(target=start,args=(self.sedTelnetCommand.get(),),daemon=True,name='Thread-Telnet')
            thread.start()
        except: messagebox.showerror('Error',message='Can not send comands')


    def savetelnet(self) -> None:
        if (self.scrollTelnet.get('1.0',tk.END).split('\n')[0] == ''):
            messagebox.showwarning('Warning',message='You need to run a command')
        else:
            with open(self.pathSave+'Net_Telnet.txt',mode='a') as f:
                f.write(self.scrollTelnet.get('1.0',tk.END))
            f.close()
            messagebox.showinfo('Info',message='Saved Telnet in your Documnets')
    
    def cleartelnet(self) -> None:
        self.scrollTelnet.delete('1.0',tk.END)
        
    #==== Arp Spoofing ====#
    
    def startarp(self) -> None:
        def start(iface:str,targetIp:str,gatewayIp:str) -> None:
            try:
                self.net.networkArpSpoofer(iface,targetIp,gatewayIp)
            except: messagebox.showerror(title='Error',message='Failed to generate Arp Spoofing')
        try:
            self.net.arp = True
            self.threadarp = Thread(target=start,args=(self.ArpInterface.get(),self.ArpTarget.get(),self.ArpGatway.get()),name='Thread-Arp',daemon=True)
            self.threadarp.start()
            if (self.threadarp.is_alive()):
                self.scrollArp.insert(tk.INSERT,"[*] Run Arp Spoofing... \nIpTarget: {} \nGatewayTarget: {}".format(self.ArpTarget.get(),self.ArpGatway.get())+'\n')
        except: messagebox.showerror(title='Error',message='Error to run Arp Spoofing')
    
    def stoparp(self) -> None:
        self.net.arp = False
        time.sleep(1.5)
        self.net.networkArpSpooferRestore(self.ArpTarget.get(),self.ArpGatway.get())
        if (not self.threadarp.is_alive()):
            self.scrollArp.insert(tk.INSERT,"[*] Finished Arp Spoofing\n")
        
    
    def cleararp(self) -> None:
        self.scrollArp.delete('1.0',tk.END)
    
    #==== Dos ====#

    def startdos(self) -> None:
        information = "[*] Runing DoS\nAttacker: {} ---> Victima: Ip:{} Port:{}\n".format(self.Doslan.get(),self.DosIptarget.get(),self.DosPortTarget.get())
        def start(ipTarget:str,portTarget:int,lanSource:str,iface:str) -> None:
            try:
                self.net.networkDos(ipTarget,portTarget,lanSource,iface)
            except : messagebox.showerror('Error',message='Error in the  DoS\'variables!')
        try:
            self.net.dos = True
            self.threaddos = Thread(target=start,args=(self.DosIptarget.get(),int(self.DosPortTarget.get()),self.Doslan.get(),self.Dosiface.get()),daemon=True,name='Thread-DoS')
            self.threaddos.start()
            if (self.threaddos.is_alive()):
                self.scrollDos.insert(tk.INSERT,information)
        except: messagebox.showerror(title='Error',message="Can\'t run the DoS!")
    
    def stopdos(self) -> None:
        self.net.dos = False
        time.sleep(1.5)
        if (not self.threaddos.is_alive()):
            self.scrollDos.insert(tk.INSERT,'[*] Stop Dos\n')
        
    
    def cleardos(self) -> None:
        self.scrollDos.delete('1.0',tk.END)


    
#==== Main ====#

if __name__ == '__main__':
    window = NetworkingFrontEnd()
    window.window.mainloop()






