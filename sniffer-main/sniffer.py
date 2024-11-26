from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter.ttk import Treeview
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
import threading
import time

event = threading.Event()
ps=list()   # ps为当前数据包展示区的包建立一个全局列表

def timestamp2time(time_stamp):
    delta_ms = str(time_stamp - int(time_stamp))
    time_temp = time.localtime(time_stamp)
    my_time = time.strftime("%Y-%m-%d %H:%M:%S", time_temp)
    my_time += delta_ms[1:8]
    return my_time


from ttkthemes import ThemedTk

import os


class GUI:
    def __init__(self):
        self.root = ThemedTk(theme="arc")
        self.root.title('网络嗅探器')
        self.root.geometry("800x600+500+150")

        # 设置图标
        icon_path = os.path.join(os.getcwd(), 'icon.ico')
        if os.path.exists(icon_path):
            self.root.iconbitmap(icon_path)

        # 设置背景图片
        bg_image_path = os.path.join(os.getcwd(), 'background.png')
        if os.path.exists(bg_image_path):
            self.bg_image = PhotoImage(file=bg_image_path)
            self.bg_label = Label(self.root, image=self.bg_image)
            self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)

        self.interface()
    def interface(self):
        # 添加标签控件
        self.label1 = Label(self.root, text="请选择网卡", font=("黑体", 12), fg="black", bg="white")
        self.label1.grid(row=0, column=0, padx=10, pady=10)

        # 添加选择框
        values = ['WLAN', '以太网2', '蓝牙网络连接']
        self.combobox = ttk.Combobox(
            master=self.root,
            height=10,
            width=20,
            state='',
            cursor='arrow',
            font=('', 12),
            values=values
        )
        self.combobox.grid(row=0, column=1, padx=10, pady=10)

        # 添加标签控件
        self.label2 = Label(self.root, text="请输入BPF过滤条件", font=("黑体", 12), fg="black", bg="white")
        self.label2.grid(row=1, column=0, padx=10, pady=10)

        # 添加输入框
        self.entry = Entry(self.root, width=50, font=("黑体", 12))
        self.entry.grid(row=1, column=1, padx=10, pady=10)

        # 添加菜单功能
        self.mainmenu = Menu(self.root)
        self.menuFile = Menu(self.mainmenu)
        self.mainmenu.add_cascade(label="文件", menu=self.menuFile)
        self.menuFile.add_command(label="打开", command=self.file_open)
        self.menuFile.add_command(label="保存", command=self.file_save)
        self.menuFile.add_command(label="退出", command=self.root.destroy)

        self.menuEdit = Menu(self.mainmenu)
        self.mainmenu.add_cascade(label="编辑", menu=self.menuEdit)
        self.menuEdit.add_command(label="清空", command=self.clear_data)

        self.menuCap = Menu(self.mainmenu)
        self.mainmenu.add_cascade(label="捕获", menu=self.menuCap)
        self.menuCap.add_command(label="开始", command=self.start)
        self.menuCap.add_command(label="暂停", command=self.pause)
        self.menuCap.add_command(label="继续", command=self.cont)

        self.root.config(menu=self.mainmenu)

        # 添加数据包展示区
        self.packet_tree = Treeview(
            self.root,
            columns=('num', 'packet_time', 'src', 'dst', 'proto', 'length', 'info'),
            show='headings',
            displaycolumns="#all",
            style="Treeview"
        )
        self.packet_tree.heading('num', text="序号", anchor=W)
        self.packet_tree.column('num', width=70, anchor='w')
        self.packet_tree.heading('packet_time', text="时间", anchor=W)
        self.packet_tree.heading('src', text="源IP/MAC", anchor=W)
        self.packet_tree.heading('dst', text="目的IP/MAC", anchor=W)
        self.packet_tree.heading('proto', text="协议", anchor=W)
        self.packet_tree.heading('length', text="长度", anchor=W)
        self.packet_tree.heading('info', text="数据", anchor=W)
        self.packet_tree.column('info', width=400, anchor='w')
        self.packet_tree.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        self.hbar = ttk.Scrollbar(self.root, orient=HORIZONTAL, command=self.packet_tree.xview)
        self.hbar.grid(row=3, column=0, columnspan=2, sticky="ew")
        self.packet_tree.configure(xscrollcommand=self.hbar.set)

        # 添加十六进制展示区文本框
        self.textbox1 = Text(self.root, width=100, height=10, font=("黑体", 12))
        self.textbox1.grid(row=4, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        # 使窗口大小调整时，控件也跟随调整
        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

        # 设置 Treeview 样式
        style = ttk.Style()
        style.configure("Treeview", background="white", foreground="black", rowheight=25, fieldbackground="white")
        style.map('Treeview', background=[('selected', 'blue')])


    def file_open(self):
        file_path = filedialog.askopenfilename()
        fd=open(file_path,"rb")
        reader=PcapReader(fd)
        for v in reader:
            self.packet_display(v)
            ps.append(v)


    def m_event(self):
        '''抓包事件，一直循环'''
        while True:
            packet=sniff(filter=self.filter,count=1,iface=self.iface) 
            event.wait()
            for p in packet:
                self.packet_display(p)
                ps.append(p)


    def packet_display(self,p):
        packet_time= timestamp2time(p.time)
        src = p[Ether].src
        dst = p[Ether].dst
        length = len(p)  
        info = p.summary()

        t = p[Ether].type
        protols_Ether = {0x0800:'IPv4',0x0806:'ARP',0x86dd:'IPv6',0x88cc:'LLDP',0x891D:'TTE'}
        if t in protols_Ether:
            proto = protols_Ether[t]
        else:
            proto = 'Not clear'
      
        #数据包都会有第三层
        if proto == 'IPv4':
            protos_ip = {1: 'ICMP', 2: 'IGMP', 4: 'IP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 41: 'IPv6', 50: 'ESP', 89:'OSPF'}
            src = p[IP].src
            dst = p[IP].dst
            t=p[IP].proto
            if t in protos_ip:
                proto=protos_ip[t]
        
        #数据包可能有第四层
        if TCP in p:
            protos_tcp = {80: 'Http', 443: 'Https', 23: 'Telnet', 21: 'Ftp', 20: 'ftp_data', 22: 'SSH', 25: 'SMTP'}
            sport = p[TCP].sport
            dport = p[TCP].dport
            if sport in protos_tcp:
                proto = protos_tcp[sport]
            elif dport in protos_tcp:
                proto = protos_tcp[dport]
        
        elif UDP in p:
            if p[UDP].sport == 53 or p[UDP].dport == 53:
                proto = 'DNS'

        self.packet_tree.insert("",END,values=(len(self.packet_tree.get_children())+1,packet_time,src,dst,proto,length,info))


    def start(self):
        self.iface=self.combobox.get()
        self.filter=self.entry.get()
        event.set()
        T1 = threading.Thread(target=self.m_event, daemon=True)
        T1.start()


    def pause(self):
        event.clear()


    def cont(self):
        event.set()


    def file_save(self):
        file_path=filedialog.asksaveasfilename(title=u'保存文件')
        wrpcap(file_path, ps) 


    def clear_data(self):
        x=self.packet_tree.get_children()
        for item in x:
            self.packet_tree.delete(item)
        self.textbox1.delete("1.0",END)
        ps.clear()


    def callback(self,event):
        item = self.packet_tree.set(self.packet_tree.focus())
        pos=int(item["num"])
        pkt=ps[pos-1]
        self.textbox1.delete("1.0",END)
        self.textbox1.insert(END, hexdump(pkt, dump=True))


if __name__ == '__main__':
    a = GUI()
    a.root.mainloop()
