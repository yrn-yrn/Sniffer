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
ps = []  # ps为当前数据包展示区的包建立一个全局列表

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
        # 获取所有可用接口
        self.interfaces = get_if_list()
        self.interface_map = {iface: iface for iface in self.interfaces}  # 创建接口名称映射

        # 添加标签控件
        self.label1 = Label(self.root, text="请选择网卡", font=("黑体", 12), fg="black", bg="white")
        self.label1.grid(row=0, column=0, padx=10, pady=10)

        # 添加选择框
        self.combobox = ttk.Combobox(
            master=self.root,
            height=10,
            width=20,
            state='readonly',  # 设置为只读，防止用户输入无效名称
            cursor='arrow',
            font=('', 12),
            values=self.interfaces
        )
        self.combobox.grid(row=0, column=1, padx=10, pady=10)

        # 添加标签控件
        self.label2 = Label(self.root, text="请输入BPF过滤条件", font=("黑体", 12), fg="black", bg="white")
        self.label2.grid(row=1, column=0, padx=10, pady=10)

        # 添加输入框
        self.entry = Entry(self.root, width=50, font=("黑体", 12))
        self.entry.grid(row=1, column=1, padx=10, pady=10)

        # 添加过滤条件模板下拉菜单
        self.filter_templates = [
            "无过滤条件",  # 提示项，对应空字符串
            "ip",  # 捕获所有IP数据包
            "arp",  # 捕获所有ARP数据包
            "tcp",  # 捕获所有TCP数据包
            "udp",  # 捕获所有UDP数据包
            "src host 192.168.1.1",  # 捕获源地址为192.168.1.1的所有数据包
            "dst host 192.168.1.2",  # 捕获目标地址为192.168.1.2的所有数据包
            "host 192.168.1.1",  # 捕获源地址或目标地址为192.168.1.1的所有数据包
            "tcp port 80",  # 捕获所有TCP端口为80的数据包（通常是HTTP流量）
            "udp port 53",  # 捕获所有UDP端口为53的数据包（通常是DNS流量）
            "port 22",  # 捕获所有端口为22的数据包（通常是SSH流量）
            "tcp and (src port 80 or dst port 80)",  # 捕获所有源端口或目标端口为80的TCP数据包
            "ip and (src host 192.168.1.1 or dst host 192.168.1.2)",  # 捕获所有源地址为192.168.1.1或目标地址为192.168.1.2的IP数据包
            "icmp",  # 捕获所有ICMP数据包
            "ether src 00:11:22:33:44:55",  # 捕获源MAC地址为00:11:22:33:44:55的所有以太网帧
            "vlan 10"  # 捕获所有VLAN ID为10的数据包
        ]

        self.template_combobox = ttk.Combobox(
            master=self.root,
            height=10,
            width=50,
            state='readonly',  # 设置为只读，防止用户输入无效名称
            cursor='arrow',
            font=('', 12),
            values=self.filter_templates
        )
        self.template_combobox.grid(row=2, column=1, padx=10, pady=10)
        self.template_combobox.bind("<<ComboboxSelected>>", self.on_template_select)
        self.template_combobox.current(0)  # 默认选中提示项

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
        self.packet_tree.grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        self.hbar = ttk.Scrollbar(self.root, orient=HORIZONTAL, command=self.packet_tree.xview)
        self.hbar.grid(row=4, column=0, columnspan=2, sticky="ew")
        self.packet_tree.configure(xscrollcommand=self.hbar.set)

        # 添加十六进制展示区文本框
        self.textbox1 = Text(self.root, width=100, height=10, font=("黑体", 12))
        self.textbox1.grid(row=5, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        # 使窗口大小调整时，控件也跟随调整
        self.root.grid_rowconfigure(3, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

        # 设置 Treeview 样式
        style = ttk.Style()
        style.configure("Treeview", background="white", foreground="black", rowheight=25, fieldbackground="white")
        style.map('Treeview', background=[('selected', 'blue')])

        # 绑定双击事件以显示数据包详情
        self.packet_tree.bind("<Double-1>", self.callback)

    def on_template_select(self, event):
        selected_template = self.template_combobox.get()
        if selected_template == "无过滤条件":
            self.entry.delete(0, END)
            self.entry.insert(0, "")
        else:
            self.entry.delete(0, END)
            self.entry.insert(0, selected_template)

    def file_open(self):
        file_path = filedialog.askopenfilename()
        with open(file_path, "rb") as fd:
            reader = PcapReader(fd)
            for v in reader:
                self.packet_display(v)
                ps.append(v)

    def m_event(self):
        '''抓包事件，一直循环'''
        while True:
            packet = sniff(filter=self.filter, count=1, iface=self.iface)
            event.wait()
            for p in packet:
                self.packet_display(p)
                ps.append(p)

    def packet_display(self, p):
        packet_time = timestamp2time(p.time)
        src = p[Ether].src
        dst = p[Ether].dst
        length = len(p)
        info = p.summary()

        t = p[Ether].type
        protols_Ether = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x88cc: 'LLDP', 0x891D: 'TTE'}
        if t in protols_Ether:
            proto = protols_Ether[t]
        else:
            proto = 'Not clear'

        # 数据包都会有第三层
        if proto == 'IPv4':
            protos_ip = {1: 'ICMP', 2: 'IGMP', 4: 'IP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 41: 'IPv6', 50: 'ESP', 89: 'OSPF'}
            src = p[IP].src
            dst = p[IP].dst
            t = p[IP].proto
            if t in protos_ip:
                proto = protos_ip[t]

        # 数据包可能有第四层
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

        # 打印捕获的数据包信息
        print(f"Captured packet: {packet_time}, {src} -> {dst}, {length}, {info}")

        # 设置不同协议类型的背景颜色
        color_map = {
            'TCP': '#ff9a72',
            'Http': '#ffd3c2',
            'Https': '#ffcbb7',
            'Telnet': '#f794c5',
            'Ftp': '#ea97dd',
            'ftp_data': '#d89df2',
            'SSH': '#c2a6ff',
            'SMTP': '#aab0ff',

            'UDP': '#79beff',
            'DNS': '#20cdeb',

            'IPv4': '#feef80',
            'IPv6': '#fff4a7',
            'ICMP': '#e0b047',

            'ARP': '#0bf080',
            'IGMP':'#69eb5c',
            'Ethernet': '#95e52c',
            'Not clear': 'white'
        }

        bg_color = color_map.get(proto, 'white')

        self.packet_tree.insert("", END, values=(len(self.packet_tree.get_children()) + 1, packet_time, src, dst, proto, length, info), tags=(bg_color,))
        self.packet_tree.tag_configure(bg_color, background=bg_color)

    def start(self):
        self.iface = self.combobox.get()
        self.filter = self.entry.get()
        print(f"Using filter: {self.filter}")  # 打印过滤条件
        event.set()
        T1 = threading.Thread(target=self.m_event, daemon=True)
        T1.start()

    def pause(self):
        event.clear()

    def cont(self):
        event.set()

    def file_save(self):
        file_path = filedialog.asksaveasfilename(title=u'保存文件')
        wrpcap(file_path, ps)

    def clear_data(self):
        x = self.packet_tree.get_children()
        for item in x:
            self.packet_tree.delete(item)
        self.textbox1.delete("1.0", END)
        ps.clear()

    def callback(self, event):
        item = self.packet_tree.selection()[0]
        pos = int(self.packet_tree.item(item, "values")[0])
        pkt = ps[pos - 1]
        self.textbox1.delete("1.0", END)
        self.textbox1.insert(END, hexdump(pkt, dump=True))


if __name__ == '__main__':
    a = GUI()
    a.root.mainloop()
