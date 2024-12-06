from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter.ttk import Treeview
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
import threading
import time
import subprocess
import platform
import os
from tkinter import messagebox
from ttkthemes import ThemedTk
from PIL import Image, ImageTk
import logging

event = threading.Event()
ps = []

def timestamp2time(time_stamp):
    delta_ms = str(time_stamp - int(time_stamp))
    time_temp = time.localtime(time_stamp)
    my_time = time.strftime("%Y-%m-%d %H:%M:%S", time_temp)
    my_time += delta_ms[1:8]
    return my_time

def get_readable_interfaces():
    interfaces = []

    if platform.system() == "Windows":
        command = "netsh interface show interface"
        result = subprocess.run(command, capture_output=True, text=True)
        output = result.stdout

        for line in output.splitlines():
            if "已启用" in line or "Connected" in line:
                parts = line.split()
                if len(parts) > 0:
                    interfaces.append(parts[-1])

    else:
        command = "ip link show"
        result = subprocess.run(command, capture_output=True, text=True)
        output = result.stdout

        for line in output.splitlines():
            if line and not line.startswith(" "):
                name = line.split(":")[1].strip()
                interfaces.append(name)

    return interfaces

class GUI:
    def __init__(self):
        self.root = ThemedTk(theme="arc")
        self.root.title('网络嗅探器')
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        # 设置窗口尺寸为接近全屏但保留标题栏和关闭按钮
        self.root.geometry(f"{screen_width - 50}x{screen_height - 50}+0+0")

        # 设置图标
        icon_path = os.path.join(os.getcwd(), 'icon.ico')
        if os.path.exists(icon_path):
            self.root.iconbitmap(icon_path)
        # 添加背景标签
        self.canvas = Canvas(self.root)
        self.canvas.place(x=0, y=0, relwidth=1, relheight=1)
        self.bg_label = Label(self.canvas)
        self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        self.canvas.create_window(0, 0, window=self.bg_label, anchor='nw')
        self.root.bind('<Configure>', self.resize_background)

        # 设置背景图片
        self.bg_image_path = os.path.join(os.getcwd(), 'background.png')
        if os.path.exists(self.bg_image_path):
            img = Image.open(self.bg_image_path)
            resized_img = img.resize((self.root.winfo_width(), self.root.winfo_height()), Image.LANCZOS)
            self.bg_image = ImageTk.PhotoImage(resized_img)
            self.bg_label = Label(self.root, image=self.bg_image)
            self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)

        self.create_interface()
        self.create_packet_display_area()
        self.create_detail_area()
        self.create_hex_display_area()
        self.create_menu()

        # 设置窗口大小调整时的行为
        self.root.grid_rowconfigure(3, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

    logging.basicConfig(filename='sniffer.log', level=logging.INFO, format='%(asctime)s - %(message)s')

    def resize_background(self, event):
        if self.bg_image_path and os.path.exists(self.bg_image_path):
            new_width = event.width
            new_height = event.height

            if hasattr(self, 'last_width') and hasattr(self, 'last_height'):
                if new_width == self.last_width and new_height == self.last_height:
                    return

            self.update_background_image()

            self.last_width = new_width
            self.last_height = new_height


    def select_background(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.bg_image_path = file_path
            print(f"Selected background image path: {self.bg_image_path}")
            self.update_background_image()
        else:
            messagebox.showwarning("警告", "未选择任何文件")

    def update_background_image(self):
        try:
            img = Image.open(self.bg_image_path)
            current_width = self.root.winfo_width()
            current_height = self.root.winfo_height()
            resized_img = img.resize((current_width, current_height), Image.LANCZOS)
            self.bg_image = ImageTk.PhotoImage(resized_img)
            self.bg_label.config(image=self.bg_image)
            self.bg_label.image = self.bg_image  # 保持对 PhotoImage 的引用
        except Exception as e:
            messagebox.showerror("错误", f"无法加载背景图片: {str(e)}")

    def create_interface(self):
        style = ttk.Style()
        style.configure("Treeview", background="white", foreground="black", rowheight=25, fieldbackground="white")
        style.map('Treeview', background=[('selected', 'blue')])

        self.interfaces = get_readable_interfaces()
        self.interfaces.insert(0, "所有网卡")

        # 第一行：网卡选择标签和下拉框
        self.label1 = Label(self.root, text="请选择网卡", font=("黑体", 12), fg="black")
        self.label1.grid(row=0, column=0, padx=(300,15), pady=15, sticky='w')
        self.combobox = ttk.Combobox(
            master=self.root,
            height=10,
            width=50,
            state='readonly',
            cursor='arrow',
            font=("黑体", 12),
            values=self.interfaces
        )
        self.combobox.grid(row=0, column=1, padx=10, pady=10, sticky='w')
        self.combobox.current(0)

        # 第二行：过滤条件标签和输入框
        self.label2 = Label(self.root, text="请输入 BPF 过滤条件", font=("黑体", 12), fg="black")
        self.label2.grid(row=1, column=0, padx=(300,15), sticky='w')
        self.entry = Entry(self.root, width=50, font=("黑体", 12))
        self.entry.grid(row=1, column=1, padx=15, sticky='w')

        # 第三行：过滤模板下拉框
        self.filter_templates = [
            "无过滤条件",
            "ip",
            "arp",
            "tcp",
            "udp",
            "src host 192.168.1.1",
            "dst host 192.168.1.2",
            "host 192.168.1.1",
            "tcp port 80",
            "udp port 53",
            "port 22",
            "tcp and (src port 80 or dst port 80)",
            "ip and (src host 192.168.1.1 or dst host 192.168.1.2)",
            "icmp",
            "ether src 00:11:22:33:44:55",
            "vlan 10"
        ]
        self.template_combobox = ttk.Combobox(
            master=self.root,
            height=10,
            width=50,
            state='readonly',
            cursor='arrow',
            font=("黑体", 12),
            values=self.filter_templates
        )
        self.template_combobox.grid(row=2, column=1, padx=10, pady=10, sticky='w')
        self.template_combobox.bind("<<ComboboxSelected>>", self.on_template_select)
        self.template_combobox.current(0)

        # 创建数据包显示区域
        self.create_packet_display_area()

    def create_packet_display_area(self):
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

        self.packet_tree.bind("<Double-1>", self.callback)

        # 设置数据包展示区的颜色
        style = ttk.Style()
        style.configure("Packet.Treeview", background="white", foreground="black", rowheight=25, fieldbackground="white")
        style.map('Packet.Treeview', background=[('selected', 'blue')])
        self.packet_tree.configure(style="Packet.Treeview")

    def create_detail_area(self):
        self.detail_frame = ttk.LabelFrame(self.root, text="详细信息", padding=(5, 5))

        self.frame_var = IntVar(value=1)
        self.ethernet_var = IntVar(value=1)
        self.ip_var = IntVar(value=1)
        self.tcp_var = IntVar(value=1)
        self.http_var = IntVar(value=1)

        style = ttk.Style()
        style.configure('Detail.Treeview', background='white', foreground='black', rowheight=25,
                        fieldbackground='white')
        self.detail_frame.configure(style='Detail.Treeview')

        self.frame_check = ttk.Checkbutton(self.detail_frame, text="Frame: 物理层的数据帧概况", variable=self.frame_var,
                                           command=lambda: self.toggle_frame(self.frame_var, self.detail_tree),
                                           style='My.TCheckbutton')
        self.ethernet_check = ttk.Checkbutton(self.detail_frame, text="Ethernet II: 数据链路层以太网帧头部信息",
                                              variable=self.ethernet_var,
                                              command=lambda: self.toggle_frame(self.ethernet_var, self.detail_tree),
                                              style='My.TCheckbutton')
        self.ip_check = ttk.Checkbutton(self.detail_frame, text="Internet Protocol Version 4: 互联网层 IP 包头部信息",
                                        variable=self.ip_var,
                                        command=lambda: self.toggle_frame(self.ip_var, self.detail_tree),
                                        style='My.TCheckbutton')
        self.tcp_check = ttk.Checkbutton(self.detail_frame,
                                         text="Transmission Control Protocol: 传输层 TCP 的数据段头部信息",
                                         variable=self.tcp_var,
                                         command=lambda: self.toggle_frame(self.tcp_var, self.detail_tree),
                                         style='My.TCheckbutton')
        self.http_check = ttk.Checkbutton(self.detail_frame,
                                          text="Hypertext Transfer Protocol: 应用层的信息，此处是 HTTP 协议",
                                          variable=self.http_var,
                                          command=lambda: self.toggle_frame(self.http_var, self.detail_tree),
                                          style='My.TCheckbutton')

        self.frame_check.grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.ethernet_check.grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.ip_check.grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.tcp_check.grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.http_check.grid(row=4, column=0, sticky="w", padx=5, pady=5)

        self.detail_frame.grid(row=5, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

    def create_hex_display_area(self):
        self.textbox1 = Text(self.root, width=100, height=10, font=("黑体", 12))
        self.textbox1.grid(row=6, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

    def create_menu(self):
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

        # 添加设置菜单
        self.menuSettings = Menu(self.mainmenu)
        self.mainmenu.add_cascade(label="设置", menu=self.menuSettings)
        self.menuSettings.add_command(label="修改背景", command=self.select_background)

        self.root.config(menu=self.mainmenu)
    def toggle_frame(self, var, tree):
        selected_item = self.packet_tree.selection()
        if selected_item:
            pos = int(self.packet_tree.item(selected_item[0], "values")[0]) - 1
            pkt = ps[pos]
            if var.get():
                layer_name = ""
                if var == self.frame_var:
                    layer_name = "Frame: 物理层的数据帧概况"
                elif var == self.ethernet_var:
                    layer_name = "Ethernet II: 数据链路层以太网帧头部信息"
                elif var == self.ip_var:
                    layer_name = "Internet Protocol Version 4: 互联网层 IP 包头部信息"
                elif var == self.tcp_var:
                    layer_name = "Transmission Control Protocol: 传输层 TCP 的数据段头部信息"
                elif var == self.http_var:
                    layer_name = "Hypertext Transfer Protocol: 应用层的信息，此处是 HTTP 协议"

                info = self.get_detailed_info_for_layer(layer_name, pkt)
                for item in tree.get_children():
                    tree.delete(item)
                tree.insert("", END, values=(layer_name, info))
            else:
                for item in tree.get_children():
                    tree.delete(item)
    def get_detailed_info_for_layer(self, layer_name, pkt):
        if layer_name == "Frame: 物理层的数据帧概况":
            frame_info = pkt.show(dump=True)
            return f"Frame Info:\n{frame_info.replace(',', '\n')}"
        elif layer_name == "Ethernet II: 数据链路层以太网帧头部信息":
            eth = pkt.getlayer(Ether)
            if eth:
                return f"源 MAC: {eth.src}\n目标 MAC: {eth.dst}"
            return "没有以太网层"
        elif layer_name == "Internet Protocol Version 4: 互联网层 IP 包头部信息":
            ip = pkt.getlayer(IP)
            if ip:
                return f"源 IP: {ip.src}\n目标 IP: {ip.dst}\n协议: {ip.proto}"
            return "没有 IP 层"
        elif layer_name == "Transmission Control Protocol: 传输层 TCP 的数据段头部信息":
            tcp = pkt.getlayer(TCP)
            if tcp:
                return f"源端口: {tcp.sport}\n目标端口: {tcp.dport}\n序列号: {tcp.seq}"
            return "没有 TCP 层"
        elif layer_name == "Hypertext Transfer Protocol: 应用层的信息，此处是 HTTP 协议":
            http = pkt.getlayer(Raw)
            if http and b'HTTP' in http.load:
                return http.load.decode('utf-8', errors='ignore')
            return "没有 HTTP 层"
        return "没有详细的信息"

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
        if not file_path:
            return
        try:
            with open(file_path, "rb") as fd:
                reader = PcapReader(fd)
                for v in reader:
                    self.packet_display(v)
                    ps.append(v)
        except Exception as e:
            messagebox.showerror("错误", f"无法打开文件: {str(e)}")

    def m_event(self):
        while True:
            event.wait()
            try:
                packet = sniff(filter=self.filter, count=1, iface=self.iface, timeout=1)
                for p in packet:
                    self.packet_display(p)
                    ps.append(p)
            except Exception as e:
                messagebox.showerror("错误", f"抓包过程中发生错误: {str(e)}")
                break

    def packet_display(self, p):
        packet_time = timestamp2time(p.time)
        src = p[Ether].src if Ether in p else ""
        dst = p[Ether].dst if Ether in p else ""
        length = len(p)
        info = p.summary()

        t = p[Ether].type if Ether in p else 0
        protols_Ether = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x88cc: 'LLDP', 0x891D: 'TTE'}
        proto = protols_Ether.get(t, 'Not clear')

        # 数据包都会有第三层
        if proto == 'IPv4':
            protos_ip = {1: 'ICMP', 2: 'IGMP', 4: 'IP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 41: 'IPv6', 50: 'ESP', 89: 'OSPF'}
            src = p[IP].src if IP in p else src
            dst = p[IP].dst if IP in p else dst
            t = p[IP].proto if IP in p else 0
            proto = protos_ip.get(t, proto)

        # 数据包可能有第四层
        if TCP in p:
            protos_tcp = {80: 'Http', 443: 'Https', 23: 'Telnet', 21: 'Ftp', 20: 'ftp_data', 22: 'SSH', 25: 'SMTP'}
            sport = p[TCP].sport
            dport = p[TCP].dport
            proto = protos_tcp.get(sport, proto)
            proto = protos_tcp.get(dport, proto)

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
            'IGMP': '#69eb5c',
            'Ethernet': '#95e52c',
            'Not clear': 'white'
        }

        bg_color = color_map.get(proto, 'white')

        self.packet_tree.insert("", END, values=(len(self.packet_tree.get_children()) + 1, packet_time, src, dst, proto, length, info), tags=(bg_color,))
        self.packet_tree.tag_configure(bg_color, background=bg_color)

    def start(self):
        self.iface = self.combobox.get()
        self.filter = self.entry.get()
        if self.iface == "所有网卡":
            self.iface = None  # 如果选择“所有网卡”，则 iface 设置为 None
        elif not self.iface:
            messagebox.showwarning("警告", "请选择一个网卡")
            return
        print(f"Using filter: {self.filter}")  # 打印过滤条件
        event.set()
        T1 = threading.Thread(target=self.m_event, daemon=True)
        T1.start()

    def pause(self):
        event.clear()

    def cont(self):
        event.set()

    def file_save(self):
        file_path = filedialog.asksaveasfilename(title=u'保存文件', defaultextension=".pcap")
        if not file_path:
            return
        try:
            wrpcap(file_path, ps)
        except Exception as e:
            messagebox.showerror("错误", f"保存文件时发生错误: {e}")

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
        print(f"Packet summary: {pkt.summary()}")
        print(f"Layers: {', '.join([p.name for p in pkt])}")

        self.textbox1.delete("1.0", END)
        self.textbox1.insert(END, hexdump(pkt, dump=True))

        # 清空详细信息树视图
        for i in self.detail_tree.get_children():
            self.detail_tree.delete(i)

        # 填充详细信息
        self.populate_detail_tree(pkt, '')

    def populate_detail_tree(self, pkt):
        # 清空现有内容
        for i in self.detail_tree.get_children():
            self.detail_tree.delete(i)

        for layer in pkt:
            layer_info = layer.show(dump=True)  # 获取层信息
            self.detail_tree.insert("", END, values=(layer_info,))  # 直接插入详细信息
if __name__ == '__main__':
    a = GUI()
    a.root.mainloop()