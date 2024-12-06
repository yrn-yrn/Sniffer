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
def get_readable_interfaces():
    interfaces = []

    # Windows下使用 'netsh' 命令
    if platform.system() == "Windows":
        command = "netsh interface show interface"
        result = subprocess.run(command, capture_output=True, text=True)
        output = result.stdout

        # 解析输出，确保提取友好的名称
        for line in output.splitlines():
            # 查找包含网络接口名称的行
            if "已启用" in line or "Connected" in line:  # 检查状态
                parts = line.split()
                if len(parts) > 0:
                    interfaces.append(parts[-1])  # 假设最后一个是接口名

    else:
        # 用于Linux或macOS，使用其他命令
        command = "ip link show"
        result = subprocess.run(command, capture_output=True, text=True)
        output = result.stdout

        for line in output.splitlines():
            if line and not line.startswith(" "):
                # 提取接口名
                name = line.split(":")[1].strip()
                interfaces.append(name)

    return interfaces
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

        self.interfaces = get_readable_interfaces()
        self.interfaces.insert(0, "所有网卡")  # 添加“所有网卡”选项

        # 添加标签控件
        self.label1 = Label(self.root, text="请选择网卡", font=("黑体", 12), fg="black", bg="white")
        self.label1.grid(row=0, column=0, padx=15, pady=15, sticky="w")

        # 添加选择框
        self.combobox = ttk.Combobox(
            master=self.root,
            height=10,
            width=30,
            state='readonly',  # 设置为只读，防止用户输入无效名称
            cursor='arrow',
            font=('', 14),
            values=self.interfaces
        )
        self.combobox.grid(row=0, column=1, padx=10, pady=10, sticky='w')
        self.combobox.current(0)  # 默认选中“所有网卡”

        # 添加标签控件
        self.label2 = Label(self.root, text="请输入BPF过滤条件", font=("黑体", 14), fg="black", bg="white")
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

        # 添加可折叠的详细信息框
        self.detail_frame = ttk.LabelFrame(self.root, text="详细信息", padding=(5, 5))
        # 添加详细信息树视图
        self.detail_tree = Treeview(
            self.detail_frame,
            columns=('layer', 'field', 'value'),
            show='headings',
            displaycolumns="#all",
            style="Treeview"
        )
        self.detail_tree.heading('layer', text="层次", anchor=W)
        self.detail_tree.column('layer', width=100, anchor='w')
        self.detail_tree.heading('field', text="字段", anchor=W)
        self.detail_tree.column('field', width=150, anchor='w')
        self.detail_tree.heading('value', text="值", anchor=W)
        self.detail_tree.column('value', width=300, anchor='w')
        self.detail_tree.grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")

        # 添加折叠按钮
        self.frame_var = IntVar(value=1)
        self.ethernet_var = IntVar(value=1)
        self.ip_var = IntVar(value=1)
        self.tcp_var = IntVar(value=1)
        self.http_var = IntVar(value=1)

        self.frame_check = ttk.Checkbutton(self.detail_frame, text="Frame: 物理层的数据帧概况", variable=self.frame_var, command=lambda: self.toggle_frame(self.frame_var, self.frame_label))
        self.frame_check.grid(row=0, column=0, sticky="w", padx=5, pady=5)

        self.ethernet_check = ttk.Checkbutton(self.detail_frame, text="Ethernet II: 数据链路层以太网帧头部信息", variable=self.ethernet_var, command=lambda: self.toggle_frame(self.ethernet_var, self.ethernet_label))
        self.ethernet_check.grid(row=1, column=0, sticky="w", padx=5, pady=5)

        self.ip_check = ttk.Checkbutton(self.detail_frame, text="Internet Protocol Version 4: 互联网层IP包头部信息", variable=self.ip_var, command=lambda: self.toggle_frame(self.ip_var, self.ip_label))
        self.ip_check.grid(row=2, column=0, sticky="w", padx=5, pady=5)

        self.tcp_check = ttk.Checkbutton(self.detail_frame, text="Transmission Control Protocol: 传输层TCP的数据段头部信息", variable=self.tcp_var, command=lambda: self.toggle_frame(self.tcp_var, self.tcp_label))
        self.tcp_check.grid(row=3, column=0, sticky="w", padx=5, pady=5)

        self.http_check = ttk.Checkbutton(self.detail_frame, text="Hypertext Transfer Protocol: 应用层的信息，此处是HTTP协议", variable=self.http_var, command=lambda: self.toggle_frame(self.http_var, self.http_label))
        self.http_check.grid(row=4, column=0, sticky="w", padx=5, pady=5)

        # 初始化标签
        self.frame_label = Label(self.detail_frame, text="", justify=LEFT)
        self.frame_label.grid(row=0, column=1, sticky="w", padx=5, pady=5)

        self.ethernet_label = Label(self.detail_frame, text="", justify=LEFT)
        self.ethernet_label.grid(row=1, column=1, sticky="w", padx=5, pady=5)

        self.ip_label = Label(self.detail_frame, text="", justify=LEFT)
        self.ip_label.grid(row=2, column=1, sticky="w", padx=5, pady=5)

        self.tcp_label = Label(self.detail_frame, text="", justify=LEFT)
        self.tcp_label.grid(row=3, column=1, sticky="w", padx=5, pady=5)

        self.http_label = Label(self.detail_frame, text="", justify=LEFT)
        self.http_label.grid(row=4, column=1, sticky="w", padx=5, pady=5)

        # 添加十六进制展示区文本框
        self.textbox1 = Text(self.root, width=100, height=10, font=("黑体", 12))
        self.textbox1.grid(row=6, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

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
        # 将 detail_frame 添加到主窗口
        self.detail_frame.grid(row=5, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

    def toggle_frame(self, var, label):
        selected_item = self.packet_tree.selection()
        if selected_item:
            pos = int(self.packet_tree.item(selected_item[0], "values")[0])
            pkt = ps[pos - 1]
            if var.get():
                # 获取详细信息并设置到label中
                detailed_info = self.get_detailed_info_for_layer(label.cget("text"), pkt)
                label.config(text=detailed_info)
            else:
                label.config(text="")

    def get_detailed_info_for_layer(self, layer_name, pkt):
        if layer_name == "Frame: 物理层的数据帧概况":
            return f"Frame Info: {pkt.show(dump=True)}"
        elif layer_name == "Ethernet II: 数据链路层以太网帧头部信息":
            eth = pkt.getlayer(Ether)
            if eth:
                return f"Source MAC: {eth.src}\nDestination MAC: {eth.dst}"
            else:
                return "No Ethernet layer found"
        elif layer_name == "Internet Protocol Version 4: 互联网层IP包头部信息":
            ip = pkt.getlayer(IP)
            if ip:
                return f"Source IP: {ip.src}\nDestination IP: {ip.dst}\nProtocol: {ip.proto}"
            else:
                return "No IP layer found"
        elif layer_name == "Transmission Control Protocol: 传输层TCP的数据段头部信息":
            tcp = pkt.getlayer(TCP)
            if tcp:
                return f"Source Port: {tcp.sport}\nDestination Port: {tcp.dport}\nSequence Number: {tcp.seq}"
            else:
                return "No TCP layer found"
        elif layer_name == "Hypertext Transfer Protocol: 应用层的信息":
            http = pkt.getlayer(Raw)
            if http and b'HTTP' in http.load:
                return http.load.decode('utf-8', errors='ignore')
            else:
                return "No HTTP layer found"
        return "No detailed information available"

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
            messagebox.showerror("错误", f"无法打开文件: {e}")

    def m_event(self):
        '''抓包事件，一直循环'''
        while True:
            event.wait()
            try:
                packet = sniff(filter=self.filter, count=1, iface=self.iface, timeout=1)
                for p in packet:
                    self.packet_display(p)
                    ps.append(p)
            except Exception as e:
                messagebox.showerror("错误", f"抓包过程中发生错误: {e}")
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

    def populate_detail_tree(self, pkt, parent_id):
        for layer in pkt:
            layer_name = layer.name
            layer_id = self.detail_tree.insert(parent_id, END, values=(layer_name, '', ''))

            for field in layer.fields_desc:
                field_name = field.name
                field_value = getattr(layer, field_name)
                self.detail_tree.insert(layer_id, END, values=('', field_name, field_value))


if __name__ == '__main__':
    a = GUI()
    a.root.mainloop()