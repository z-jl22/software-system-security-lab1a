import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (Image, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)


ROOT = Path(__file__).resolve().parents[1]
META = json.loads((ROOT / "docs" / "metadata.json").read_text(encoding="utf-8"))
STEM = f"{META['name']}_{META['student_id']}"
OUTPUT = ROOT / "output"
PACKAGE = OUTPUT / f"{STEM}_EX1A"
VERIFY = OUTPUT / "verification"


def build_report(path):
    pdfmetrics.registerFont(TTFont("Chinese", "/System/Library/Fonts/Supplemental/Arial Unicode.ttf"))
    styles = getSampleStyleSheet()
    for name in ("Normal", "Title", "Heading1", "Heading2"):
        styles[name].fontName = "Chinese"
    styles["Normal"].fontSize, styles["Normal"].leading = 10, 16
    styles["Normal"].spaceAfter = 7
    styles["Heading1"].textColor = colors.HexColor("#0f766e")
    styles["Heading1"].fontSize = 19
    styles["Heading2"].fontSize = 12
    styles["Title"].leading = 32
    small = ParagraphStyle("SmallChinese", parent=styles["Normal"], fontSize=8, leading=12)
    story = []

    def paragraph(text, style="Normal"):
        story.append(Paragraph(escape(text).replace("\n", "<br/>"), styles[style]))

    def heading(text):
        paragraph(text, "Heading1")
        story.append(Spacer(1, 4 * mm))

    def table(rows, widths):
        cells = [[Paragraph(escape(str(cell)), small) for cell in row] for row in rows]
        item = Table(cells, colWidths=widths, repeatRows=1, hAlign="LEFT")
        item.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e0f2f1")),
                                  ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                  ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                                  ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                                  ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
        story.append(item)
        story.append(Spacer(1, 5 * mm))

    def screenshot(name, caption):
        image_path = VERIFY / f"{name}.png"
        if image_path.exists():
            story.append(Image(str(image_path), width=160 * mm, height=104.45 * mm))
            story.append(Paragraph(escape(caption), small))
            story.append(Spacer(1, 2 * mm))

    story.append(Spacer(1, 25 * mm))
    paragraph("《软件与系统安全》实验 1A", "Title")
    paragraph("Lantern：带 GUI 的网络嗅探器\n设计与实现", "Title")
    story.append(Spacer(1, 15 * mm))
    paragraph(f"姓名：{META['name']}\n学号：{META['student_id']}\n实验平台：macOS 15.6 / Apple Silicon\n实现：Python + PySide6 + libpcap\n日期：2026 年 11 月 21 日")
    paragraph("Git 仓库：" + (META["repository"] or "待创建并补充实际 URL（个人主页不是仓库地址）"))
    paragraph("文档说明：本报告依据当前实际实现与自动化结果编写。代码、报告和自动化演示由 AI 辅助生成，作者需自行复现、理解核心模块并修订学习总结。未完成的能力明确列出。")
    story.append(PageBreak())
    heading("1. 实验目标与需求分析")
    paragraph("本实验设计带图形界面的网络嗅探器，通过 libpcap 捕获网络报文，并自行解析常见网络层、传输层和应用层协议。NPS 关注捕获真实网络数据；NPA 关注从字节解释协议含义。项目以真实抓包为基础，增加协议过滤、离线 PCAP、详情浏览和 TCP 流追踪。")
    table([["课程要求 / 目标", "实现与验证"],
           ["真实网络嗅探 NPS", "ctypes 直接调用系统 libpcap；lo0 实测 370 包"],
           ["图形交互", "PySide6 网卡选择、实时启停、包列表、字段树、十六进制"],
           ["协议分析 NPA", "Ethernet/VLAN、ARP、IPv4/v6、TCP/UDP、ICMP/v6、DNS、段内 HTTP/1.x、TLS 特征"],
           ["协议过滤", "libpcap BPF 捕获过滤 + 递归下降实现逻辑显示过滤"],
           ["TCP 流追踪（增强）", "双向端点归组、包序列与载荷预览；不声称字节流重组"],
           ["源码、视频、报告", "按课件格式生成源码目录、自动化演示 MP4 与本 PDF"]], [49 * mm, 121 * mm])
    paragraph("技术选型：Python 降低界面与测试实现成本；PySide6 提供桌面模型视图组件；macOS 自带 libpcap，避免依赖 Windows Npcap。核心解析使用 struct 和 ipaddress，不依赖 Wireshark 作为解析后端。")
    paragraph("交付范围：先保证正确性和可复现性。未实施 eBPF/XDP、进程关联、HTTPS 解密与高速链路优化。")
    story.append(PageBreak())
    heading("2. 分层原理与总体架构")
    paragraph("OSI 七层为物理、数据链路、网络、传输、会话、表示、应用。实际 TCP/IP 协议栈通常将上三层归入应用层。libpcap 的可见数据由捕获接口和 DLT 链路类型决定，不能假定每份原始数据都以 Ethernet 头开始。")
    table([["输入或模块", "处理与输出"],
           ["en0 / lo0 + 系统 BPF", "libpcap 获取帧、时间戳、捕获长度、线上长度和 DLT"],
           ["sniffer/pcap.py", "枚举、打开、BPF 编译设置、非阻塞取包、PCAP 文件读写"],
           ["sniffer/parser.py", "链路层 -> 网络层 -> 传输层 -> 应用特征；生成 Packet 与协议树"],
           ["sniffer/filters.py", "not / and / or / 括号以及协议、IP、端口条件"],
           ["sniffer/streams.py", "双向 TCP 端点归组；跟踪 SYN、关闭标志与空闲间隔"],
           ["sniffer/gui.py", "抓包线程 -> 有界队列 -> GUI 定时批量处理 -> 表格/详情/流视图"]], [49 * mm, 121 * mm])
    paragraph("线程设计：CaptureWorker 独占 pcap 句柄；主线程不并发关闭该句柄。非阻塞模式无包时等待 10 ms，停止使用 Event，后台退出时在 finally 关闭句柄。GUI 每 100 ms 取最多 1000 条记录，避免逐包刷新。")
    paragraph("资源限制：会话最多 20000 包或 64 MiB 原始字节，队列最多 4096 条。解析对象与队列另有额外开销。显示过滤不删除包；达到会话上限会自动停止。队列丢弃数不代表系统内核丢包数。")
    paragraph("关于 Thor 思考题：应用层代理观察到的是被代理的应用请求/响应，不必具有原始 TCP 报文的完整可见性。安装受信任根证书使代理在满足客户端信任、无阻碍证书固定等条件下终止 TLS 并读取内容，但不等于获得任意层报文或所有 HTTPS 内容。抓包位置决定可见信息，分析层次由工具实现决定。")
    story.append(PageBreak())
    heading("3. libpcap 抓包与 PCAP 存储")
    paragraph("调用流程：pcap_findalldevs -> pcap_open_live -> pcap_compile / pcap_setfilter -> pcap_setnonblock -> pcap_datalink -> 循环 pcap_next_ex -> pcap_close。pcap_freealldevs 和 pcap_freecode 分别释放列表与 BPF 指令。")
    paragraph("ctypes 映射 pcap_if、timeval、pcap_pkthdr 和 bpf_program。pcap_next_ex 返回 1 时先复制 caplen 字节，防止下次调用复用 libpcap 内部缓冲。返回 0 表示当前无包，负值表示错误或结束。snaplen 设置为 65535；当前实时抓包使用非混杂模式。")
    paragraph("macOS 抓包受 /dev/bpf* 权限保护。普通用户可运行离线 GUI；真实验证只将无 GUI 的 CLI 捕获以管理员授权启动，绑定 lo0 并过滤本机测试端口。未将 BPF 设备修改为全局可读写。若已有官方 ChmodBPF 配置，可在普通用户 GUI 中实时捕获。")
    paragraph("DLT 处理：Ethernet=1（支持 VLAN）、macOS NULL=0、LOOP=108、RAW=12/101 及 IPv4/IPv6 特定 DLT。NULL 地址族兼容主机端序及跨端序文件。未知 DLT 保留字节并提示，不错误套用以太网偏移。")
    paragraph("文件格式：支持经典 PCAP 的大小端和微秒/纳秒时间戳读取，写出小端微秒格式。检查文件头、捕获长度、线上长度和截断记录；拒绝 PCAPNG。一次会话保持统一链路类型，保存包含所有已存包而非仅显示结果。")
    paragraph("CLI 可复现命令：\nsudo /usr/bin/python3 main.py --capture lo0 --filter 'tcp port 8080 or icmp or icmp6' --seconds 15 --output local.pcap\n另开终端运行：.venv/bin/python tools/local_traffic.py\n离线查看：.venv/bin/python main.py --read local.pcap")
    story.append(PageBreak())
    heading("4. 协议解析与错误处理")
    table([["协议", "字段与边界处理"],
           ["Ethernet / VLAN / ARP", "源/目的 MAC、EtherType、VLAN ID；ARP 操作及 IPv4/MAC 地址"],
           ["IPv4", "IHL、总长度、TTL、协议、IP、分片偏移与 MF；含分片时跳过传输层"],
           ["IPv6", "载荷长度、Next Header、Hop Limit、地址；遍历常见扩展头，标识分片"],
           ["TCP", "端口、序列号、确认号、data offset、flags、窗口、段载荷"],
           ["UDP / ICMP(v6)", "UDP 长度、端口和校验和字段；ICMP 类型、代码和常见摘要"],
           ["HTTP/1.x", "检查当前段载荷起始行的方法、版本或响应状态行，不只依赖端口"],
           ["DNS", "53/UDP 上解析头部与首个问题；名称压缩支持与指针循环检测"],
           ["TLS", "记录类型、版本字节、声明长度特征；不解密，不视为完整握手校验"]], [35 * mm, 135 * mm])
    paragraph("解析前先用 need(data, offset, size) 检查可用字节，再解包。IPv4 IHL 和 TCP data offset 均以 4 字节为单位，不能固定按 20 字节计算。使用网络字节序解析协议数值。IP 总长度限制可见载荷范围，避免把 Ethernet 填充解释为应用数据。")
    paragraph("HTTP 的局限：完整请求行必须位于当前 TCP 段开头；报头跨段、重传、乱序或多消息粘连没有通过流重组完整处理。TLS 判断为启发式记录头特征，TLS 1.3 的记录层版本不能作为最终协商版本。未校验所有报文的协议校验和。")
    paragraph("失败行为：未知协议保留原始字节；截断、长度非法和不支持分片等情况在协议树中给出提示，不让普通解析错误终止抓包。自动测试遍历样例的每个截断前缀，并额外输入 1000 份固定随机种子的随机字节。")
    story.append(PageBreak())
    heading("5. 过滤与 TCP 流设计")
    paragraph("捕获过滤使用 libpcap 编译的经典 BPF，例如 tcp port 8080。在报文进入本程序前执行筛选，可减少用户态工作量；HTTP 不能仅用端口可靠识别。显示过滤在 Packet 已解析后执行，因此 http、tcp、ipv4 可以分别匹配同一个 HTTP/TCP/IPv4 包。")
    paragraph("显示表达式语法：expression = conjunction ('or' conjunction)*；conjunction = atom ('and' atom)*；atom 包括 not atom、括号表达式、协议名、[src|dst] host IP、[src|dst] port NUMBER。用递归下降实现，不使用 eval。优先级 not > and > or。输入错误时保留此前生效的过滤器。")
    table([["表达式", "含义"], ["http", "已识别 HTTP 的包"], ["ipv6 and icmp6", "IPv6 中的 ICMPv6"],
           ["(tcp or udp) and not port 53", "TCP/UDP 包，排除任一端口为 53 的报文"],
           ["src host 192.0.2.10 and dst port 8080", "指定源 IP、目的端口"]], [85 * mm, 85 * mm])
    paragraph("TCP 流使用排序后的两端 (IP, port) 作为双向键，以便请求和响应归入同一条流。新初始 SYN、已关闭流的新 SYN 或超过 120 秒空闲可开启新会话；相同序列号的初始 SYN 重传仍归入原流。两端 FIN 或 RST 标记关闭。这只是有限启发式，没有实现完整 TCP 状态机。")
    paragraph("流视图保留捕获顺序、方向、包编号和段载荷，不做 TCP 序列号排序、重传消除、缺口补齐或跨段 HTTP 消息恢复。因此名称为 TCP 流追踪，不把它当作完整可靠字节流重组。")
    story.append(PageBreak())
    heading("6. GUI 与离线功能验证")
    screenshot("02-http-detail", "图 1：真实 GUI 离屏截图。人工样例的非 80 端口 HTTP 请求、协议树及原始字节。")
    screenshot("05-tcp-flow", "图 2：双向 TCP 流，共 8 个数据包；视图明确提示未进行字节流重组。")
    story.append(PageBreak())
    heading("7. 真实抓包与自动测试结果")
    live = json.loads((VERIFY / "live-result.json").read_text(encoding="utf-8")) if (VERIFY / "live-result.json").exists() else None
    if live:
        paragraph(f"真实验证结果 PASS：本程序经管理员授权调用 libpcap，在 macOS lo0 上捕获 {live['packets']} 包。测试服务仅监听 127.0.0.1，动态端口 {live['http_port']}；捕获表达式限制该 TCP 端口及 ICMP。结果保存在 live-loopback.pcap 和 live-result.json，可独立复核。")
        paragraph("最上层互斥分类计数：" + "；".join(f"{name} {count}" for name, count in live["protocols"].items()) + "。HTTP 包同样包含 TCP 层，分类统计和分层过滤的含义不同。")
    else:
        paragraph("尚未取得实时验证结果。离线样例不作为真实抓包成功证据。")
    screenshot("09-live-http", "图 3：本程序真实 lo0 捕获文件的 GUI 回放；HTTP 显示过滤展示实际请求与响应。")
    paragraph("自动化验证：19 项 unittest 通过，包括非标准端口 HTTP、端口误判防护、DNS 压缩与循环、IPv6 扩展头、分片、截断及随机输入、逻辑过滤、双向流、端点复用、PCAP 大小端/纳秒与损坏文件检查。另直接调用真实 libpcap 的 pcap_open_dead、pcap_compile、pcap_offline_filter，验证 BPF 匹配 TCP/8080 并排除 DNS。")
    paragraph("GUI 自动验收：加载 15 包教学样例、点击详情、HTTP 筛选为 2 包、逻辑筛选为 9 包、TCP 流为 8 包、DNS 为 2 包、IPv6 为 1 包、回环样例读取与清空均通过。使用 tcpdump 读取样例并对照 HTTP 请求/响应和 TCP 序列，未执行 Wireshark 图形界面对照。")
    story.append(PageBreak())
    heading("8. 运行复现、限制与总结")
    paragraph("环境：实际运行于 Darwin 24.6.0 / arm64，Python 3.9.6，PySide6 6.10.3，系统 /usr/lib/libpcap.dylib。新环境先 python3 -m venv .venv，再 .venv/bin/python -m pip install -r requirements.txt，最后 .venv/bin/python main.py。无需管理员权限即可加载教学样例或打开 PCAP。")
    paragraph("真实抓包时需 BPF 权限，推荐管理员 CLI 抓包后普通 GUI 分析；实时 GUI 在已授权 BPF 的账户下可使用。自动视频为真实 Qt 窗口操作状态生成的功能演示，含实际抓包文件回放，并非连续桌面录屏，不包含人工口述。")
    paragraph("当前不足：未实现 IP 分片重组、TCP 字节流重组、TLS 解密、进程关联、PCAPNG、完整 DNS 回答解析；没有测量高吞吐性能或内核丢包率。离线 GUI 与 CLI 实时捕获已验证，尚未在已配置 BPF 普通用户权限的 GUI 中进行完整开始/停止实测。")
    paragraph("后续改进：完善 TCP 状态机与方向重组、处理应用消息分帧、增加 pcap_stats、将离线解析移入后台并提升大文件交互性能、加入可复现的吞吐和内存测量。")
    paragraph("方法总结：先用最小 CLI 验证抓包链路，再逐层解析和接入 GUI；对长度、字节序和 DLT 显式检查；将人工样例与真实流量证据区分；把资源上限与不支持能力写入界面和报告。作者个人学习体会应在理解代码并复现后补充。")
    paragraph("提交：源码目录、演示 MP4、本报告按姓名和学号命名，统一 ZIP，不加密。远程仓库链接：" + (META["repository"] or "待补充，提交前必须完成") + "。开发记录应如实保留，不补造历史。")
    paragraph("参考资料", "Heading2")
    paragraph("[1] 刘鹏：《软件与系统安全》实验 1A & 1B 讲解，2026。\n[2] libpcap 官方文档：https://www.tcpdump.org/manpages/pcap.3pcap.html\n[3] BPF 语法：https://www.tcpdump.org/manpages/pcap-filter.7.html\n[4] Qt for Python：https://doc.qt.io/qtforpython-6/\n[5] RFC 791、8200、9293、768、1035、9112。")

    def page_footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Chinese", 8)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(20 * mm, 13 * mm, f"Lantern | {META['name']} {META['student_id']} | 实验 1A")
        canvas.drawRightString(190 * mm, 13 * mm, str(document.page))
        canvas.restoreState()

    document = SimpleDocTemplate(str(path), pagesize=(210 * mm, 297 * mm),
                                 leftMargin=20 * mm, rightMargin=20 * mm,
                                 topMargin=18 * mm, bottomMargin=22 * mm,
                                 title="Lantern 嗅探器设计与实现", author=META["name"])
    document.build(story, onFirstPage=page_footer, onLaterPages=page_footer)


def main():
    PACKAGE.mkdir(parents=True, exist_ok=True)
    source = PACKAGE / f"{STEM}_ex1A_src"
    source.mkdir(exist_ok=True)
    for name in ("sniffer", "tools", "tests", "samples", "docs"):
        shutil.copytree(ROOT / name, source / name, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for name in ("main.py", "launch.command", "requirements.txt", ".gitignore"):
        shutil.copy2(ROOT / name, source / name)
    evidence = source / "evidence"
    evidence.mkdir(exist_ok=True)
    for path in VERIFY.glob("*"):
        if path.is_file() and path.suffix in (".json", ".pcap", ".txt"):
            shutil.copy2(path, evidence / path.name)
    if (ROOT / ".git").exists():
        bundle = source / "development.bundle"
        subprocess.run(["git", "bundle", "create", str(bundle), "--all"], cwd=ROOT, check=True)
    report = PACKAGE / f"{STEM}_ex1A_report.pdf"
    build_report(report)
    video = PACKAGE / f"{STEM}_ex1A_play.mp4"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", "2", "-i",
                    str(VERIFY / "video-frames" / "%04d.png"), "-c:v", "libx264", "-pix_fmt", "yuv420p",
                    "-r", "24", "-movflags", "+faststart", str(video)], check=True)
    archive = OUTPUT / f"{STEM}_EX1A.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(PACKAGE.rglob("*")):
            if path.is_file():
                bundle.write(path, path.relative_to(OUTPUT))
    print(json.dumps({"report": str(report), "video": str(video), "zip": str(archive)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
