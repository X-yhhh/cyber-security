#!/usr/bin/env python3
"""P1 Npcap 有界实采，只采指定 IPv4 双端的两个 TCP 高端口；不注入报文。"""
import argparse
import ctypes as c
import ipaddress
import json
import os
from pathlib import Path
import struct
import time


class Device(c.Structure):pass
Device._fields_=[('next',c.POINTER(Device)),('name',c.c_char_p),('description',c.c_char_p),('addresses',c.c_void_p),('flags',c.c_uint)]
class Timeval(c.Structure):_fields_=[('sec',c.c_long),('usec',c.c_long)]
class Header(c.Structure):_fields_=[('ts',Timeval),('caplen',c.c_uint),('length',c.c_uint)]
class BPF(c.Structure):_fields_=[('length',c.c_uint),('insns',c.c_void_p)]
# pcap_stat 在 Windows 另有 ps_capt / ps_sent / ps_netdrop，必须分配全部六个 uint。
class Stats(c.Structure):_fields_=[('received',c.c_uint),('dropped',c.c_uint),('interfaceDropped',c.c_uint),('captured',c.c_uint),('sent',c.c_uint),('networkDropped',c.c_uint)]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--list',action='store_true');p.add_argument('--device')
    p.add_argument('--local');p.add_argument('--peer');p.add_argument('--port',type=int,default=55161)
    p.add_argument('--seconds',type=int,default=90);p.add_argument('--output',type=Path)
    a=p.parse_args()
    if os.name!='nt':raise ValueError('仅供 Windows Npcap 验证')
    dll=Path(os.environ['WINDIR'])/'System32'/'Npcap'
    dll_dir=os.add_dll_directory(str(dll))
    lib=c.CDLL(str(dll/'wpcap.dll'))
    lib.pcap_lib_version.restype=c.c_char_p
    lib.pcap_findalldevs.argtypes=[c.POINTER(c.POINTER(Device)),c.c_char_p]
    lib.pcap_freealldevs.argtypes=[c.POINTER(Device)]
    err=c.create_string_buffer(256);first=c.POINTER(Device)()
    if lib.pcap_findalldevs(c.byref(first),err)!=0:raise RuntimeError(err.value.decode())
    devices=[];cur=first
    while cur:
        devices.append({'name':cur.contents.name.decode(),'description':(cur.contents.description or b'').decode()});cur=cur.contents.next
    lib.pcap_freealldevs(first)
    if a.list:
        print(json.dumps({'version':lib.pcap_lib_version().decode(),'devices':devices}));return
    if a.device not in [d['name'] for d in devices]:raise ValueError('未知接口')
    for value in [a.local,a.peer]:
        ip=ipaddress.IPv4Address(value)
        if not(ip.is_private or ip in ipaddress.ip_network('100.64.0.0/10')) or ip.is_loopback:raise ValueError('只允许私网/覆盖网')
    if a.local==a.peer or not 49152<=a.port<=65533 or not 1<=a.seconds<=180 or a.output is None or a.output.exists():raise ValueError('范围或输出无效')
    lib.pcap_open_live.argtypes=[c.c_char_p,c.c_int,c.c_int,c.c_int,c.c_char_p];lib.pcap_open_live.restype=c.c_void_p
    lib.pcap_compile.argtypes=[c.c_void_p,c.POINTER(BPF),c.c_char_p,c.c_int,c.c_uint]
    lib.pcap_setfilter.argtypes=[c.c_void_p,c.POINTER(BPF)]
    lib.pcap_freecode.argtypes=[c.POINTER(BPF)]
    lib.pcap_setnonblock.argtypes=[c.c_void_p,c.c_int,c.c_char_p]
    lib.pcap_datalink.argtypes=[c.c_void_p];lib.pcap_datalink.restype=c.c_int
    lib.pcap_next_ex.argtypes=[c.c_void_p,c.POINTER(c.POINTER(Header)),c.POINTER(c.POINTER(c.c_ubyte))]
    lib.pcap_close.argtypes=[c.c_void_p]
    lib.pcap_stats.argtypes=[c.c_void_p,c.POINTER(Stats)];lib.pcap_stats.restype=c.c_int
    handle=lib.pcap_open_live(a.device.encode(),256,0,100,err)
    if not handle:raise RuntimeError(err.value.decode())
    count=0;lengths=0
    try:
        expression=f'ip and tcp and host {a.local} and host {a.peer} and (port {a.port} or port {a.port+1})'
        bpf=BPF()
        if lib.pcap_compile(handle,c.byref(bpf),expression.encode(),1,0xffffffff)!=0:raise RuntimeError('过滤器编译失败')
        try:
            if lib.pcap_setfilter(handle,c.byref(bpf))!=0:raise RuntimeError('过滤器应用失败')
        finally:lib.pcap_freecode(c.byref(bpf))
        if lib.pcap_setnonblock(handle,1,err)!=0:raise RuntimeError('非阻塞配置失败')
        link=lib.pcap_datalink(handle);until=time.monotonic()+a.seconds
        header=c.POINTER(Header)();data=c.POINTER(c.c_ubyte)()
        with a.output.open('xb') as f:
            f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,256,link))
            print(json.dumps({'event':'capture_ready','datalink':link,'durationSeconds':a.seconds}),flush=True)
            while time.monotonic()<until:
                result=lib.pcap_next_ex(handle,c.byref(header),c.byref(data))
                if result==0:time.sleep(.01);continue
                if result!=1:raise RuntimeError('实采读取失败')
                h=header.contents
                if h.caplen>256 or h.caplen>h.length:raise RuntimeError('非法捕获长度')
                f.write(struct.pack('<IIII',h.ts.sec,h.ts.usec,h.caplen,h.length));f.write(c.string_at(data,h.caplen));count+=1;lengths+=h.length
            f.flush();os.fsync(f.fileno())
        stats=Stats();stats_ok=lib.pcap_stats(handle,c.byref(stats))==0
        print(json.dumps({'event':'capture_finished','packets':count,'wireBytes':lengths,'datalink':link,'injection':False,
                          'nativeStats':({'received':stats.received,'dropped':stats.dropped,'interfaceDropped':stats.interfaceDropped} if stats_ok else None)}),flush=True)
    finally:lib.pcap_close(handle);dll_dir.close()


if __name__=='__main__':main()
