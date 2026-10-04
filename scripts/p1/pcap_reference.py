#!/usr/bin/env python3
"""P1 离线头部参考工具，支持 Ethernet / Raw IPv4；不是现场 v5 提取器。

保留容器完整性、抓包截短、乱序和不支持报文的区别。只使用已观察头部，
不重新组装载荷或运行抓包中的内容；快照统计不读截止时间之后的包。
"""
import collections
import hashlib
import math
import struct


def frames(path, audit):
    sha=hashlib.sha256();md5=hashlib.md5()
    def hashed(f,n):
        data=f.read(n);sha.update(data);md5.update(data);return data
    with path.open('rb') as f:
        magic=f.read(4);f.seek(0)
        if magic==b'\x0a\x0d\x0d\x0a':
            yield from pcapng_frames(f,hashed,audit)
            audit.update({'completeContainer':True,'bytes':f.tell(),'sha256':sha.hexdigest(),'md5':md5.hexdigest()})
            return
        head=hashed(f,24)
        formats={b'\xd4\xc3\xb2\xa1':('<',1),b'\xa1\xb2\xc3\xd4':('>',1),
                 b'\x4d\x3c\xb2\xa1':('<',1000),b'\xa1\xb2\x3c\x4d':('>',1000)}
        if len(head)!=24 or head[:4] not in formats:raise ValueError('需要完整经典 PCAP')
        endian,divisor=formats[head[:4]]
        major,minor,_,_,snaplen,link=struct.unpack(endian+'HHIIII',head[4:])
        if (major,minor)!=(2,4) or link not in (1,12,101):raise ValueError('PCAP 版本或链路类型不支持')
        audit.update({'containerFormat':'pcap','datalink':link,'snaplen':snaplen,'frames':0,'snapTruncatedFrames':0,'timestampRegressions':0})
        previous=None
        while True:
            hdr=hashed(f,16)
            if not hdr:break
            if len(hdr)!=16:raise ValueError('PCAP 记录头截断')
            sec,frac,cap,wire=struct.unpack(endian+'IIII',hdr)
            if cap>16*1024*1024 or cap>snaplen or cap>wire or frac>=1000000*divisor:raise ValueError('PCAP 长度或时间不合法')
            data=hashed(f,cap)
            if len(data)!=cap:raise ValueError('PCAP 报文截断')
            ts=sec*1000000+frac//divisor
            audit['frames']+=1;audit['snapTruncatedFrames']+=cap<wire
            audit['timestampRegressions']+=previous is not None and ts<previous
            previous=ts
            yield ts,data,wire,link
        audit.update({'completeContainer':True,'bytes':f.tell(),'sha256':sha.hexdigest(),'md5':md5.hexdigest()})


def pcapng_options(data,endian):
    """检查带四字节对齐的选项；重复时间参数不得静默覆盖。"""
    result={};pos=0
    while pos<len(data):
        if pos+4>len(data):raise ValueError('PCAPNG 选项头截断')
        code,size=struct.unpack_from(endian+'HH',data,pos);pos+=4
        if code==0:
            if size or any(data[pos:]):raise ValueError('PCAPNG 选项终止符不合法')
            return result
        end=pos+((size+3)//4)*4
        if end>len(data):raise ValueError('PCAPNG 选项值截断')
        result.setdefault(code,[]).append(data[pos:pos+size]);pos=end
    return result


def pcapng_frames(f,hashed,audit):
    """读取单 section/单接口 PCAPNG EPB，拒绝混捕获域、无时间包和损坏块。

    保留原件字节及其哈希，时间按接口 tsresol/tsoffset 换算为微秒；
    更细精度无法整除时显式计数，不根据扩展名猜容器或时区。
    """
    endian=None;interface=None;previous=None;section_end=None
    audit.update({'containerFormat':'pcapng','frames':0,'snapTruncatedFrames':0,
                  'timestampRegressions':0,'subMicrosecondTimestamps':0,'blocks':{}})
    while True:
        header=hashed(f,8)
        if not header:break
        if len(header)!=8:raise ValueError('PCAPNG 块头截断')
        section=header[:4]==b'\x0a\x0d\x0d\x0a'
        prefix=b''
        if section:
            if endian is not None:raise ValueError('PCAPNG 多 section 需要独立捕获域审计')
            prefix=hashed(f,4)
            endian={b'\x4d\x3c\x2b\x1a':'<',b'\x1a\x2b\x3c\x4d':'>'}.get(prefix)
            if endian is None:raise ValueError('PCAPNG 字节序标识无效')
        elif endian is None:raise ValueError('PCAPNG 缺 section')
        kind,length=struct.unpack(endian+'II',header)
        if length<12+len(prefix) or length%4 or length>16*1024*1024:
            raise ValueError('PCAPNG 块长度无效')
        tail=hashed(f,length-8-len(prefix))
        if len(tail)!=length-8-len(prefix):raise ValueError('PCAPNG 块截断')
        if struct.unpack(endian+'I',tail[-4:])[0]!=length:raise ValueError('PCAPNG 首尾块长度不一致')
        body=prefix+tail[:-4]
        audit['blocks'][str(kind)]=audit['blocks'].get(str(kind),0)+1
        if section:
            if len(body)<16:raise ValueError('PCAPNG section 截断')
            major,minor,declared=struct.unpack_from(endian+'HHq',body,4)
            if (major,minor)!=(1,0) or declared< -1:raise ValueError('PCAPNG section 版本或长度不支持')
            section_end=None if declared==-1 else f.tell()+declared
            pcapng_options(body[16:],endian)
        elif kind==1:
            if interface is not None:raise ValueError('PCAPNG 多接口需要独立捕获域审计')
            if len(body)<8:raise ValueError('PCAPNG 接口块截断')
            link,reserved,snaplen=struct.unpack_from(endian+'HHI',body)
            if link not in (1,12,101) or reserved:raise ValueError('PCAPNG 接口类型不支持')
            options=pcapng_options(body[8:],endian)
            resolution=options.get(9,[b'\x06']);offset=options.get(14,[bytes(8)])
            if len(resolution)!=1 or len(resolution[0])!=1 or len(offset)!=1 or len(offset[0])!=8:
                raise ValueError('PCAPNG 接口时间参数不合法')
            value=resolution[0][0];units=(2 if value&128 else 10)**(value&127)
            shift=struct.unpack(endian+'q',offset[0])[0]
            interface=(link,snaplen,units,shift)
            audit.update({'datalink':link,'snaplen':snaplen,'timestampUnitsPerSecond':units,
                          'timestampOffsetSeconds':shift,'captureInterfaces':1})
        elif kind==6:
            if interface is None or len(body)<20:raise ValueError('PCAPNG 包缺接口或必要字段')
            ident,hi,lo,cap,wire=struct.unpack_from(endian+'IIIII',body)
            link,snaplen,units,shift=interface
            if ident!=0:raise ValueError('PCAPNG 包引用未知接口')
            padded=((cap+3)//4)*4
            if cap>wire or (snaplen and cap>snaplen) or 20+padded>len(body):
                raise ValueError('PCAPNG 捕获长度无效')
            pcapng_options(body[20+padded:],endian)
            ticks=(hi<<32)|lo
            micros,remainder=divmod(ticks*1000000,units);ts=micros+shift*1000000
            audit['subMicrosecondTimestamps']+=bool(remainder)
            audit['frames']+=1;audit['snapTruncatedFrames']+=cap<wire
            audit['timestampRegressions']+=previous is not None and ts<previous
            previous=ts
            yield ts,body[20:20+cap],wire,link
        elif kind in (2,3):
            raise ValueError('PCAPNG 旧式或无时间包不支持，不能跳过后宣称完整关联')
        if section_end is not None and f.tell()>section_end:raise ValueError('PCAPNG 超出 section 声明长度')
    if interface is None or not audit['frames']:raise ValueError('PCAPNG 缺接口或为空捕获')
    if section_end is not None and f.tell()!=section_end:raise ValueError('PCAPNG section 长度不完整')


def tcp(ts,data,wire,link,quality):
    offset=0
    if link==1:
        if len(data)<14:quality['shortEthernet']+=1;return
        eth=struct.unpack_from('!H',data,12)[0];offset=14
        while eth in (0x8100,0x88a8):
            if len(data)<offset+4:quality['shortVlan']+=1;return
            eth=struct.unpack_from('!H',data,offset+2)[0];offset+=4
        if eth!=0x0800:quality['nonIPv4']+=1;return
    if len(data)<offset+20:quality['shortIPv4']+=1;return
    ihl=(data[offset]&15)*4;total=struct.unpack_from('!H',data,offset+2)[0]
    frag=struct.unpack_from('!H',data,offset+6)[0]
    if data[offset]>>4!=4 or ihl<20 or total<ihl or wire<offset+total:quality['invalidIPv4']+=1;return
    if frag&0x3fff:quality['fragmentedIPv4']+=1;return
    if data[offset+9]!=6:quality['nonTCP']+=1;return
    off=offset+ihl
    if len(data)<off+20 or total<ihl+20:quality['shortTCP']+=1;return
    thl=(data[off+12]>>4)*4
    if thl<20 or total<ihl+thl or len(data)<off+thl:quality['invalidTCP']+=1;return
    src,dst=struct.unpack_from('!II',data,offset+12);sport,dport=struct.unpack_from('!HH',data,off)
    seq,ack=struct.unpack_from('!II',data,off+4);flags=data[off+13];payload=total-ihl-thl
    prefix=data[off+thl:off+thl+16]
    a,b=(src,sport),(dst,dport)
    return {'ts':ts,'key':tuple(sorted((a,b))),'src':a,'dst':b,'flags':flags,'seq':seq,'ack':ack,
            'tcpWindow':struct.unpack_from('!H',data,off+14)[0],
            'payloadBytes':payload,'ipBytes':total,'httpRequestStart':prefix.startswith((b'GET ',b'POST ',b'HEAD ')),
            'payloadOffset':off+thl,
            'offloadSized':total>1500,'payloadFullyCaptured':len(data)>=offset+total}


class Metrics:
    """单截止点的头部统计；乱序 IAT 不伪装成可用值，握手只在完整序列可见时为真。"""
    def __init__(self,local,cutoff):
        self.local=local;self.cutoff=cutoff;self.counts=collections.Counter();self.n=0
        self.mean=self.m2=self.iatMean=self.iatM2=0.0;self.iatN=0
        self.minimum=self.maximum=self.first=self.last=None;self.reordered=False
        self.syn=None;self.synack=None;self.handshake=False

    def add(self,p):
        if p['ts']>self.cutoff:return
        outbound=p['src'][0]==self.local;suffix='Outbound' if outbound else 'Inbound'
        self.counts['packets'+suffix]+=1;self.counts['bytes'+suffix]+=p['ipBytes']
        self.counts['payload'+suffix]+=p['payloadBytes'];self.n+=1;length=p['ipBytes']
        delta=length-self.mean;self.mean+=delta/self.n;self.m2+=delta*(length-self.mean)
        self.minimum=length if self.minimum is None else min(self.minimum,length)
        self.maximum=length if self.maximum is None else max(self.maximum,length)
        if self.last is not None:
            gap=p['ts']-self.last
            if gap<0:self.reordered=True
            self.iatN+=1;delta=gap-self.iatMean;self.iatMean+=delta/self.iatN;self.iatM2+=delta*(gap-self.iatMean)
        else:self.first=p['ts']
        self.last=p['ts'];flags=p['flags']
        # 契约的 synCount 只计发起 SYN，响应 SYN-ACK 单列，避免夸大连接发起量。
        self.counts['synCount']+=bool(flags&2) and not bool(flags&16)
        for name,mask in [('rstCount',4),('finCount',1)]:self.counts[name]+=bool(flags&mask)
        self.counts['synAckCount']+=(flags&0x12)==0x12
        if flags&2 and not flags&16:self.syn=(p['src'],p['seq'])
        elif flags&0x12==0x12 and self.syn and p['src']!=self.syn[0] and p['ack']==(self.syn[1]+1)%2**32:self.synack=p['seq']
        elif flags&16 and self.syn and self.synack is not None and p['src']==self.syn[0] and p['ack']==(self.synack+1)%2**32:self.handshake=True

    def report(self):
        names=['packetsOutbound','packetsInbound','bytesOutbound','bytesInbound','payloadOutbound','payloadInbound','synCount','synAckCount','rstCount','finCount']
        out={n:self.counts[n] for n in names}
        out.update({'packets':self.n,'lengthMin':self.minimum,'lengthMax':self.maximum,
                    'lengthMean':self.mean if self.n else None,'lengthStd':math.sqrt(max(0,self.m2/self.n)) if self.n else None,
                    'iatMeanUs':self.iatMean if self.iatN and not self.reordered else None,
                    'iatStdUs':math.sqrt(max(0,self.iatM2/self.iatN)) if self.iatN and not self.reordered else None,
                    'timestampReordered':self.reordered,'handshakeSeen':self.handshake})
        return out
