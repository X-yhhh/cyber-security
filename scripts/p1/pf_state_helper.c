/*
 * P1 macOS 精确状态删除探针，仅供已授权的独立高端口 canary。
 *
 * 布局参考 Apple XNU bsd/net/pfvar.h；当前 /sbin/pfctl arm64e 的
 * DIOCKILLSTATES 实参为 0xc0d84429（216 字节）。公开参考并非当前内核
 * 源码，因此同时限制内核版本，静态校验偏移，并要求实机目标/控制连接验收。
 * 不提供主机级删除、通配地址、全局 flush 或 shell 执行功能。
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <unistd.h>

struct addr_wrap {
    union { struct { uint32_t addr[4], mask[4]; } a; char name[32]; } v;
    uint64_t pointer;
    uint8_t type, flags;
};
union xport { struct { uint16_t port[2]; uint8_t op; } range; uint32_t spi; };
struct addr_kill { struct addr_wrap addr; uint8_t reserved[3], neg; union xport port; };
struct state_kill {
    uint8_t af, proto, variant, pad;
    struct addr_kill src, dst;
    char ifname[16], owner[64];
};
_Static_assert(sizeof(struct state_kill)==216, "PF kill ABI size");
_Static_assert(offsetof(struct state_kill,src)==8, "PF source offset");
_Static_assert(offsetof(struct state_kill,dst)==72, "PF destination offset");
_Static_assert(offsetof(struct state_kill,dst.port)==124, "PF port offset");
_Static_assert(offsetof(struct state_kill,ifname)==136, "PF interface offset");
_Static_assert(_IOWR('D',41,struct state_kill)==0xc0d84429UL, "PF native ioctl");

static int private_v4(struct in_addr ip) {
    uint32_t x=ntohl(ip.s_addr);
    return (x>>24)==127 || (x>>24)==10 || (x>>20)==0xac1 ||
           (x>>16)==0xc0a8 || (x>>22)==0x191;
}

int main(int argc,char **argv) {
    struct utsname u;
    if(uname(&u))return 1;
    int matched=!strcmp(u.release,"27.2.0") && strstr(u.version,"xnu-13432.40.162~92");
    if(argc==2 && !strcmp(argv[1],"--abi")) {
        printf("{\"size\":216,\"ioctl\":\"0xc0d84429\",\"kernelMatches\":%s}\n",matched?"true":"false");
        return matched?0:1;
    }
    if(argc!=6 || strcmp(argv[1],"kill") || !matched || geteuid()!=0) {
        fputs("PF_SCOPE_OR_KERNEL_NOT_VERIFIED\n",stderr);return 2;
    }
    struct in_addr local,peer;
    char *end=NULL;long port=strtol(argv[4],&end,10);
    if(!end || *end || port<49152 || port>65533 ||
       inet_pton(AF_INET,argv[2],&local)!=1 || inet_pton(AF_INET,argv[3],&peer)!=1 ||
       local.s_addr==peer.s_addr || !private_v4(local) || !private_v4(peer) ||
       strlen(argv[5])>=16 || !if_nametoindex(argv[5])) {
        fputs("PF_NARROW_SCOPE_REQUIRED\n",stderr);return 2;
    }
    struct state_kill k={0};
    k.af=AF_INET;k.proto=IPPROTO_TCP;
    k.src.addr.v.a.addr[0]=peer.s_addr;k.src.addr.v.a.mask[0]=UINT32_MAX;
    k.dst.addr.v.a.addr[0]=local.s_addr;k.dst.addr.v.a.mask[0]=UINT32_MAX;
    k.dst.port.range.port[0]=k.dst.port.range.port[1]=htons((uint16_t)port);
    k.dst.port.range.op=2; /* PF_OP_EQ，拒绝区间和通配端口。 */
    memcpy(k.ifname,argv[5],strlen(argv[5]));
    int fd=open("/dev/pf",O_RDWR|O_CLOEXEC);
    if(fd<0) { perror("PF_OPEN_FAILED");return 1; }
    int result=ioctl(fd,_IOWR('D',41,struct state_kill),&k),saved=errno;
    close(fd);
    if(result) { errno=saved;perror("PF_KILL_FAILED");return 1; }
    /* psk_af 是 8 位计数；外部观察者仍须枚举实际状态，不能靠计数宣称恢复。 */
    printf("{\"matchedStatesModulo256\":%u,\"narrowTcpPort\":%ld}\n",k.af,port);
    return 0;
}
