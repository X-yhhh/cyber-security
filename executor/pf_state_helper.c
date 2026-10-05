/* P5 PF 精确状态清理。只接受独立执行器已校验的 IPv4 peer/service，
 * 不提供全局 flush；非匹配内核拒绝运行。须以 root 所有、不可组写的文件部署。
 * ABI 与 P1 实测一致；服务端口由执行器受控配置和保护清单限定。
 */
#include <arpa/inet.h>
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

int main(int argc,char **argv) {
    struct utsname u;
    if(uname(&u))return 1;
    int matched=!strcmp(u.release,"27.2.0") && strstr(u.version,"xnu-13432.40.162~92");
    if(argc==2 && !strcmp(argv[1],"--abi")) {
        printf("{\"kernelMatches\":%s}\n",matched?"true":"false");
        return matched?0:1;
    }
    if(argc!=6 || strcmp(argv[1],"kill") || !matched || geteuid()!=0)return 2;
    struct in_addr local,peer;
    char *end=NULL;long port=strtol(argv[4],&end,10);
    if(!end || *end || port<1 || port>65535 || port==22 || port==53 || port==3389 ||
       inet_pton(AF_INET,argv[2],&local)!=1 || inet_pton(AF_INET,argv[3],&peer)!=1 ||
       local.s_addr==peer.s_addr || local.s_addr==0 || peer.s_addr==0 ||
       IN_MULTICAST(ntohl(peer.s_addr)) || strlen(argv[5])>=16 || !if_nametoindex(argv[5]))return 2;
    struct state_kill k={0};
    k.af=AF_INET;k.proto=IPPROTO_TCP;
    k.src.addr.v.a.addr[0]=peer.s_addr;k.src.addr.v.a.mask[0]=UINT32_MAX;
    k.dst.addr.v.a.addr[0]=local.s_addr;k.dst.addr.v.a.mask[0]=UINT32_MAX;
    k.dst.port.range.port[0]=k.dst.port.range.port[1]=htons((uint16_t)port);
    k.dst.port.range.op=2;
    memcpy(k.ifname,argv[5],strlen(argv[5]));
    int fd=open("/dev/pf",O_RDWR|O_CLOEXEC);
    if(fd<0)return 1;
    int result=ioctl(fd,_IOWR('D',41,struct state_kill),&k);
    close(fd);
    if(result)return 1;
    printf("{\"matchedStatesModulo256\":%u}\n",k.af);
    return 0;
}
