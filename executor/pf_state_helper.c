/* P5 PF 精确状态清理。只接受独立执行器已校验的 IPv4 peer/service 或非保护端口区间，
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

/* 已实机验证的内核构建，只精确匹配 "root:<构建>/"。新增构建须先有 pf_abi_evidence.py 静态证据
 * 与 P1 探针实机通过：40.177.0.3~56 于 2026-10-09 通过（result.json SHA b5465ff2de886dff7a4bc72a8c2cd28318fa69ff068f58297c7a82469ba77dbb，
 * 启动记录 SHA dd7851f7197e9682e32ced0f9abd1c161464400de19a7890ff29ad3ef0e0fdea）。 */
static const char *const VERIFIED_XNU[]={"root:xnu-13432.40.162~92/","root:xnu-13432.40.177.0.3~56/"};

static int verified_kernel(const struct utsname *u) {
    if(strcmp(u->release,"27.2.0"))return 0;
    for(size_t i=0;i<sizeof(VERIFIED_XNU)/sizeof(VERIFIED_XNU[0]);i++)
        if(strstr(u->version,VERIFIED_XNU[i]))return 1;
    return 0;
}

int main(int argc,char **argv) {
    struct utsname u;
    if(uname(&u))return 1;
    int matched=verified_kernel(&u);
    if(argc==2 && !strcmp(argv[1],"--abi")) {
        printf("{\"kernelMatches\":%s}\n",matched?"true":"false");
        return matched?0:1;
    }
    int ranged=argc==6 && !strcmp(argv[1],"kill-ranges");
    if(argc!=6 || (strcmp(argv[1],"kill") && !ranged) || !matched || geteuid()!=0)return 2;
    struct in_addr local,peer;
    if(inet_pton(AF_INET,argv[2],&local)!=1 || inet_pton(AF_INET,argv[3],&peer)!=1 ||
       local.s_addr==peer.s_addr || local.s_addr==0 || peer.s_addr==0 ||
       IN_MULTICAST(ntohl(peer.s_addr)) || strlen(argv[5])>=16 || !if_nametoindex(argv[5]))return 2;
    uint16_t first[129],last[129];size_t count=0;
    const char *cursor=argv[4];char *end=NULL;
    do {
        long low=strtol(cursor,&end,10);
        if(end==cursor || low<1 || low>65535 || (ranged && *end!=':') ||
           (!ranged && *end))return 2;
        long high=low;
        if(ranged){
            cursor=end+1;high=strtol(cursor,&end,10);
            if(end==cursor || high<low || high>65535 || (*end && *end!=','))return 2;
        }
        if(count>=129 || (count && low<=last[count-1]) ||
           (low<=22 && 22<=high) || (low<=53 && 53<=high) ||
           (low<=3389 && 3389<=high))return 2;
        first[count]=(uint16_t)low;last[count]=(uint16_t)high;count++;
        if(!ranged || !*end)break;
        cursor=end+1;
        if(!*cursor)return 2;
    }while(1);
    if(ranged && count<2)return 2;
    int fd=open("/dev/pf",O_RDWR|O_CLOEXEC);
    if(fd<0)return 1;
    unsigned int killed=0;int result=0;
    for(size_t i=0;i<count;i++){
        struct state_kill k={0};
        k.af=AF_INET;k.proto=IPPROTO_TCP;
        k.src.addr.v.a.addr[0]=peer.s_addr;k.src.addr.v.a.mask[0]=UINT32_MAX;
        k.dst.addr.v.a.addr[0]=local.s_addr;k.dst.addr.v.a.mask[0]=UINT32_MAX;
        k.dst.port.range.port[0]=htons(first[i]);k.dst.port.range.port[1]=htons(last[i]);
        k.dst.port.range.op=first[i]==last[i]?2:9; /* PF_OP_EQ / PF_OP_RRG */
        memcpy(k.ifname,argv[5],strlen(argv[5]));
        result=ioctl(fd,_IOWR('D',41,struct state_kill),&k);
        if(result)break;
        killed+=k.af;
    }
    close(fd);
    if(result)return 1;
    printf("{\"matchedStatesModulo256\":%u}\n",killed%256);
    return 0;
}
