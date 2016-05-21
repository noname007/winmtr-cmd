// mtr-icmp.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"


#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdio.h>
//#include  <WinSock2.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

char buf[1024];


#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

typedef ip_option_information IPINFO, *PIPINFO, FAR *LPIPINFO;

#ifdef _WIN64
typedef icmp_echo_reply32 ICMPECHO, *PICMPECHO, FAR *LPICMPECHO;
#else
typedef icmp_echo_reply ICMPECHO, *PICMPECHO, FAR *LPICMPECHO;
#endif


typedef HANDLE (WINAPI *LPFNICMPCREATEFILE)(VOID);
typedef BOOL  (WINAPI *LPFNICMPCLOSEHANDLE)(HANDLE);
typedef DWORD (WINAPI *LPFNICMPSENDECHO)(HANDLE, u_long, LPVOID, WORD, LPVOID, LPVOID, DWORD, DWORD);

#define IPFLAG_DONT_FRAGMENT	0x02
#define MAX_HOPS				30
#define ECHO_REPLY_TIMEOUT 5000

#ifndef  DEBUG
#define  DEBUG 1
#endif


typedef struct  {
	__int32 addr;		// IP as a decimal, big endian
	int xmit;			// number of PING packets sent
	int returned;		// number of ICMP echo replies received
	unsigned long total;	// total time
	int last;				// last time
	int best;				// best time
	int worst;			// worst time
	int percent;
	char name[255];
}ICMP_STATSDATA_T,*ICMP_STATSDATA_T_P;

ICMP_STATSDATA_T host[MAX_HOPS];
int real_host_hops  = 0;


HANDLE				hICMP;
LPFNICMPCREATEFILE	lpfnIcmpCreateFile;
LPFNICMPCLOSEHANDLE lpfnIcmpCloseHandle;
LPFNICMPSENDECHO	lpfnIcmpSendEcho;

HINSTANCE			hICMP_DLL;


void calc_percent(ICMP_STATSDATA_T_P host){
	int at = 0;
	for(at =0;at < real_host_hops  ;++at){
		host[at].percent = (host[at].xmit == 0) ? 0 : (100 - (100 * host[at].returned / host[at].xmit));
	}
}

int max_percent(ICMP_STATSDATA_T_P host){
	int at  = 0;
	int max_val = 0;
	for(at = 0; at < real_host_hops ;++at){
		
		if(host[at].addr ==0 ){
			continue;
		}

		if(max_val < host[at].percent){		
			max_val = host[at].percent;
		}
	}
	return max_val;
}

char * ip_str(int addr){
	static char temp[32];
	addr = ntohl(addr);
	sprintf(temp,"%d.%d.%d.%d", (addr >> 24) & 0xff, (addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff);
	return temp;
}

void icmp_lost_packet_ans(ICMP_STATSDATA_T_P host){
	int at = 0;
	for(at =0;at < real_host_hops  ;++at){
		//printf()
//#define IS_A_REAL_HOST(host) (host) != 0 //(strcmp((host),"0.0.0.0"))
//		if(IS_A_REAL_HOST(host[at].addr)){
			int addr = ntohl(host[at].addr);
			printf("%d.%d.%d.%d ", (addr >> 24) & 0xff, (addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff);
			printf("%d\n",host[at].percent);
//		}
//#undef  NO_HOST	
	}
}

void ResetHops()
{
	memset(host,0,sizeof(ICMP_STATSDATA_T) * MAX_HOPS);
	real_host_hops = 0;
	return;

	for(int i = 0; i < MAX_HOPS;i++) {
		host[i].addr = 0;
		host[i].xmit = 0;
		host[i].returned = 0;
		host[i].total = 0;
		host[i].last = 0;
		host[i].best = 0;
		host[i].worst = 0;
		memset(host[i].name,0,sizeof(host[i].name));
	}
}

int  init(){
	ResetHops();
	hICMP_DLL =  LoadLibrary(_T("ICMP.DLL"));
	if (hICMP_DLL == 0) {
		printf("Failed: Unable to locate ICMP.DLL!");
		return -1;
	}


	lpfnIcmpCreateFile  = (LPFNICMPCREATEFILE)GetProcAddress(hICMP_DLL,"IcmpCreateFile");
	lpfnIcmpCloseHandle = (LPFNICMPCLOSEHANDLE)GetProcAddress(hICMP_DLL,"IcmpCloseHandle");
	lpfnIcmpSendEcho    = (LPFNICMPSENDECHO)GetProcAddress(hICMP_DLL,"IcmpSendEcho");

	hICMP = (HANDLE) lpfnIcmpCreateFile();
	if (hICMP == INVALID_HANDLE_VALUE) {
		printf("Error in ICMP.DLL !");
		return -1;
	}
	return 0;
}

int deinit(){
	lpfnIcmpCloseHandle(hICMP);

	// Shut down...
	FreeLibrary(hICMP_DLL);
	return 0;

}

int get_ip( char * Hostname){
	WSADATA wsaData;
	int iResult;

	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed: %d\n", iResult);
		return 1;
	}

	struct hostent *host;
	int isIP=1;
	 char *t = Hostname;
	while(*t) {
		if(!isdigit(*t) && *t!='.') {
			isIP=0;
			break;
		}
		t++;
	}
	int traddr;
	if(!isIP) {
		host = gethostbyname(Hostname);
		traddr = *(int *)host->h_addr;
	} else
		traddr = inet_addr(Hostname);


	WSACleanup();

	//sprintf(buf,"%d.%d.%d.%d",(traddr >> 4)&& 0xff );
	return traddr;
}





int icmp(char *HostName){  

	// Declare and initialize variables

	IPINFO			stIPInfo, *lpstIPInfo;
    DWORD			dwReplyCount;
	char			achReqData[8192];
	int				nDataLen	= 64;
	char			achRepData[sizeof(ICMPECHO) + 8192];


	
    /*
     * Init IPInfo structure
     */
    lpstIPInfo				= &stIPInfo;
    stIPInfo.Ttl			= 4;
    stIPInfo.Tos			= 0;
    stIPInfo.Flags			= IPFLAG_DONT_FRAGMENT;
    stIPInfo.OptionsSize	= 0;
    stIPInfo.OptionsData	= NULL;

    for (int i = 0; i < nDataLen; i++) achReqData[i] = 32; //whitespaces
	
/*	if(HostName == NULL)HostName = "localhost";*/
	int address = get_ip(HostName);
	
	
	


   // while(wmtrnet->tracing) {
	int sentpacket = 6;
	while(sentpacket -- ){
		int i = 0;
		while(i < MAX_HOPS){

			ICMP_STATSDATA_T_P host_hops = host + i ;
			++i;
			lpstIPInfo->Ttl = i;//决定了返回结果中，路由节点中的第几个节点的 Address

			// For some strange reason, ICMP API is not filling the TTL for icmp echo reply
			// Check if the current thread should be closed
			//if( current->ttl > wmtrnet->GetMax() ) break;

			// NOTE: some servers does not respond back everytime, if TTL expires in transit; e.g. :
			// ping -n 20 -w 5000 -l 64 -i 7 www.chinapost.com.tw  -> less that half of the replies are coming back from 219.80.240.93
			// but if we are pinging ping -n 20 -w 5000 -l 64 219.80.240.93  we have 0% loss
			// A resolution would be:
			// - as soon as we get a hop, we start pinging directly that hop, with a greater TTL
			// - a drawback would be that, some servers are configured to reply for TTL transit expire, but not to ping requests, so,
			// for these servers we'll have 100% loss
			dwReplyCount = lpfnIcmpSendEcho(hICMP, address, achReqData, nDataLen, lpstIPInfo, achRepData, sizeof(achRepData), ECHO_REPLY_TIMEOUT);

			

			host_hops->xmit += 1;

			if (dwReplyCount == 0){
				continue;
			}

			PICMPECHO icmp_echo_reply = (PICMPECHO)achRepData;
			if(icmp_echo_reply->Status != IP_SUCCESS && icmp_echo_reply->Status != IP_TTL_EXPIRED_TRANSIT) {
				continue;
			}


#if DEBUG == 1
			printf( "%s %u\n",ip_str(icmp_echo_reply->Address),icmp_echo_reply->RoundTripTime);
#endif				
			

			host_hops->last  = icmp_echo_reply->RoundTripTime;
			host_hops->total += host_hops->last;
			
			host_hops->returned += 1;
			host_hops->addr = icmp_echo_reply->Address;
			if(icmp_echo_reply->Address == address){
#if DEBUG == 1
				printf("=======host hops num:%d========\n",i);
				printf("=======sentpacket times:%d========\n",6 - sentpacket);
#endif
				real_host_hops  = i;
				break;
			}
			
		}


		//printf("")
		 /* end ping loop */
	}

	return 0;
}


typedef struct {

	char ip[20];
	int percent;
}SERVER_LOSTPACKET_RESULT;


int main(int argc, char* argv[])
{

	if(argc < 2){
		exit(-1);//参数不足
	}
	

	SERVER_LOSTPACKET_RESULT* result = new SERVER_LOSTPACKET_RESULT[argc -1];
	printf("%s",argv[1]);
	int i = 1;
	for(;i < argc;++i){
		init();
		strcpy(result[i-1].ip,argv[i]);
		icmp(argv[i]);
		calc_percent(host);
#if DEBUG == 1
		icmp_lost_packet_ans(host);
#endif
		result[i-1].percent = max_percent(host);
		deinit();
	}

	delete []result;
	printf("100");

	return 0;
}

