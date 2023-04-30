#ifndef		RFILES_H
#define 	RFILES_H

//rules.c declarations/definitions

extern int *total_rules ;
extern int *pid_rules ;
extern int *packet_rules ;

struct pidrule               // if mem2==-1 then range not given only value given,  if mem2==-2 then check for all ranges within the domain.
{
    int ruleno,pid;
    int type,priority;   //kill pid->1, drop packet->2, accept packet-> 3   // priority from 0-10
    float mem1,mem2;
    char proto[5];     //tcp->1, udp->2, icmp->3
    int port1,port2;
    float cpu1,cpu2;
    char ip1[20], ip2[20];
    struct pidrule * nextp;

};

struct packetrule
{
    int ruleno;
    int type,priority;                          ////type==1 then DROP type==2 then ACCEPT
    int port1,port2;
    char ip1[20], ip2[20];
    char proto[5];
    struct packetrule * nextp;
};


extern struct pidrule * lkd_pid_rule;
extern struct packetrule * lkd_pkt_rule;

extern struct pidrule * shared_pid_rule;
extern struct packetrule * shared_packet_rule;

void init_rules();
void print_rules();

//end rules.c 

//begin resources.c declarations/definitions

extern int *pid_list;  //total pids on the system
extern int *total_pids , *active_pids ,sock_pids ;

struct resource_info
{
    int pid;
    double cpu_usage ;
    double memory_usage;

};

struct net_inode
{
	char glocal_hexip[30], grem_hexip[30];
	char glocal_ip[30],grem_ip[30];
	int gindex;
	long int ginode2;
	char conn_type;                  
};

struct connection_info
{
	int c_pid;
	int open_socks;     // number of open sockets ,also tells how much memory needed for struct n_info
	
	long int  c_inode[100];
	struct net_inode n_info[100];
	
};

extern int *tcp_conns , *udp_conns ,*icmp_conns ,*all_conns ;

extern double cpu_usage_percentage;

extern struct connection_info* primary_conn_info;

//extern struct resource_info res_info_arr[2000];
extern struct resource_info * res_info;

void show_procs();
int init_resources();

//end resources.c  

void init_tables(struct packetrule *);
//void tables_flush()

#endif
