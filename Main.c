#include<stdio.h>
#include<stdlib.h>
#include<ctype.h>
#include<string.h>
#include<math.h>
#include<unistd.h>
#include<signal.h>
#include<sys/types.h>
#include<sys/mman.h>
#include<fcntl.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<pty.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include<pthread.h>


#include "include/rfiles.h"

#define MAP_ANONY 0x20

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
int run = 0;

struct pidrule * shared_pid_rule;
struct packetrule * shared_packet_rule;

int check_port(int ,int ,int );                  //return of 1 means there is a match with the signature. Should be killed/dropped....
int check_protocol(char *,int);
int check_cpu(double ,double ,int);

int check_ip(char * ,char *,char *);
int check_memory(double ,double, int );
void monitor();
void pid_monitor();
int get_port(char * );
double pid_query(int ,int ); 
char * get_ip(char * );



struct net_inode * pid_query_net(int ,int);


int check_cpu(double c1,double c2,int lpid)
{
    int i,ret;
    double lcpu;
    if(fabs(c2+2)<=0.00001)
    {
        //printf("l49 cpu match for %d\n",lpid);
        return 1;
    }
    
    lcpu=pid_query(lpid,2);
    if(fabs(lcpu+1)<=0.00001)
    return 0;
    if(fabs(c2+1)<=0.00001)
    {
        if(fabs(lcpu-c1)<=0.0001)
        {
        //printf("l60 match for %d\n",lpid);
        return 1;
        }
        else return 0;
    }
    if((lcpu-c1)>=0.00001 && (c2-lcpu)>=0.00001)
    {
        //printf("l67 match for %d\n",lpid);
        return 1;
    }
    else
    return 0;
}

int check_memory(double m1,double m2,int lpid)
{
    int i,ret;
    double lmem=-1;
    if(fabs(m2+2)<=0.00001)
    {
        //printf("l80 mem match for %d\n",lpid);
        return 1;
    }
    lmem=pid_query(lpid,1);
    if(fabs(lmem+1)<=0.00001)
    return 0;
    if(fabs(m2+1)<=0.00001)
    {
        if(fabs(lmem-m1)<=0.00001)
        {
            //printf("l90 match for %d\n",lpid);
        return 1;
        }
        else return 0;
    }
    if((lmem-m1)>=0.00001 && (m2-lmem)>=0.00001)
    {
        //printf("l97 match for %d\n",lpid);
        return 1;
    }
    else
    return 0;
}

int check_net(int lpid, char * lip1, char * lip2)
{
    int i,j;
    int ret;
    //char lip1[20],lip2[20];
    char * temp;
    //printf("(%s),(%s) are the IP ranges\n",lip1,lip2);
    if(strcmp(lip2,"ALL")==0)
    {
        //printf("l112 net match for %d\n",lpid);
        return 1;extern struct packetrule * shared_packet_rule;
    }
    for(i=0;i<*active_pids;i++)
    {
        if(lpid==primary_conn_info[i].c_pid)
        {
            for(j=0;j<primary_conn_info[i].open_socks;j++)
            {
                if(strcmp(lip2,"NA")==0)
                {
                    //printf("PID matched and NA detected\n");
                    temp=get_ip(primary_conn_info[i].n_info[j].grem_ip);
                    //printf("lip1 ->(%s) and germ_ip ->(%s)\n",lip1,temp);
                    if(strcmp(lip1,temp)==0)
                    {
                        //printf("l126 match for %d\n",lpid);
                        free(temp);
                        return 1;
                    }
                    free(temp);
                }
                else
                ret=check_ip(lip1,lip2,primary_conn_info[i].n_info[j].grem_ip);
                if(ret==1)
                {
                    //printf("l49 match for %d\n",lpid);
                    return 1;
                }
            }
        }
    }
    return 0;
}


int check_ip(char * lip1,char * lip2,char * buffer)         
{

    int i;
    int j=0;
    struct connection_info  lconn;
    char *ip_check_str;

    //ip1_str=get_ip(lip1);
    //ip2_str=get_ip(lip2);
    ip_check_str=get_ip(buffer);
    
    unsigned long ip1 = ntohl(inet_addr(lip1));
    unsigned long ip2 = ntohl(inet_addr(lip2));
    unsigned long ip_check = ntohl(inet_addr(ip_check_str));
    
    // Check if ip_check is between ip1 and ip2
    if (ip_check >= ip1 && ip_check <= ip2) {
    free(ip_check_str);
        //printf("l165 ip match\n\n");
        return 1;
    } else {
    free(ip_check_str);
        return 0;
    }
}


int check_port(int p1,int p2,int lpid)
{
    int i;
    int j=0;
    int lport;
    struct connection_info  lconn;
    if(p2==-2)
    {
        //printf("l181 port match for %d\n",lpid);
        return 1;
    }
    for(i=0;i<*active_pids;i++)
    {
        if(lpid==primary_conn_info[i].c_pid)
        {
            lconn=primary_conn_info[i];
            j=1;
        }
    }
    if(j==1)
    for(i=0;i<lconn.open_socks;i++)
    {
        lport=get_port(lconn.n_info[i].glocal_ip);
            if(lport>=p1 && lport<p2)
            {
                //printf("l198 port match for %d\n",lpid);
                return 1;
            }
        
    }
    return 0;
}


int get_port(char * str)
{
    char p[20];
    int i,k=-1;
    for(i=0;i<strlen(str);i++)
    {
        if(str[i]==':')
        {
            k++;
        }
        if(k>-1 && str[i]!=':')
        {
            p[k]=str[i];
            k++;
        }
    }
    return atoi(p);
}

char * get_ip(char * ip_port)
{
    char * p=malloc(sizeof(char)*20);
    int i,k=-1;
    for(i=0;i<strlen(ip_port);i++)
    {
        if(ip_port[i]==':')
        {
            p[i]='\0';
            return p;
        }
        
        p[i]=ip_port[i];
    }
}

double pid_query(int lpid,int query)            /// 1.mem   2.cpu    
{
    int i;
    for(i=0;i<*total_pids;i++)
    {
        if(res_info[i].pid==lpid)
        {
            if(query==1)
            return res_info[i].memory_usage;
            else if(query==2)
            return res_info[i].cpu_usage;
        }
    }
    return -1;
}

int check_protocol(char * lproto,int lpid)
{
    int i;
    int j=0;
    int lport;
    struct connection_info  lconn;
    if(lproto[0]=='A')
    {
        //printf("l49 protocol match for %d\n",lpid);
        return 1;
    } 
    for(i=0;i<*active_pids;i++)
    {
        if(lpid==primary_conn_info[i].c_pid)
        {
            lconn=primary_conn_info[i];
            j=1;
        }
    }
    if(j==1)
    for(i=0;i<lconn.open_socks;i++)
    {
        if(lproto[0]==lconn.n_info[i].conn_type)
            {
                //printf("l49 protocol match for %d\n",lpid);
                return 1;
            }
        
    }
    return 0;
    
}


void pid_monitor()              //check the rules...
{
    int i,lpid,ret;
    struct pidrule * node;
    for(i=0;i<*total_pids;i++)
    {
        lpid=pid_list[i];
        if(lpid<10)
        {continue;}
        node=shared_pid_rule->nextp;
        //printf("*******Checking PID %d\n",lpid);
        //if(node==NULL)
        //printf("CARE!!\n\n\n");
        while(node!=NULL)
        {
            //printf("In node line265");
        if(lpid==node->pid || node->pid==0)
        {
            ret=1;
            //printf("PID has matched!\n");
        ret=check_cpu(node->cpu1,node->cpu2,lpid);
        ret*=check_net(lpid,node->ip1,node->ip2);
        ret*=check_memory(node->mem1,node->mem2,lpid);
        ret*=check_port(node->port1,node->port2,lpid);
        ret*=check_protocol(node->proto,lpid);

         if(ret==1)
        {
            printf("Killing PID %d",lpid);
        }
        }
        
        node=node->nextp;
        }
    }
    return ;
}


void * thread_func()              //check the rules...
{
    while(1)
        {
            sleep(1);
        pthread_mutex_lock(&lock);
        while(!run) { /* We're paused */
        pthread_cond_wait(&cond, &lock); /* Wait for run signal */
        }
        pthread_mutex_unlock(&lock);
        struct pidrule * node=shared_pid_rule->nextp;
        pid_monitor();
        printf("pid_monitor done");
        }
        return NULL;
}

void * thread_func2()
{
    while(1)
    {
        sleep(1);
        init_resources();
    }
}

void main()
{
    char str[20];

    pid_list=mmap(NULL, sizeof(int)*2000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONY	, -1, 0);  //
    total_pids=mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONY, -1, 0);      //
    active_pids=mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONY, -1, 0);
    tcp_conns=mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONY, -1, 0);
    udp_conns=mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONY, -1, 0);
    icmp_conns=mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONY, -1, 0);
    all_conns=mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONY, -1, 0);
    *total_pids=0;   
    *active_pids=0;
    *tcp_conns=0;
    *udp_conns=0;
    *icmp_conns=0;
    *all_conns=0;

    shared_pid_rule =mmap(NULL, sizeof(struct pidrule)*200, PROT_READ | PROT_WRITE, MAP_SHARED| MAP_ANONY, -1, 0);
    shared_pid_rule->nextp=lkd_pid_rule;

    shared_packet_rule=mmap(NULL, sizeof(struct packetrule)*200, PROT_READ | PROT_WRITE, MAP_SHARED| MAP_ANONY , -1, 0);
    shared_packet_rule->nextp=lkd_pkt_rule;

    res_info=mmap(NULL, sizeof(struct resource_info)*2000, PROT_READ | PROT_WRITE, MAP_SHARED| MAP_ANONY, -1, 0);
    primary_conn_info=mmap(NULL, sizeof(struct connection_info)*2000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONY, -1, 0);

    total_rules=mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED| MAP_ANONY, -1, 0);
    pid_rules=mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED| MAP_ANONY, -1, 0);
    packet_rules=mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED| MAP_ANONY, -1, 0);

    *total_rules=0;
    *pid_rules=0;
    *packet_rules=0;

    printf("Hello from Monitori!\n");

    char *buff;
    size_t l=15;
    
    init_rules();
    init_resources();
    show_procs();
    sleep(1);
    print_rules();
    printf("Starting pid_monitor\n");
    shared_pid_rule->nextp=lkd_pid_rule;
    shared_packet_rule->nextp=lkd_pkt_rule;
    pid_monitor();
    init_tables(shared_packet_rule->nextp);
    
    
        
}
