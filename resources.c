#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<math.h>
#include<ctype.h>
#include <sys/types.h>
#include <sys/dir.h>
#include <sys/param.h>
#include<dirent.h>
#include<string.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<arpa/inet.h>
#include <linux/kernel.h>       
#include <sys/sysinfo.h>
#include<err.h>
#include<errno.h>

int* pid_list;  //total pids on the system

int *total_pids, *active_pids,sock_pids=0;

struct sysinfo s_info;     //IMPORTANT


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
	int open_socks;     // number of open sockets 
	
	long int  c_inode[100];
	struct net_inode n_info[100];
	
	
};

char * hex_endian_converter(char *);
int print_pids(char *,int * );  
int form_IP_lists(char * ,struct net_inode*,char );
long int get_sock_inode(char * );
int sock_list_per_pid(int , struct connection_info * );
struct net_inode get_IP(long int);
void testfun();
int memory_usage(int);
int init_resources();


int *tcp_conns, *udp_conns,*icmp_conns,*all_conns;
char temp_conn='e';
struct net_inode error_net_inode;
double cpu_usage_percentage;

double gtret,gtret2;

struct net_inode all_sock_list_arr[1000];


struct net_inode * all_sock_list;   //mapping of tcp IP and socket inode


struct connection_info *primary_conn_info;

//struct resource_info res_info[2000];
struct resource_info * res_info;
/////////////////////////////////////////////////////////

int memory_usage(int pid)
{
    FILE *ptr_path;
	size_t bufsize=1000;
	ssize_t retv;
    int bytesread,i,memory;
	char * dbarr;
    char *ptr;
	int prev_index=-1;
    long int utime,stime,cutime,cstime,start_time;
    long int total_time,uptime;
	char path[50];//="./directory/Blank.txt";
	dbarr=malloc(bufsize*sizeof(char));

    sprintf(path,"/proc/%d/status",pid);
	//printf("%s path\n",path);
	ptr_path=fopen(path,"r");

	if(ptr_path==NULL)
	{
		printf("error opening path 102\n");
		perror("fopen");
		return -1;
		exit(1);
	}

    for(i=0;i<22;i++)
	bytesread=getdelim(&dbarr,&bufsize,'\n',ptr_path);
   
    sscanf(dbarr,"%*s %d %*s",&memory);
	fclose(ptr_path);
	free(dbarr);
    //printf("this is the memory used %d kB\n",memory);
    return memory;
}

////////////////////////////////////////////////////////

float cpu_usage2(int pid)
{
    FILE *ptr_path;
	size_t bufsize=1000;
	ssize_t retv;
    int bytesread;
	char * dbarr;
    char *ptr;
	int prev_index=-1;
    long int utime,stime,cutime,cstime;
    double total_time,uptime;
	char path[50];
	dbarr=malloc(bufsize*sizeof(char));

    sprintf(path,"/proc/%d/stat",pid);
	ptr_path=fopen(path,"r");

	if(ptr_path==NULL)
	{
		return (-1);
	}
	int i;

	for(i=0;i<14;i++)
	bytesread=getdelim(&dbarr,&bufsize,' ',ptr_path);
   
    //printf("this is dbarr %s\n",dbarr);
    utime=strtol(dbarr,&ptr,10);
    bytesread=getdelim(&dbarr,&bufsize,' ',ptr_path);
    stime=strtol(dbarr,&ptr,10);
    bytesread=getdelim(&dbarr,&bufsize,' ',ptr_path);
    cutime=strtol(dbarr,&ptr,10);
    bytesread=getdelim(&dbarr,&bufsize,' ',ptr_path);
    cstime=strtol(dbarr,&ptr,10);

    for(i=0;i<5;i++)
    bytesread=getdelim(&dbarr,&bufsize,' ',ptr_path);


    //printf("%ld %ld %ld %ld %ld\n",utime,stime,cutime,cstime,start_time);

    total_time=utime+stime+cutime+cstime;

    if(sysinfo(&s_info)!=0)
    {
        printf("error getting sysinfo !\n");
        exit(1);
    }

    double hertz=sysconf(_SC_CLK_TCK);
    double diff=0;
    double process_seconds=total_time/hertz;
	fclose(ptr_path);
	free(dbarr);
    return process_seconds;


}

////////////////////////////////////////////////////////

void total_cpu()
{
    FILE * ptr_path;
    size_t bufsize=1000;
	ssize_t retv;
    int bytesread,i;
	char * dbarr;
    char *ptr;
	ptr_path=fopen("/proc/stat","r");

	if(ptr_path==NULL)
	{
		printf("error opening path 191\n");
		exit(1);
	}

     int num_of_processors = sysconf(_SC_NPROCESSORS_ONLN);
     double previdle=0,prevnonidle=0,prevtotal=0,previdle0=0;

     double user,nice,system,idle0=0,idle=0,iowait,irq,softirq,steal;
     for(i=0;i<num_of_processors;i++)
    {
        retv=getline(&dbarr,&bufsize,ptr_path);
        sscanf(dbarr,"%*s %lf %lf %lf %lf %lf %lf %lf %lf %*s",&user,&nice,&system,&idle0,&iowait,&irq,&softirq,&steal);
        previdle+=idle0+iowait;
        prevnonidle+=user+nice+system+irq+softirq+steal;
        printf(" %lf %lf %lf %lf %lf %lf %lf %lf \n",user,nice,system,idle0,iowait,irq,softirq,steal);
    }
 prevtotal=previdle+prevnonidle;
fclose(ptr_path);
    sleep(2);

    ptr_path=fopen("/proc/stat","r");
    if(ptr_path==NULL)
	{
		printf("error opening path 214");
		exit(1);
	}
	
    double nonidle=0,total=0;
    for(i=0;i<num_of_processors;i++)
    {
        retv=getline(&dbarr,&bufsize,ptr_path);
        sscanf(dbarr,"%*s %lf %lf %lf %lf %lf %lf %lf %lf %*s",&user,&nice,&system,&idle0,&iowait,&irq,&softirq,&steal);
        idle+=idle0+iowait;
        nonidle+=user+nice+system+irq+softirq+steal;
        //printf(" %lf %lf %lf %lf %lf %lf %lf %lf \n",user,nice,system,idle0,iowait,irq,softirq,steal);
    }

total=idle+nonidle;
double totalcpu=total-prevtotal;
double idlecpu=idle-previdle;

cpu_usage_percentage=100*((totalcpu-idlecpu)/totalcpu);

//printf("cpu usage is %lf\n",cpu_usage_percentage);
fclose(ptr_path);
free(dbarr);
}
////////////////////////////////////////////////////////

void form_resource_list()
{
    int i,lpid;
    double ret,mem;
    for(i=0;i<*total_pids;i++)
    {
        lpid=pid_list[i];
        mem=memory_usage(lpid);
        ret=cpu_usage2(lpid);
        res_info[i].cpu_usage=ret;
        res_info[i].memory_usage=mem;
        res_info[i].pid=lpid;
		// if(lpid==9236)
		// gtret=ret;
    }
	sleep(2);
	double temp;
	for(i=0;i<*total_pids;i++)
    {
		lpid=pid_list[i];
        if(lpid!=res_info[i].pid)
		{
			printf("FATAL\n");
			exit(1);
		}
		ret=cpu_usage2(lpid);

		if(ret==-1)
		{
			res_info[i].cpu_usage=0;
			continue;
		}
        res_info[i].cpu_usage=100*((ret-res_info[i].cpu_usage)/2);
		//if(res_info[i].cpu_usage!=0)
			//printf("pid is %d and cpu usage is %lf\n",lpid,res_info[i].cpu_usage);
        
    }
}

// /////////////////////////////////////////////////////
int form_IP_lists(char * path, struct net_inode * map_sock_ip,char c) ///// path to /proc/net/{tcp,udp,icmp}   //forms IP and socket_inode relation    can be multi threaded easily .....
{
	FILE *ptr_path;
	size_t bufsize=200;
	ssize_t retv;
	char * dbarr=NULL;
	int prev_index=-1;
	//dbarr=malloc(bufsize*sizeof(char));

	struct net_inode * ptr=map_sock_ip;

	ptr_path=fopen(path,"r");

	if(ptr_path==NULL)
	{
		printf("error opening path 291");
		perror("fopen");
		exit(1);
	}
	char local_hexip[30], rem_hexip[30];
	char local_ip[30],rem_ip[30];
	int index=0;
	long int inode2;

	int iter=0;
	retv=getline(&dbarr,&bufsize,ptr_path);
	while(retv!=-1)
	{
		retv=getline(&dbarr,&bufsize,ptr_path);
		
		sscanf(dbarr," %d: %s %s %*s %*s %*s %*s %*s %*s %ld %*s %*s %*s %*s %*s %*s %*s ",&index,local_hexip,rem_hexip,&inode2);
		if(prev_index!=index)
		{
			prev_index=index; ///so that last entry is not duplicated when 'basically' /proc/net/tcp
		}
		else
			break;

        if(inode2==0)
        continue;

		iter++;
        (*all_conns)++;

		strcpy(ptr->glocal_hexip,local_hexip);
		strcpy(ptr->grem_hexip,rem_hexip);
		ptr->ginode2=inode2;
		ptr->gindex=index;
		ptr->conn_type=c;
		//printf("\n%d -> index   %s -> local address  %s -> remote address  and %ld -> is inode",ptr->gindex,ptr->glocal_hexip,ptr->grem_hexip,ptr->ginode2);
		
		strcpy(ptr->glocal_ip,hex_endian_converter(local_hexip));
		strcpy(ptr->grem_ip,hex_endian_converter(rem_hexip));

		//printf("\n%s\n",ptr->glocal_ip);
		ptr++;
	}
	
	free(dbarr);
	fclose(ptr_path);
	return iter;
	
}
///////////////////////////////////////////////////////

int print_pids(char * path,int * list)    //also prints directory contents that are numbers.  //works
{
	DIR *proc = opendir(path);
	struct dirent *pids;
	char * pid;
	int i,j,k=0;

	if(proc)
	{
		while((pids=readdir(proc))!=NULL)
		{
			j=1;
			pid=pids->d_name;
			for(i=0;i<strlen(pid);i++)
			{
				if(isdigit(pid[i])==0)
				j=0;
			}
			
			if(j==1)			//file is a no.
			{
				//printf("\n%s",pid);
				list[k++]=atoi(pid);
				
			}
		}
		return k;
	}
	else
	{
		//printf("error opening subdirectory");
		return 0;
	}
}
//////////////////////////////////////////////////////////////////////

struct net_inode get_IP(long int inode)   ///returns the tcp/udp/icmp connection details for given inode     ////can be multi threaded easily....  //WORKSSSS.
{
		int i;
		temp_conn='e';

		//printf("\nwe in getIp\n");

		for(i=0;i<*all_conns;i++)
		{
			if((all_sock_list+i)->ginode2==inode)
			{
				//printf("FOUND A CONNNNNNN\n");
				if(i<*tcp_conns)
				temp_conn='T';
				else if(i<*tcp_conns+*udp_conns)
				temp_conn='U';
				else if(i>=*tcp_conns+*udp_conns)
				temp_conn='I';
				return all_sock_list[i];
			}
		}

		return error_net_inode;
		
}

/////////////////////////////////////////////////////////////////////


long int get_sock_inode(char * path ) ///WORKS.....
{
	struct stat *stat_info; ///stat code.
	
	stat_info=malloc(sizeof(struct stat));
	
	long int k=0;
			//starting stat code...
			if(stat(path,stat_info)==0)
			{
				
				if(S_ISSOCK(stat_info->st_mode))
				{
					
					sock_pids++;
					k=stat_info->st_ino;
					free(stat_info);
					//printf("\n\n\n-----successfully fetched stat.-----\n\n\n"); 
					return k;
				} 
				
				else
				{
					free(stat_info);
					
					return 0;
				}
				
			}
			else
			{
				//printf("error fetching 439");
				return (-1);
			}
			
		
}

///////////////////////////////////////////////////////////////////////

int sock_list_per_pid(int local_pid, struct connection_info * c_info)    //path=/proc/[pid] ///iterate through the fds of the GIVEN PROCESS   //maps sockets to GIVEN PID
{
	int i,iter=0,temp2=0; 
	long int temp=0;   //temp is inode, temp2 is open sockets
	struct net_inode temp_ptr;
	int list[1000],open_fds;
	char  pathfd[80], pathfdn[100];
	
	sprintf(pathfd,"/proc/%d/fd",local_pid); 
	
	//printf("line 463 PID=%d\n",local_pid);
	
	open_fds=print_pids(pathfd,list); //list of open fds of the process
	if(open_fds==0)
	return 0;

	// for(i=0;i<open_fds;i++)                     //works
	// {
	// 	printf("list of open fds for PID %d is %d\n",local_pid,list[i]);
	// }

	//*(c_info->n_info)=temp_ptr;
	for(iter=0;iter<open_fds;iter++)
	{
		sprintf(pathfdn,"%s/%d",pathfd,list[iter]);     //pathfdn= /proc/[pid]/fd/[fd]

		//printf("line 479 pathfdn=%s, ",pathfdn);
		temp=get_sock_inode(pathfdn);
		if(temp>0)              //if fd is socket returns inode.
		{
			c_info->n_info[temp2]=get_IP(temp);
			//printf("line 264 c_info->c_inode[temp2].ginode2 has inode value= %ld\n",c_info->n_info[temp2].ginode2);  
			if(c_info->n_info[temp2].ginode2==-1)
			{
				//printf("-1 detected go on...\n");
			
				continue;
			}
			
			c_info->open_socks=temp2+1;
			c_info->c_pid=local_pid;
			c_info->c_inode[temp2]=temp;
			c_info->n_info[temp2].conn_type=temp_conn;
			
			//printf("*****current sock number is: %d,  inode is: %ld,  and IP is %s,  connection type is %c  *****\n",temp2, temp, c_info->n_info[temp2].grem_ip,c_info->n_info[temp2].conn_type);
			temp2++;
		}
	}
	if(temp2>0)      //very important
	{
		//printf("*active_pids should increase\n");
		(*active_pids)++;
		return 1;
	}
	
	else if(temp2==0)
	return 0;
	else 
	return -1;

}


//////////////////////////////////////////////////////////////////////

char * hex_endian_converter(char * ip_port)   //WORKS.......
{
	int i=0,retv;
	int count=0;
	long ret=0;
	char * little,temp[3];
	int len=strlen(ip_port);

	char ip[20],port[10];

	little=malloc(sizeof(char)*20);
	for(i=len-6;i>=0;i=i-2)
	{

			temp[0]=ip_port[i-1];
			temp[1]=ip_port[i];
			ret=strtol(temp,NULL,16);
			//printf("\n%ld is ld\n",ret);
			if(i==len-6)
			{
				retv=sprintf(little,"%ld",ret);
			}
			else
			retv=sprintf(little,"%s.%ld",little,ret);
			//printf("every iteration of 'little' is %s \n",little);
			
	}

	for(i=0;i<4;i++)   //form the port
	{
		port[3-i]=ip_port[len-1-i];
	}

	ret=strtol(port,NULL,16);   //convert from hex to decimal
	retv=sprintf(port,"%ld",ret);
	
	//printf("\nport value is string %s\n",port);
	retv=sprintf(little,"%s:%ld",little,ret);

	return (little);

	//printf("\n%s-> final little\n",little);
}


//////////////////////////////////////////////////////////////////////

void testfun()    
{
	int i,j,ret,temp_arr[200],t1,t2;
	long int t3;
	char pid_path[50],fdn_path[75];
	for(i=0;i<*total_pids;i++)
	{
		// ret=sock_list_per_pid(pid_list[i],&primary_conn_info[*active_pids]);
		sprintf(pid_path,"/proc/%d/fd",pid_list[i]);
		//printf("pid_path is %s\n",pid_path);

		t2=print_pids(pid_path,temp_arr);
		//printf("t2 is %d\n",t2);
		for(j=0;j<t2;j++)
		{
			sprintf(fdn_path,"%s/%d",pid_path,temp_arr[j]);
			//printf("fdn_path= %s\n",fdn_path);
			t3=get_sock_inode(fdn_path);

			//printf("for path %s inode is this %ld\n",fdn_path,t3);
		}
		
	}
}

void testfun2()     ///has worked !!!
{
	int i,j,ret,temp_arr[200],t1,t2,t3;
	long int pid;
	for(i=0;i<*total_pids;i++)
	{
		 ret=sock_list_per_pid(pid_list[i],&primary_conn_info[*active_pids]);
		 
	}
	//printf("++++++++++++++LINE 600++++++++++++++\n");
	for(i=0;i<*active_pids;i++)
	{
		pid=pid_list[i];
		t1=primary_conn_info[i].open_socks;
		//printf("open socks for PID %ld  is %d",pid,t1);
		for(j=0;j<t1;j++)
		{
			t2=primary_conn_info[i].c_inode[j];
			t3=primary_conn_info[i].n_info[j].ginode2;
			//printf("primary_conn_info --- pid is %d, inode is %d, and remote IP is %s, and protocol is %c\n\n\n",primary_conn_info[i].c_pid,t2,primary_conn_info[i].n_info[j].grem_ip,primary_conn_info[i].n_info[j].conn_type);
		}
	}
	//printf("Done fun2\n");
	return;
	
}

//////////////////////////////////////////////////////////////////////

void testfun3()
{
    int i,lpid,mem;
    double lcpu;
    form_resource_list();
    for(i=0;i<*total_pids;i++)
    {
        lpid=res_info[i].pid;
        mem=res_info[i].memory_usage;
        lcpu=res_info[i].cpu_usage;
		if(lcpu==0)
		continue;
        //printf("\n%d is pid,  %d kb is mem, %lf is %% cpu usage \n",lpid,mem,lcpu);

    }

	 for(i=0;i<*total_pids;i++)
    {
        lpid=res_info[i].pid;
        mem=res_info[i].memory_usage;
        lcpu=res_info[i].cpu_usage;

    }
	return;
}

void show_procs()
{
	int i,lpid,mem;
	int pid,j,ret,temp_arr[200],t1,t2,t3;
    double lcpu;
	for(i=0;i<*total_pids;i++)
    {
        lpid=res_info[i].pid;
        mem=res_info[i].memory_usage;
        lcpu=res_info[i].cpu_usage;
		if(lcpu==0)
		continue;
        printf("%d is pid,  %d kb is mem, %lf is %% cpu usage (filter based on CPU)\n",lpid,mem,lcpu);

    }
	printf("\n\n\n");
	for(i=0;i<*total_pids;i++)
    {
        lpid=res_info[i].pid;
        mem=res_info[i].memory_usage;
        lcpu=res_info[i].cpu_usage;
		if(mem==0)
		continue;
        printf("%d is pid,  %d kb is mem, %lf is %% cpu usage (filter based on memory)\n",lpid,mem,lcpu);

    }
	printf("\n\n\n");
	for(i=0;i<*active_pids;i++)
	{
		pid=pid_list[i];
		t1=primary_conn_info[i].open_socks;
		printf("open socks for PID %d  is %d\n",pid,t1);
		for(j=0;j<t1;j++)
		{
			t2=primary_conn_info[i].c_inode[j];
			t3=primary_conn_info[i].n_info[j].ginode2;
			printf("primary_conn_info --- pid is %d, inode is %d, and remote IP is %s, local IP is %s, and protocol is %c,\n\n\n",primary_conn_info[i].c_pid,t2,primary_conn_info[i].n_info[j].grem_ip,primary_conn_info[i].n_info[j].glocal_ip,primary_conn_info[i].n_info[j].conn_type);
		}
	}
}

int init_resources()
{
	/// mandatory code begin...
	
	error_net_inode.ginode2=-1;

	all_sock_list=all_sock_list_arr;
    res_info=res_info;

	int i=0;
	int ret;
	
	(*tcp_conns)=form_IP_lists("/proc/net/tcp",all_sock_list,'T'); 
	(*udp_conns)=form_IP_lists("/proc/net/udp",all_sock_list+(*tcp_conns),'U'); 
	(*icmp_conns)=form_IP_lists("/proc/net/icmp",all_sock_list+(*udp_conns),'I'); 

	*total_pids=print_pids("/proc",&pid_list[0]);
	/// mandatory code end...

	//testfun();		//works
	testfun3();  
	testfun2();
	//printf("done resources\n");
	return 0;
	
}
