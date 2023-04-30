#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>
#include<ctype.h>

int *total_rules;
int *pid_rules;
int *packet_rules;

int temp_word_num=0;

struct pidrule                    // if mem2==-1 then range not given only value given,  if mem2==-2 then check for all ranges within the domain.
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
 ////type==1 then DROP type==2 then ACCEPT

struct packetrule
{
    int ruleno;
    int type,priority;                         
    int port1,port2;
    char ip1[20], ip2[20];
    char proto[5];
    struct packetrule * nextp;
};


struct pidrule * lkd_pid_rule=NULL;
struct packetrule * lkd_pkt_rule=NULL;

static void form_words(char *);
static void form_main_rule(char **,int);
static int check_num_val(char *);
static void form_pid_rule(char **,struct pidrule *, int);
static void get_range(float *,char *);
static void get_ip_range(char ** , char *);
static void form_packet_rule(char ** ,struct packetrule * , int);
static void deleterule(char **,int);

void print_rules();

///////////////////////////////////////////////////////

int check_num_val(char * word)
{
    int i;
    for(i=0;i<strlen(word);i++)
    {
        if(isdigit(word[i])==0)
        {
            printf("WRONG USAGE !!");
            (*total_rules)--;
            return(-1);
        }
    }
    int ret=atoi(word);
    return ret;
}

///////////////////////////////////////////////////////

void form_words(char * str)
{
    char * temp;
    temp=malloc(500*sizeof(char));
    char *temp2=temp;
    strcpy(temp,str);
    //printf("temp variable in 81 is %s*** \n",temp);
    int num_words=0;
    char word[50];
    char ** word_arr;
    word_arr=(char **)malloc(500*sizeof(char *));
    while(sscanf(temp,"%s",word)==1)
    {
        if(strcmp(temp," ")==0)
        continue;
        num_words++;
        word_arr[num_words-1]=(char *)malloc(250*sizeof(char));
        strcpy(word_arr[num_words-1],word);
        //printf("word_arr[%d] is %s\n",num_words-1,word_arr[num_words-1]);
        temp+=strlen(word)+1;
        {                                                                       //////only for debugging purpose    
            sscanf(temp,"%s",word);
            //printf("next word is %s___________**** \n",word);
        }
        
    }
    
    if(strcmp(word_arr[0],"RULE-NO")==0)
    {
        (*total_rules)++;
        form_main_rule(word_arr,num_words);
        
        
    }

    else if(strcmp(word_arr[0],"DELETE")==0)
    {
        deleterule(word_arr,num_words);
    }
    else 
    {
        printf("IMPROPER USAGE, RULE-NO COMES FIRST OR TYPE EXIT\n");      /////DELETE RULE-NO IS MISSING.
        free(temp2);
        return;
    }
    free(temp2);
    int i;
    for(i=0;i<num_words;i++)
    {
        free(word_arr[i]);
    }
    free(word_arr);
}

///////////////////////////////////////////////////////


void form_main_rule(char ** word_arr,int num_words)
{
    char * word=malloc(50*sizeof(char));
    strcpy(word,"HELLO WORLD!!");
    int i;
    int lprio;
    //printf("%s is word_arr[1]  and   %s is word\n",word_arr[1],word);
    
    strcpy(word,word_arr[1]);

   int lruleno=check_num_val(word);
   if(lruleno==-1)
   {free(word);
    return ;
    }
   struct pidrule * node=lkd_pid_rule;
   while(node!=NULL)
   {
    if(node->ruleno==lruleno)
    {
        printf("RULE ALREADY IN USE\n");
        (*total_rules)--;
        free(word);
        return;
    }
    node=node->nextp;
    
   }
   struct packetrule * node2=lkd_pkt_rule;
    while(node2!=NULL)
   {
    if(node2->ruleno==lruleno)
    {
        printf("RULE ALREADY IN USE\n");
        (*total_rules)--;
        free(word);
        return;
    }
    node2=node2->nextp;
    
   }
   
   int bln;
   if (strcmp(word_arr[4],"DROP")==0)  
   bln=1;
   if(strcmp(word_arr[4],"ACCEPT")==0)
   bln=2;

    struct pidrule * new_node=malloc(sizeof(struct pidrule));
    struct packetrule * new_node2=malloc(sizeof(struct packetrule));

   
   if(strcmp(word_arr[4],"KILL")==0)                               ////FORM PID RULE.
   {
        (*pid_rules)++;
        new_node->ruleno=lruleno;
        new_node->priority=check_num_val(word_arr[3]);
        new_node->type=0;
        form_pid_rule(word_arr,new_node,num_words);
        //word to be done lkd
        new_node->nextp=NULL;
        if(lkd_pid_rule==NULL)
        {
            lkd_pid_rule=new_node;
        free(word);
        return;
        }
        if(new_node->priority>lkd_pid_rule->priority)
        {
            new_node->nextp=lkd_pid_rule;
            lkd_pid_rule=new_node;
            free(word);
            return;
        }
        struct pidrule *current=lkd_pid_rule;
        while(current->nextp!=NULL && current->nextp->priority>new_node->priority)
        current=current->nextp;

        new_node->nextp=current->nextp;
        current->nextp=new_node;
   }
  
   else if (bln==1 || bln==2)                          /// FOR PACKET RULES.
   {
    (*packet_rules)++;
    new_node2->type=bln;
    new_node2->ruleno=lruleno;
    new_node2->priority=check_num_val(word_arr[3]);
    //printf("rule-no is %d     and     priority is %d\n",new_node2->ruleno,new_node2->priority);
    form_packet_rule(word_arr,new_node2,num_words);

    new_node2->nextp=NULL;
    if(lkd_pkt_rule==NULL)
    {
        lkd_pkt_rule=new_node2;
        free(word);
        return;
    }
    if(new_node2->priority>lkd_pkt_rule->priority)
    {
        new_node2->nextp=lkd_pkt_rule;
        lkd_pkt_rule=new_node2;
        free(word);
        return;
    }
    struct packetrule *current2=lkd_pkt_rule;
    while(current2->nextp!=NULL && current2->nextp->priority>new_node2->priority)
    current2=current2->nextp;

    new_node2->nextp=current2->nextp;
    current2->nextp=new_node2;
    }
   
   else
   {
    printf("WRONG USAGE, OPTIONS ARE EITHER 'KILL' OR 'DROP' OR 'ACCEPT'\n");   
    (*total_rules)--;
    free(word);
    return;
   }

   free(word);

}

//////////////////////////////////////////////////////////

void form_pid_rule(char ** word_arr,struct pidrule * l_pidrule,int num_words)
{
    int i,flag=0;
    float array[3];    //a[0]==0 then only one value stored at a[1],
    char ** ip_arr;
    ip_arr=(char **)malloc(3*sizeof(char *));
    l_pidrule->pid=check_num_val(word_arr[6]);
    l_pidrule->mem2=-2;                  // -2 means all ranges(no range given), -1 means only one value given, NA for ip2 means one value only
    l_pidrule->cpu2=-2;
    l_pidrule->port2=-2;
    strcpy(l_pidrule->ip2,"ALL");
    strcpy(l_pidrule->proto,"ALL");
    for(i=7;i<num_words;i=i+2)
    {
        if(strcmp(word_arr[i],"MEM-RANGE")==0)
        {
            get_range(array,word_arr[i+1]);
            l_pidrule->mem1=array[1];
            l_pidrule->mem2=array[2];

        }
        if(strcmp(word_arr[i],"PROTOCOL")==0)
        {
            strcpy(l_pidrule->proto,word_arr[i+1]);
        }
        if(strcmp(word_arr[i],"IP-RANGE")==0)
        {
            flag++;
            get_ip_range(ip_arr,word_arr[i+1]);
            strcpy(l_pidrule->ip1,ip_arr[0]);
            strcpy(l_pidrule->ip2,ip_arr[1]);

        }
        if(strcmp(word_arr[i],"CPU-RANGE")==0)
        {
            get_range(array,word_arr[i+1]);
            l_pidrule->cpu1=array[1];
            l_pidrule->cpu2=array[2];

        }
        if(strcmp(word_arr[i],"PORT-RANGE")==0)
        {
            get_range(array,word_arr[i+1]);
            l_pidrule->port1=(int)array[1];
            l_pidrule->port2=(int)array[2];

        }
        
    }
    if(flag!=0)
    for(i=0;i<3;i++)
    free(ip_arr[i]);

    free(ip_arr);
}

/////////////////////////////////////////////////////

void form_packet_rule(char ** word_arr,struct packetrule * l_packetrule, int num_words)
{
    int i;
    float array[3];    //a[0]==0 then only one value stored at a[1],
    char ** ip_arr;
    ip_arr=(char **)malloc(3*sizeof(char *));
    l_packetrule->port2=-2;
    strcpy(l_packetrule->ip2,"ALL");
    strcpy(l_packetrule->proto,"ALL");
    for(i=5;i<num_words;i++)
    {
        if(strcmp(word_arr[i],"PROTOCOL")==0)
        {
            strcpy(l_packetrule->proto,word_arr[i+1]);
        }
        if(strcmp(word_arr[i],"PORT-RANGE")==0)
        {
            get_range(array,word_arr[i+1]);
            l_packetrule->port1=(int)array[1];
            l_packetrule->port2=(int)array[2];

        }
        if(strcmp(word_arr[i],"IP-RANGE")==0)
        {
            get_ip_range(ip_arr,word_arr[i+1]);
            strcpy(l_packetrule->ip1,ip_arr[0]);
            strcpy(l_packetrule->ip2,ip_arr[1]);

        }

    }

    for(i=0;i<3;i++)
    free(ip_arr[i]);

    free(ip_arr);
}

void get_range(float *array,char * str)
{
    int i,j,k=-1,t=0,f1=0;
    int num_words=strlen(str);
    int lno,bno;
    char word1[100],word2[100];
    array[0]=0;
    strcpy(word2,"-1");
    for(i=0;i<num_words;i++)
    {
        if(str[i]=='-')
        {
            array[0]=1;
            k=i;
            break;
        }
            word1[i]=str[i];
            f1++;
    }

    if(k!=-1)
    for(i=k+1;i<num_words;i++)                           ////frustrated with an error, so two loops deal with it.
    {
        word2[t]=str[i];
        t++;
    }

    
    word1[f1]='\0';
    if(k!=-1)
    word2[t+1]='\0';
    //printf("(line 322) word1 is %s,    word2 is %s&&&&&&&&&\n",word1,word2);
    array[1]=atof(word1);
    array[2]=atof(word2);
}

void get_ip_range(char ** ip_list, char * str)
{
    int i,t=0,k=-1;
    int f1=0;
    char temp1[100],temp2[100];
    strcpy(temp2,"NA");
    int num_words=strlen(str);
    for(i=0;i<3;i++)
    ip_list[i]=(char *)malloc(150*sizeof(char));
    for(i=0;i<num_words;i++)
    {
        if(str[i]=='-')
        {
            k=i;
            break;
        }
            temp1[i]=str[i];
            f1++;
    }

    if(k!=-1)
    for(i=k+1;i<num_words;i++)                           ////frustrated with an error, so two loops deal with it.
    {
        temp2[t]=str[i];
        t++;
    }
    temp1[f1]='\0';
    if(k!=-1)
    temp2[t]='\0';
    //printf("(line347) IP1 is %s and length is %ld******\n\n",temp1,strlen(temp1));
    strcpy(ip_list[0],temp1);
    strcpy(ip_list[1],temp2);
}

//////////////////////////////////////////////////

void deleterule(char ** word_arr,int num_words)
{
    int i,j,t=0,k=0;
    int l_ruleno,temp_ruleno;
    if(strcmp(word_arr[1],"RULE-NO")!=0)
    {
        printf("\nwrong usage!! RULE-NO comes after DELETE");
        return;
    }
    l_ruleno=check_num_val(word_arr[2]);
    struct pidrule * node=lkd_pid_rule;
    struct pidrule * prev_node=lkd_pid_rule;
    struct packetrule * node2=lkd_pkt_rule;
    struct packetrule * prev_node2=lkd_pkt_rule;

    if(lkd_pid_rule->ruleno==l_ruleno)
    {
        lkd_pid_rule=lkd_pid_rule->nextp;
        free(node);
        (*pid_rules)--;
        (*total_rules)--;
            return;
    }

    else if(lkd_pkt_rule->ruleno==l_ruleno)
    {
        lkd_pkt_rule=lkd_pkt_rule->nextp;
        free(node2);
        (*packet_rules)--;
        (*total_rules)--;
        return;
    }

    while(node!=NULL)
    {
        if(node->ruleno==l_ruleno)
        {
            printf("--------------------DELETED SUCCESSFULLY--------------------\n");
            prev_node->nextp=node->nextp;
            free(node);
            (*pid_rules)--;
            (*total_rules)--;
            return;
        }
        prev_node=node;
        node=node->nextp;
    }

    while(node2!=NULL)
    {
        if(node2->ruleno==l_ruleno)
        {
            printf("--------------------DELETED SUCCESSFULLY--------------------\n");
            prev_node2->nextp=node2->nextp;
            free(node2);
            (*packet_rules)--;
            (*total_rules)--;
            return;
        }
        prev_node2=node2;
        node2=node2->nextp;
    }


}

void print_rules()
{
    struct packetrule prl;
    struct pidrule pdl;
    struct pidrule * node=lkd_pid_rule;
    struct packetrule * node2=lkd_pkt_rule;
    while(node2!=NULL)
    {
        prl=*node2;
        printf("PACKET-RULE VALUES ARE:ruleno=%d,  priority=%d,   port1=%d,  port2=%d,  IP1=%s,  IP2=%s,  PROTOCOL=%s  \n",prl.ruleno,prl.priority,prl.port1,prl.port2,prl.ip1,prl.ip2,prl.proto);
        node2=node2->nextp;
    }
    printf("\n");
    while(node!=NULL)
    {
        pdl=*node;
        printf("PID-RULE VALUES ARE:ruleno=%d,  priority=%d,   port1=%d,  port2=%d,  IP1=%s,  IP2=%s,  PROTOCOL=%s,  MEM1=%f,  MEM2=%f,  CPU1=%f,  CPU2=%f\n",pdl.ruleno,pdl.priority,pdl.port1,pdl.port2,pdl.ip1,pdl.ip2,pdl.proto,pdl.mem1,pdl.mem2,pdl.cpu1,pdl.cpu2);
        node=node->nextp;
    }
}

char * robust(char * str)
{
    int i,k=0;
    char *ret=malloc(sizeof(char)*strlen(str));
    char prev;
    if(str[0]==' ')
        prev=' ';
    for(i=0;i<strlen(str);i++)
    {
        
        if(str[i]==' ' && prev==' ')
            continue;
        prev=str[i];
        ret[k++]=str[i];
    }
    return ret;
}

void packet_checker()
{
    int i;
    size_t l=50;
    char * str=NULL;
    char ch[50];
    while(1)
    {
    printf("\nENTER RULE:\n->");
    int ret=getline(&str,&l,stdin);
    ret=getline(&str,&l,stdin);
    char * str_trimmed=robust(str);
    if(str_trimmed[0]=='E' || str_trimmed[0]=='Q')
    {
        return;
    }
    else
    {
    form_words(str_trimmed);
    print_rules();
    free(str);
    free(str_trimmed);
    }
    }
}

void init_rules()
{
    packet_checker();
}