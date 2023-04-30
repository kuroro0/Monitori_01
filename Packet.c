#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<string.h>
#include<ctype.h>
#include<fcntl.h>

#include "include/rfiles.h"


void tables_ip(struct packetrule* node,char * str)
{
    char ch=' ';
    if(strcmp(node->ip2,"ALL")!=0)
            {
                if(strcmp(node->ip2,"NA")==0)
                    sprintf(str,"-s %s",node->ip1);
                
                else
                    sprintf(str,"-m iprange --src-range %s-%s",(node->ip1),(node->ip2));
            }
            else if(strcmp(node->ip2,"ALL")==0)
            sprintf(str,"%c",ch);
}

void tables_port(struct packetrule *node,char *str)
{
    char ch=' ';
    if(node->port2!=-2)
            {
                if(node->port2==-1)
                    sprintf(str,"--dport %d",node->port1);
                else
                    sprintf(str,"--dports %d:%d",(node->port1),(node->port2));
            }
            else
            sprintf(str,"%c",ch);
}

void tables_protocol(struct packetrule *node,char * str)
{
    char temp[50];
    char ch=' ';
    if(node->proto[0]!='A')
            {
                if(node->proto[0]=='T')
                strcpy(temp,"tcp");
                else if(node->proto[0]=='U')
                strcpy(temp,"udp");
                else if(node->proto[0]=='I')
                strcpy(temp,"icmp");

                sprintf(str,"-p %s",temp);

            }
            else
            sprintf(str,"%c",ch);
}

void init_tables(struct packetrule *node)
{
    char ch=' ';
    char iprule[70],portrule[30],protocolrule[30];
    char temp[5],action[30];
    char finalrule[200];
    //printf("packet.c working!");
    if(node==NULL)
    {
        printf("packet.c node is NULL");
    }
    while(node!=NULL)
    {
        if(node->type==1)
        strcpy(action,"DROP");
        else
        strcpy(action,"ACCEPT");

        tables_ip(node,iprule);
        tables_port(node,portrule);
        tables_protocol(node,protocolrule);
        
        sprintf(finalrule,"iptables -A INPUT %s %s %s -j %s",iprule,portrule,protocolrule,action);

        printf("final rule is %s\n",finalrule);

        node=node->nextp;
    }
}