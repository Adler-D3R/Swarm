#ifndef RIP_HEADER
#define RIP_HEADER

//IP and Port Randomizer
void RandomIP(int* field_1, int* field_2, int* field_3, int* field_4, int* new_port)
{
    *field_1 = rand() % 256;
    *field_2 = rand() % 256;
    *field_3 = rand() % 256;
    *field_4 = rand() % 256;
    *new_port = rand() % 65535;
}

#endif