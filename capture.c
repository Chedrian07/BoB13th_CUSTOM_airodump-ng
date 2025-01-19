#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/wireless.h>
#include <arpa/inet.h>
#include "capture.h"

#define MAX_NETWORKS 100

static void FREE_BF(BEACON_FRAME* BF) {
    TAG* T = BF->body.tag;
    while (T) {
        TAG* NT = T->next;
        free(T->data);
        free(T);
        T = NT;
    }
}

void SET_CH(const char* IFACE, int CH) {
    int SK = socket(AF_INET, SOCK_DGRAM, 0);
    if (SK < 0) {
        perror("[DEBUG]Socket creation failed");
        exit(EXIT_FAILURE);
    }
    struct iwreq REQ = {0};
    strncpy(REQ.ifr_name, IFACE, IFNAMSIZ);
    REQ.u.freq.m = CH;
    REQ.u.freq.e = 0;
    REQ.u.freq.flags = IW_FREQ_FIXED;

    if (ioctl(SK, SIOCSIWFREQ, &REQ) < 0) {
        perror("[DEBUG]Failed to set channel");
        close(SK);
        exit(EXIT_FAILURE);
    }
    close(SK);
    usleep(200000); 
}

void PUSH_DI(DP_INFO* HDI, DP_INFO* NDI) {
    DP_INFO* CDI = HDI;
    int count = 0;
    while (CDI->next != NULL) {
        if (memcmp(CDI->next->bss_id, NDI->bss_id, 6) == 0) {
            CDI->next->power = NDI->power;
            CDI->next->beacons++;
            free(NDI->essid);
            free(NDI);
            return;
        }
        CDI = CDI->next;
        count++;
    }
    if (count < MAX_NETWORKS) {
        CDI->next = NDI;
    } else {
        free(NDI->essid);
        free(NDI);
    }
}

void FREE_DI(DP_INFO* HDI) {
    DP_INFO* CDI = HDI;
    while (CDI != NULL) {
        DP_INFO* NDI = CDI->next;
        free(CDI->essid);
        free(CDI);
        CDI = NDI;
    }
}

int PARSE_BCN(const uint8_t* PKT, BEACON_FRAME* BF, int PKTLEN) {
    const uint8_t* CUR = PKT;
    BF->header.frame_control = *(uint16_t*)(CUR);

    if (BF->header.frame_control != htons(0x8000)) {
        return -1;
    }

    CUR += sizeof(uint16_t);
    BF->header.duration_id = *(uint16_t*)(CUR);
    CUR += sizeof(uint16_t);
    memcpy(BF->header.da, CUR, sizeof(BF->header.da));
    CUR += sizeof(BF->header.da);
    memcpy(BF->header.sa, CUR, sizeof(BF->header.sa));
    CUR += sizeof(BF->header.sa);
    memcpy(BF->header.bss_id, CUR, sizeof(BF->header.bss_id));
    CUR += sizeof(BF->header.bss_id);
    BF->header.sequence_control = *(uint16_t*)(CUR);
    CUR += sizeof(uint16_t);

    BF->body.timestamp = *(uint64_t*)(CUR);
    CUR += sizeof(uint64_t);
    BF->body.beacon_interval = *(uint16_t*)(CUR);
    CUR += sizeof(uint16_t);
    BF->body.capacity_info = *(uint16_t*)(CUR);
    CUR += sizeof(uint16_t);

    BF->body.tag = NULL;
    TAG* LT = NULL;

    while (CUR - PKT < PKTLEN) {
        TAG* NT = (TAG*)malloc(sizeof(TAG));
        if (!NT) {
            perror("[DEBUG]Failed to allocate memory for new tag");
            return -1;
        }
        NT->tag_name = *(CUR++);
        NT->tag_len = *(CUR++);
        NT->data = (uint8_t*)malloc(NT->tag_len);
        if (!NT->data) {
            perror("[DEBUG]Failed to allocate memory for tag data");
            free(NT);
            return -1;
        }
        memcpy(NT->data, CUR, NT->tag_len);
        CUR += NT->tag_len;
        NT->next = NULL;

        if (!BF->body.tag) {
            BF->body.tag = NT;
        } else {
            LT->next = NT;
        }
        LT = NT;
    }
    return 1;
}

bool PARSE_RT(const uint8_t* PKT, RADIO_T* R) {
    const uint8_t* CUR = PKT;
    R->header.version = *CUR++;
    R->header.pad = *CUR++;
    R->header.len = *(uint16_t*)(CUR);
    CUR += sizeof(uint16_t);

    unsigned int PC = 0;
    R->header.present = (uint32_t*)malloc(sizeof(uint32_t));
    if (!R->header.present) {
        perror("[DEBUG]Failed to allocate memory for present flags");
        return false;
    }
    R->header.present[0] = *(uint32_t*)(CUR);
    CUR += sizeof(uint32_t);

    while (R->header.present[PC] & 0x80000000) {
        PC++;
        R->header.present = (uint32_t*)realloc(R->header.present, sizeof(uint32_t) * (PC + 1));
        if (!R->header.present) {
            perror("[DEBUG]Failed to reallocate memory for present flags");
            return false;
        }
        R->header.present[PC] = *(uint32_t*)(CUR);
        CUR += sizeof(uint32_t);
    }

    unsigned int OFFSET_PWR = 8 + 4 * PC;

    if (R->header.present[0] & 0x00000001) OFFSET_PWR += 8;  
    if (R->header.present[0] & 0x00000002) OFFSET_PWR += 1;  
    if (R->header.present[0] & 0x00000004) OFFSET_PWR += 1;  
    if (R->header.present[0] & 0x00000008) OFFSET_PWR += 4;  
    if (R->header.present[0] & 0x00000010) OFFSET_PWR += 2;  

    if (OFFSET_PWR < R->header.len) {
        R->power = *(int8_t*)(PKT + OFFSET_PWR);
    } else {
        R->power = 0; 
    }

    return true;
}

void FREE_RT(RADIO_T* R) {
    free(R->header.present);
}

void print_table_header(int CH) {
    printf("---------------------------------------------------------------------------------------------\n");
    printf("|                                Now Channel : %-3d                                          |\n", CH);
    printf("---------------------------------------------------------------------------------------------\n");
    printf("|      BSS_ID       | Power | Beacons | Channel |                    ESSID                  |\n");
    printf("---------------------------------------------------------------------------------------------\n");
}

void center_text(char* dest, const char* src, int width) {
    int len = strlen(src);
    int padding = (width - len) / 2;
    int i;

    for (i = 0; i < padding; i++) {
        dest[i] = ' ';
    }
    strcpy(dest + padding, src);
    for (i = padding + len; i < width; i++) {
        dest[i] = ' ';
    }
    dest[width] = '\0';
}

void print_table_row(DP_INFO* CDI) {
    char essid[41];
    char centered_essid[41];
    if (CDI->essid) {
        snprintf(essid, sizeof(essid), "%-40s", CDI->essid);
    } else {
        snprintf(essid, sizeof(essid), "%-40s", "");
    }
    center_text(centered_essid, essid, 40);

    printf("| %02x:%02x:%02x:%02x:%02x:%02x | %6d | %7d | %7d | %-40s |\n",
           CDI->bss_id[0], CDI->bss_id[1], CDI->bss_id[2],
           CDI->bss_id[3], CDI->bss_id[4], CDI->bss_id[5],
           CDI->power, CDI->beacons, CDI->channel, centered_essid);
}

int main(int ARGC, char* ARGV[]) {
    if (ARGC != 2) {
        printf("Usage: %s [interface]\n", ARGV[0]);
        return -1;
    }

    char* DEV = ARGV[1];
    char ERRBUF[PCAP_ERRBUF_SIZE];
    pcap_t* HNDL = pcap_open_live(DEV, BUFSIZ, 1, 1000, ERRBUF);

    if (HNDL == NULL) {
        fprintf(stderr, "[DEBUG]Couldn't open device %s: %s\n", DEV, ERRBUF);
        return -1;
    }

    DP_INFO* HDI = (DP_INFO*)malloc(sizeof(DP_INFO));
    HDI->next = NULL;

    int CH = 1;

    while (1) {
        SET_CH(DEV, CH);
        print_table_header(CH);
        DP_INFO* CDI = HDI->next;
        while (CDI != NULL) {
            print_table_row(CDI);
            CDI = CDI->next;
        }
        printf("---------------------------------------------------------------------------------------------\n");
        printf("\033[H\033[J");
        CH = (CH % 10) + 1;

        struct pcap_pkthdr* HDR;
        const uint8_t* PKT;
        int RES = pcap_next_ex(HNDL, &HDR, &PKT);

        if (RES == 0) continue;
        if (RES == -1 || RES == -2) break;

        RADIO_T RT;
        if (!PARSE_RT(PKT, &RT)) {
            FREE_RT(&RT);
            continue;
        }

        BEACON_FRAME BF;
        if (PARSE_BCN(PKT + RT.header.len, &BF, HDR->caplen - RT.header.len) == -1) {
            FREE_RT(&RT);
            continue;
        }

        DP_INFO* NDI = (DP_INFO*)malloc(sizeof(DP_INFO));
        memcpy(NDI->bss_id, BF.header.bss_id, 6);
        NDI->power = RT.power;
        NDI->beacons = 1;
        NDI->channel = CH;
        NDI->essid = NULL;
        NDI->next = NULL;

        TAG* CTG = BF.body.tag;
        while (CTG != NULL) {
            if (CTG->tag_name == 0) {
                NDI->essid = (char*)malloc(CTG->tag_len + 1);
                memcpy(NDI->essid, CTG->data, CTG->tag_len);
                NDI->essid[CTG->tag_len] = '\0';
                break;
            }
            CTG = CTG->next;
        }

        PUSH_DI(HDI, NDI);

        FREE_BF(&BF);
        FREE_RT(&RT);
    }

    FREE_DI(HDI);
    pcap_close(HNDL);
    return 0;
}