#pragma pack(1)

typedef struct DP_INFO{ // Display_info
    uint8_t bss_id[6];
    int power;
    int beacons;
    int channel;
    struct DP_INFO* next;
    char* essid;
} DP_INFO;

typedef struct{
    uint8_t version;
    uint8_t pad;
    uint16_t len;
    uint32_t* present;
} RADIO_THEADER; // Radio_tap_header

typedef struct {
    RADIO_THEADER header;
    int8_t power;
} RADIO_T; // Radio_tap

#define MAX_PAYLOAD_SIZE 2312

typedef struct {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t da[6];
    uint8_t sa[6];
    uint8_t bss_id[6];
    uint16_t sequence_control;
} MAC; // MACHeader

typedef struct TAG{
    uint8_t tag_name;
    uint8_t tag_len;
    uint8_t* data;
    struct TAG* next;
} TAG; // Tagged

typedef struct {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capacity_info;
    TAG* tag;
} FBODY; // FrameBody

typedef struct {
    MAC header;
    FBODY body;
} BEACON_FRAME; // Beacon_Frame

#pragma pack()